#!/usr/bin/env python3

"""
SERVER_DIST.PY: MAIN SCRIPT FOR THE CLUSTER

		* tested using Python version 3.9.10
		* Dask 
		* Pyenv to change python versions
"""

import time
import os
import sys
import threading
import tempfile
import queue
import signal
import time
import joblib
import scapy.config
import pickle
import json
import psutil
import subprocess
import socket
import datetime
import hashlib


import torch
import torch.nn as nn
import torch.nn.functional as F
import torchvision.transforms as transforms

import pandas as pd
import numpy as np
import rclpy

from uuid import getnode as get_mac
from nfstream import NFPlugin, NFStreamer
from scapy.all import *


from rclpy.node import Node
from std_msgs.msg import String

NUM_INPUT = 38


class Net(nn.Module):
		def __init__(self) -> None:
				super(Net, self).__init__()
				self.fc1 = nn.Linear(in_features=NUM_INPUT, out_features=30)
				self.fc2 = nn.Linear(in_features=30, out_features=20)
				self.fc3 = nn.Linear(in_features=20, out_features=1)

		def forward(self, x: torch.Tensor) -> torch.Tensor:
				output = self.fc1(x)
				output = torch.relu(output)
				output = self.fc2(output)
				output = torch.relu(output)
				output = self.fc3(output)
				output = torch.sigmoid(output)

				return output


class ModelDriver:

		def __init__(self, path, scaler_path):
				self.model_path = path
				print(f'Loaded model: {path}')
				self.model = None
				self.scaler = joblib.load(scaler_path)
				print(f'Loaded scaler: {self.scaler}')

		def get_instance(self):
				pass

		def load_model(self):
				pass

		def predict(self, dataframe):
				pass


class ScikitModelDriver(ModelDriver):

		def __init__(self, model_path, scaler_path):
				super().__init__(model_path, scaler_path)

		def get_instance(self):         
				if self.model is None:
					self.load_model()
				return self.model

		def load_model(self):
				sci_model = joblib.load(self.model_path)
				self.model = sci_model

		def predict(self, dataframe):
				vals = self.scaler.transform(dataframe.values)
				predictions = self.model.predict(vals)
				results = [0 if result < 0.5 else 1 for result in predictions]
				return results


class PyTorchModelDriver(ModelDriver):

		def __init__(self, model_path, net_class, scaler_path):
				super().__init__(model_path, scaler_path)
				self.net = net_class

		def get_instance(self):
				if self.model == None:
					self.load_model()
				return self.model

		def load_model(self):
				model = self.net
				model.load_state_dict(torch.load(self.model_path))
				model.eval()
				self.model = model

		def predict(self, dataframe):
				vals = self.scaler.transform(dataframe.values)
				data_tensor = torch.tensor(vals, dtype=torch.float)
				data_tensor = torch.FloatTensor(data_tensor)
				results = self.model(data_tensor)
				results = [0 if result[0] < 0.6 else 1 for result in results.detach().numpy()]
				return results



class AccessPointNode(Node):

	def __init__(self, net_interface):
		super().__init__('access_point_node')

		timer_period = 0.2 # seconds

		self.COLLAB_MODE = False # False means local AP operation
		self.MAX_PACKET_SNIFF = 75

		self.capture_name = 'tmp_capture'
		self.net_interface = net_interface
		self.dataframe = pd.DataFrame()

		self.ap_mac = get_mac()
		self.ap_hash = self.hash_value('ap' + str(datetime.now()) + str(self.ap_mac))

		# Access points will subscribe to dispatch topic for masters
		self.dispatch_subscriber = self.create_subscription(String, 'master_node_dispatch', self.master_dispatch_listener, 10)
		self.number_masters = 0
		self.master_poll_cycles = 0

		# Access points will publish to a inference IDS service topic
		self.inference_topic_publisher = self.create_publisher(String, 'ids_service', 10)
		self.timer = self.create_timer(timer_period, self.ids_service_callback)


		# Access points will publish to a private topic to manage elected masters: Publisher will publish current master info
		self.private_topic_master_manager = self.create_publisher(String, 'master_manager', 10)
		self.timer = self.create_timer(timer_period, self.master_manager_publish_callback)

		# Access points will subscribe to private topic to manage elected masters: Subscribers will receive all infos from APs and elect master 
		self.master_manager_subscriber = self.create_subscription(String, 'master_manager', self.master_manager_subscribe_callback, 10)

		self.master_queue = {}

		self.current_master_hash = ''
		self.curr_elected_master_info = ''


	def master_manager_publish_callback(self):

		if self.COLLAB_MODE == False:
			return
		
		elected_master_info = String()
		elected_master_info.data = self.curr_elected_master_info

		self.private_topic_master_manager.publish(elected_master_info)


	def master_manager_subscribe_callback(self, msg):

		if self.COLLAB_MODE == False:
			return

		rec_master_inf = msg.data.split('$')

		master_hash = rec_master_inf[0]

		if master_hash not in self.master_queue:
	
			master_cycle_cnt = rec_master_inf[1]
			master_init_time = rec_master_inf[2]

			self.ap_masters[master_hash] = list()
			self.ap_masters[master_hash].append(master_cycle_cnt)
			self.ap_masters[master_hash].append(master_init_time)

		'''
		conflict resolution rules for master election:

			- If the queue is larger than one, compare AP master with other masters in queue.
			- If a master within the queue has a smaller timestamp than current, elect this as our master.
			- If a master within the queue has the same timestamp, select the one with the largest cycle count. 
			- If any master within the queue has a smaller cycle count (within a threshold) than the current poll count, discard it. 
		'''
		if self.number_masters > 1 and len(self.master_queue) > 1:

			for master in self.master_queue:
				if master == self.master_hash:
					continue
				
				timestamp = self.master_queue[master][2]
				cycle_cnt = self.master_queue[master][1]

				if timestamp < self.master_queue[self.master_hash][2] or (timestamp == self.master_queue[self.master_hash][1] and cycle_cnt > self.master_queue[self.master_hash][1]):
					self.master_hash = master
					self.master_info = self.package_master_info(master)



	def ids_service_callback(self):
		
		self.number_masters = self.inference_topic_publisher.get_subscription_count()

		if self.number_masters >= 1:
			self.COLLAB_MODE = True
		else:
			self.COLLAB_MODE = False
			self.current_master_hash = ''
			self.curr_elected_master_info = ''
			print('Falling back to local inference state')

		# Temporary
		if self.COLLAB_MODE == True:
			print(f'Collab mode on. Elected: {self.master_hash}')

			ap_hashm = String()
			# Temporary: For testing we will publish the hash of the elected master

			tmp = String()
			tmp.data = f'AP: {self.ap_hash}; MS: {self.master_hash}'
			self.inference_topic_publisher.publish(tmp)

		# Temporary

		return
		# capture data from network
		self.sniff_traffic(self.capture_name, self.net_interface)

		# turn it into flow
		stream = NFStreamer(self.capture_name, statistical_analysis=True, decode_tunnels=False, accounting_mode=3)
		mapped = map(self.create_data_frame_entry_from_flow, iter(stream))
		df = pd.DataFrame(mapped)

		self.dataframe = pd.concat([self.dataframe, df], ignore_index=True)
		self.dataframe.dropna(how='all', inplace=True)

		if len(self.dataframe) >= 30:
			for start in range(0, len(self.dataframe), 30):
				subdf = self.dataframe[start:start+30]
				subdf.reset_index(drop=True,inplace=True)
				# publish if master node is available
				self.dataframe = df
		else:
			# publish if master node is available
			pass

		if self.dataframe >= 105:
			self.dataframe = df

		# if no master node, fill buffer here.

	
	def master_dispatch_listener(self, message):
		
		self.master_poll_cycles += 1

		master_dat = message.data
		master_splt = master_dat.split('$')

		master_hash = master_splt[0]
		master_init_time = master_splt[1]

		if master_hash not in self.master_queue:
			self.master_queue[master_hash] = list()
			self.master_queue[master_hash].append(0)
			self.master_queue[master_hash].append(master_init_time)
		else: 
			master_cycle_cnt = 0
			master_info = self.master_queue[master_hash]
			master_info[master_cycle_cnt] += 1


		# Initial master selection to get the resolution scheme going

		if self.number_masters == 1 and self.master_hash == '':
			self.master_hash = master_hash
			self.curr_elected_master_info = self.package_master_info(self.master_hash)


	def package_master_info(self, mhash):

		return self.master_queue[mhash] + '$' + self.master_queue[mhash][0] + '$' + self.master_queue[mhash][1]


	def create_data_frame_entry_from_flow(self, flow):
		# Create dataframe entry with fields respective to model only.
		# old * 0.001
		bytes_sec = flow.bidirectional_bytes / ((flow.bidirectional_duration_ms + 1) / 1000) 
		packets_sec = flow.bidirectional_packets / ((flow.bidirectional_duration_ms + 1) / 1000)
		fwd_packets_sec = flow.src2dst_packets / ((flow.src2dst_duration_ms + 1) / 1000)  
		bwd_packets_sec = flow.dst2src_packets / ((flow.dst2src_duration_ms + 1) / 1000)  
		fwd_iat_total = flow.src2dst_max_piat_ms # total time between two packets in forward direction
		bwd_iat_total = flow.dst2src_max_piat_ms # total time between two packets in the backward direction
		avg_packet_size = flow.bidirectional_bytes / flow.bidirectional_packets
		packet_length_variance = flow.bidirectional_stddev_ps ** 2
		
		return [flow.src_mac, flow.dst_port, flow.bidirectional_duration_ms, flow.src2dst_packets, flow.dst2src_packets, flow.src2dst_bytes, flow.dst2src_bytes, flow.src2dst_max_ps, flow.src2dst_min_ps, flow.src2dst_mean_ps, flow.src2dst_stddev_ps, flow.dst2src_max_ps, flow.dst2src_min_ps, flow.dst2src_mean_ps, flow.dst2src_stddev_ps, bytes_sec, packets_sec, flow.bidirectional_mean_piat_ms, flow.bidirectional_max_piat_ms, flow.bidirectional_min_piat_ms, fwd_iat_total, flow.src2dst_mean_piat_ms, flow.src2dst_stddev_piat_ms, flow.src2dst_max_piat_ms, flow.src2dst_min_piat_ms, bwd_iat_total, flow.dst2src_mean_piat_ms, flow.dst2src_stddev_piat_ms, flow.dst2src_max_piat_ms, flow.dst2src_min_piat_ms, fwd_packets_sec, bwd_packets_sec, flow.bidirectional_min_ps, flow.bidirectional_max_ps, flow.bidirectional_mean_ps, flow.bidirectional_stddev_ps, packet_length_variance, flow.bidirectional_rst_packets, avg_packet_size]


	def sniff_traffic(self, tmp_file_name, listen_interface):
		# Temporary sniffing workaround for VM environment:
		#os.system(f"sshpass -p \"{pfsense_pass}\" ssh root@{pfsense_wan_ip} \"tcpdump -i {lan_nic} -c {MAX_PACKET_SNIFF} -w - \'not (src {ssh_client_ip} and port {ssh_client_port}) and not (src {pfsense_lan_ip} and dst {ssh_client_ip} and port 22)\'\" 2>/dev/null > {tmp_file_name}")
		os.system(f"tcpdump --immediate-mode -i {listen_interface} -c {self.MAX_PACKET_SNIFF} -w - 2>/dev/null > {tmp_file_name}")

	def hash_value(self, val):
		hasher = hashlib.sha256()
		hasher.update(val.encode('UTF-8'))
		return hasher.hexdigest()



MODEL_TYPE = 1 # 0 for scikit, 1 for pytorch - should be enum instead but python isn't clean like that

PATH_PREF = "./ModelPack/clean_17_models/NN"

SCIKIT_MODEL_PATH = f"{PATH_PREF}/kn_2017.pkl"
SCALER_PATH = f"{PATH_PREF}/scaler_nn_17.pkl"
PYTORCH_MODEL_PATH = f"{PATH_PREF}/simple_nn_17.pth"



def main(args=None):

	if 'INTERFACE_IDS' not in os.environ:
		print('Missing environment variable for interface. Set it using export (INTERFACE_IDS).')
		sys.exit(0)

	interface_selector, int_choice_msg = make_pretty_interfaces()

	interface = os.environ['INTERFACE_IDS']

	print(f'Checking interface: {interface}...')

	if interface not in psutil.net_if_addrs():

		user_selection = 1_000_000

		while user_selection not in interface_selector:
			print(f'Interface not available. Select one of the ones below:')
			print(int_choice_msg)
			print(f'\nSelect an interface: ', end='')
			user_selection = int(input())

		interface = interface_selector[user_selection]
	print(f'Interface set to {interface}')



	model_driver = None

	if MODEL_TYPE == 0:
			model_driver = ScikitModelDriver(SCIKIT_MODEL_PATH, SCALER_PATH)
	else:
			model_driver = PyTorchModelDriver(PYTORCH_MODEL_PATH, Net(), SCALER_PATH)


	rclpy.init(args=args)

	access_point = AccessPointNode(interface)

	rclpy.spin(access_point)
	access_point.destroy_node()
	rclpy.shutdown()




def make_pretty_interfaces():
	interfaces = psutil.net_if_addrs()
	interface_dict_list = len(interfaces)
	interface_selector = {i + 1 : j for i, j in zip(range(interface_dict_list), interfaces.keys())} 

	message = []
	for key in interface_selector:
		message.append(f"{key}.) {interface_selector[key]}")

	return interface_selector, "\n".join(message)


								
		
