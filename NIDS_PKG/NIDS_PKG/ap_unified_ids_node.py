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


import torch
import torch.nn as nn
import torch.nn.functional as F
import torchvision.transforms as transforms

import pandas as pd
import numpy as np
import rclpy

from nfstream import NFPlugin, NFStreamer
from scapy.all import *
from datetime import datetime
from rclpy.node import Node


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

	def __init__(self):
		super().__init__('access_point_node')

		timer_period = 0.5 # seconds

		# Access points will subscribe to dispatch topic for masters
		self.dispatch_subscriber = self.create_subcription(String, 'master_node_dispatch', 10)

		# Access points will publish to a inference IDS service topic
		self.inference_topic_publisher = self.create_publisher(String, 'ids_service', 10)
		self.timer = self.create_timer(timer_period, self.ids_service_callback)


	def ids_service_callback(self):
		
		test_message = String()
		test_message.data = 'test ids talker'
		self.inference_topic_publisher.publish(test_message)

	def dispatch_listener(self, message):
		print(message)


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


	def sniff_traffic(self, tmp_file_name):
		# Temporary sniffing workaround for VM environment:
		#os.system(f"sshpass -p \"{pfsense_pass}\" ssh root@{pfsense_wan_ip} \"tcpdump -i {lan_nic} -c {MAX_PACKET_SNIFF} -w - \'not (src {ssh_client_ip} and port {ssh_client_port}) and not (src {pfsense_lan_ip} and dst {ssh_client_ip} and port 22)\'\" 2>/dev/null > {tmp_file_name}")
		os.system(f"tcpdump --immediate-mode -i {listen_interface} -c {MAX_PACKET_SNIFF} -w - 2>/dev/null > {tmp_file_name}")




MODEL_TYPE = 1 # 0 for scikit, 1 for pytorch - should be enum instead but python isn't clean like that

PATH_PREF = "./ModelPack/clean_17_models/NN"

SCIKIT_MODEL_PATH = f"{PATH_PREF}/kn_2017.pkl"
SCALER_PATH = f"{PATH_PREF}/scaler_nn_17.pkl"
PYTORCH_MODEL_PATH = f"{PATH_PREF}/simple_nn_17.pth"



def main(args=None):

	arg_length = len(args)

	if arg_length != 2:
		print('Missing argument for interface.')
		print('Usage: ros2 run ap_unified_ids <interface_name>')
		sys.exit(0)

	interface_selector, int_choice_msg = make_pretty_interfaces()

	interface = sys.argv[1]

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

	access_point = AccessPointNode()

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


								
		
