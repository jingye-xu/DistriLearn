#!/usr/bin/env python3

"""
Access points script
		* tested using Python version 3.9.10
		* Pyenv to change python versions

APs run autoencoder and forward all flows to BERT. 
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
import pickle
import base64


from uuid import getnode as get_mac
from nfstream import NFPlugin, NFStreamer
from scapy.all import *

from NIDS_PKG.kappa_coeff import *
from NIDS_PKG.blackListAPI import *


from rclpy.node import Node
from std_msgs.msg import String


import warnings
warnings.filterwarnings(action='ignore')

# This is to accomadate packages on the home directory (i.e. the autoencoder)
sys.path.append(f'{os.environ["HOME"]}/ids_work')

import AnomalyAutoEncoder

class AnomalyDetector:

	# We can assume defaults here. AE trained on input size of 40, and the path is the 4th checkpoint! :)
    def __init__(self, path=f'{os.environ["HOME"]}/ids_work/anomaly_autoencoder_weights4.ckpt', input_output_size=40):

        self.anomaly_autoencoder = AnomalyAutoEncoder(input_output_size)
        self.anomaly_autoencoder.load_weights(path)


    def get_inference(flow_data, threshold=(0.024148070913876787 - 0.01)):
    	# remove features that cause overfit.
    	# For the huge dataset: flow_data.drop(columns=['IPV4_SRC_ADDR', 'IPV4_DST_ADDR', 'Label', 'Attack'], inplace=True)

    	flow_data.drop(columns=['IPV4_SRC_ADDR', 'IPV4_DST_ADDR', 'Attack', 'L4_DST_PORT'], inplace=True)
        # Basic reconstruction
        reconstruction = self.model.predict(flow_data)
        reconstruction_error = tf.keras.losses.mae(reconstruction, flow_data)
        # If the reconstruction error is beyond our threshold, then it is malicious (not fitting within benign distribution.)
        if reconstruction_error >= threshold:
            return 1.0
        return 0.0



class BlackListComposition:

	def __init__(self, ma, attack_type, model_name, model_type, ap_hash, flow):

		self.mac_addr = ma
		#self.mac_id = int(f'{ma[0:2]}{ma[3:5]}{ma[6:8]}{ma[9:11]}{ma[12:14]}{ma[15:17]}',16)
		self.attack_type = attack_type
		self.model_name = model_name
		self.model_type = model_type
		self.flow = flow
		self.domain_id = os.environ['DOMAIN_ID']
		self.ap_hash = ap_hash
		self.kappa = 0.0
		self.ban_mac = False


class AccessPointNode(Node):

	def __init__(self, net_interface):
		super().__init__('access_point_node')

		self.model = AnomalyDetector()

		timer_period = 0.2 # seconds for "refresh rate" of publisher callbacks

		self.COLLAB_MODE = False # False means local AP operation
		self.MAX_PACKET_SNIFF = 25

		self.MALICIOUS_THRESHOLD = 150 # Number of reports for malicious before sending to master or reporting.
		self.BENIGN_THRESHOLD = 150 # Number of report for bengin before sending to master or reporting. 
		self.MAX_BUFFER_SIZE = 100 # maximum size for buffer with respect to memory
		self.OUTGOING_MSG_QUEUE_SIZE = 10 # Max queue size for outgoing messages to subsribers
		self.INCOMING_MSG_QUEUE_SIZE = 10 # Max queue size for incoming messages to subscribers/from publishers

		self.capture_name = '/tmp/tmp_capture'
		self.net_interface = net_interface
		self.domain_id = os.environ['DOMAIN_ID']

		self.dataframe = pd.DataFrame()

		self.ap_mac = get_mac()
		self.ap_hash = self.hash_value('ap' + str(datetime.now()) + str(self.ap_mac))

		# Access points will subscribe to dispatch topic for masters
		self.dispatch_subscriber = self.create_subscription(String, 'master_node_dispatch', self.master_dispatch_listener, self.INCOMING_MSG_QUEUE_SIZE)
		self.number_masters = 0
		self.master_poll_cycles = 0
		self.previous_poll_cycle_cnt = 0

		# Access points will publish to a inference IDS service topic
		self.inference_topic_publisher = self.create_publisher(String, 'ids_service', self.OUTGOING_MSG_QUEUE_SIZE)
		_ = self.create_timer(timer_period, self.ids_service_callback)


		# Access points will publish to a private topic to manage elected masters: Publisher will publish current master info
		self.private_topic_master_manager = self.create_publisher(String, 'master_manager', self.OUTGOING_MSG_QUEUE_SIZE)
		_ = self.create_timer(timer_period, self.master_manager_publish_callback)

		# Access points will subscribe to private topic to manage elected masters: Subscribers will receive all infos from APs and elect master 
		self.master_manager_subscriber = self.create_subscription(String, 'master_manager', self.master_manager_subscribe_callback, self.INCOMING_MSG_QUEUE_SIZE)


		# Blacklist subsystem (TODO: Place in own node) -> everyone in the complex/enterprise will publish and subscribe to it. 
		self.blacklist_publisher = self.create_publisher(String, 'blacklist_subsytem', self.OUTGOING_MSG_QUEUE_SIZE)
		_ = self.create_timer(timer_period, self.blacklist_pub_callback)

		self.blacklist_subscriber = self.create_subscription(String, 'blacklist_subsytem', self.blacklist_sub_callback, self.INCOMING_MSG_QUEUE_SIZE)


		self.master_queue = {}

		self.master_hash = ''
		self.curr_elected_master_info = ''

		self.inference_buffer = {}

		# BL format: macid_integer: (mac_addr, {ap_hash: [attack_type_0_cnt, attack_type_1_cnt]})
		self.internal_blacklist = {}

		self.blacklist_obj =  None
		self.defaultMsg = String()





	# This subsystem is subscribed to by ALL masters, and ALL access points for preemptive decision making. 
	def blacklist_sub_callback(self, data):

		topic_encoded_b64_str = data.data
		topic_decoded_b64_bytes = bytes(topic_encoded_b64_str, 'UTF-8') 
		topic_obj_decoded = base64.b64decode(topic_decoded_b64_bytes)
		topic_obj = pickle.loads(topic_obj_decoded)

		# On receiving, we use Domain ID to fill internal blacklist. Then, we check agreement (for malicious/non-benign), and if it's
		# high agreement of malicious, we blacklist it. LATER: Use some metric to perform online learning based on flow info for the 
		# incoming flow once we decide to blacklist. 

		# Agreement is an INTERNAL DOMAIN PROCESS: Rows - MAC addresses (i.e., subjects); columns - categories (i.e, attack type [1+] or non-malicious [0]); cells - agreements; 
		kap = 0.0
		if self.domain_id == topic_obj.domain_id:
			# BL format: {mac_addr : {ap_hash: [attack_type_0_cnt, attack_type_1_cnt]}
			# AP hash will allow us to count votes per access point and not double-, triple-, or n-count
			if topic_obj.mac_addr not in self.internal_blacklist:
				self.internal_blacklist[topic_obj.mac_addr] = np.zeros((1,2))

			table = self.internal_blacklist[topic_obj.mac_addr]
			if topic_obj.attack_type == 0:
				table[0][0] += 1
			else:
				table[0][1] += 1 

			# Rule for memory constraint and runtime use: For real-time, we will keep a singular table of 1x2, in which the cells represent benign/mal agreement
			kap = fleiss_kappa(self.internal_blacklist[topic_obj.mac_addr], method='randolph')
			
			if np.abs(kap) >= 0.50:
				# check to see which is greater, benign or malicious;
				if table[0][1] > table[0][0]:
					# Ban it for a time if it's not in the blacklist already. (aka if in blacklist do nothing.)
					# If malicious is greater, set flag to ban the mac
					topic_obj.ban_mac = True
					blockHandler(src_mac=topic_obj.mac_addr)

		if self.domain_id != topic.domain_id and topic_obj.ban_mac == True:
			# simply check to see if the object has a ban flag. If so, ban it for the same time. If it is already in the list, however, do nothing. 
			blockHandler(src_mac=topic_obj.mac_addr)



	def blacklist_pub_callback(self):

		# If the determination is that a malicious node is found in buffers: Publishing MAC of adversary + Attack Type + Model Type + Flow Info
		# Meaning if blacklist object is not none, we transmit.

		if self.blacklist_obj is None:
			return

		# Check to see if the object is in the banlist. If so, set ban flag. 

		topic_obj = pickle.dumps(self.blacklist_obj)
		topic_obj_encoded = base64.b64encode(topic_obj)
		topic_obj_str = topic_obj_encoded.decode('UTF-8')

		self.defaultMsg.data = topic_obj_str
		self.blacklist_publisher.publish(self.defaultMsg)




	def master_manager_publish_callback(self):

		if self.COLLAB_MODE == False or (self.curr_elected_master_info == '' and self.master_hash == ''):
			return
		
		elected_master_info = String()
		# Format of message: master_hash$master_cycle_cnt$master_init_time$master_poll_cycles
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

			self.master_queue[master_hash] = list()
			self.master_queue[master_hash].append(master_cycle_cnt)
			self.master_queue[master_hash].append(master_init_time)

		'''
		conflict resolution rules for master election:

			- If the queue is larger than one, compare AP master with other masters in queue.
			- If a master within the queue has a smaller timestamp than current, elect this as our master.
			- If a master within the queue has the same timestamp, select the one with the largest cycle count. 
			- If any master within the queue has a smaller cycle count (within a threshold) than the current poll count, discard it. 
		'''

		if self.number_masters >= 1:

			have_to_delete_master = False
			del_hash = ''

			for master in self.master_queue:
				if not have_to_delete_master and (self.master_poll_cycles - self.previous_poll_cycle_cnt) >= 3:
					have_to_delete_master = True
					del_hash = self.master_hash
					continue


				timestamp = self.master_queue[master][1]
				cycle_cnt = self.master_queue[master][0]

				if have_to_delete_master or timestamp < self.master_queue[self.master_hash][1] or (timestamp == self.master_queue[self.master_hash][1] and cycle_cnt > self.master_queue[self.master_hash][0]):
					self.master_hash = master
					self.curr_elected_master_info = self.package_master_info(master)
					self.master_poll_cycles = 0
					if have_to_delete_master:
						break

			if have_to_delete_master:
				del self.master_queue[del_hash]
				self.previous_poll_cycle_cnt = 0
				



	def ids_service_callback(self):
		
		self.number_masters = self.inference_topic_publisher.get_subscription_count()

		if self.number_masters >= 1:
			self.COLLAB_MODE = True
		elif self.number_masters == 0 or (self.master_hash == '' and self.curr_elected_master_info == ''):
			self.COLLAB_MODE = False
			self.master_hash = ''
			self.curr_elected_master_info = ''
			self.master_poll_cycles = 0
			self.master_queue = {}

		# Temporary
		# if self.COLLAB_MODE == True:
		# 	print(f'Collab mode on. Elected: {self.master_hash}')

		# 	ap_hashm = String()
		# 	# Temporary: For testing we will publish the hash of the elected master

		# 	tmp = String()
		# 	tmp.data = f'AP: {self.ap_hash};{self.master_hash}'
		# 	self.inference_topic_publisher.publish(tmp)
		# Temporary

		# capture data from network
		# parameters: tmp_file_name, listen_interface, chroot_dir
		self.sniff_traffic(self.capture_name, self.net_interface, f"/mnt/debby")

		# turn it into flow
		self.create_fows(self.capture_name, f"/mnt/debby")

		df = self.read_traffic_cap(f"/mnt/debby/flow_outs/")
		

		inf_report = self.make_inference(df)
		# publish if master node is available
		if self.COLLAB_MODE and inf_report is not None:
			print(f'Sending report to master: {self.master_hash}')
			tmp = String()
			tmp.data = self.build_inf_report(inf_report)
			self.inference_topic_publisher.publish(tmp)
			

		# If no master node, report here.
		# if making local reports, THEN we can create a blacklist object to send to the topic.
		if inf_report is not None and self.COLLAB_MODE == False:

			gmtime = time.gmtime()
			dt_string = "%s:%s:%s" % (gmtime.tm_hour, gmtime.tm_min, gmtime.tm_sec)

			mac_addr = inf_report[0]
			attack_encoding = inf_report[1]

			if attack_encoding == 0:
				print(f'\033[32;1m[{dt_string}]\033[0m {mac_addr} - \033[32;1mNormal.\033[0m')
				self.blacklist_obj = BlackListComposition(mac_addr, attack_encoding, MODEL_NAME, MODEL_TYPE, self.ap_hash, None)
			else:
				print(f'\033[31;1m[{dt_string}]\033[0m {mac_addr} - \033[31;1mSuspicious.\033[0m')
				self.blacklist_obj = BlackListComposition(mac_addr, attack_encoding, MODEL_NAME, MODEL_TYPE, self.ap_hash, None)
			

	# Prepare string report for the master. 
	def build_inf_report(self, inf_data):
		# format: master hash $ mac $ type (0 or 1) $ count
		# TODO: Prepare BERT inputs (sentence of flow data). 
		return f'{self.master_hash}${inf_data[0]}${inf_data[1]}${inf_data[2]}'


	# Thresholded based inference buffers. 
	def make_inference(self, df):
		inf_res = None
		# Pass input dataframe to the model, for all rows but only columns 1 through the end. The 0th column are the source mac addresses.
		predictions = self.model.predict(df.iloc[:,1:])

		# predictions do not contain mac, so we need to do a parallel iteration for dataframe
		mac_index = 0
		while mac_index < len(df):
			# df[column][row_num]
			mac_addr = df[0][mac_index]
			prediction = predictions[mac_index]

			if mac_addr not in self.inference_buffer:
				self.inference_buffer[mac_addr] = {0:0,1:0}
			# buffers have an internal dictionary encoding of benign (0) and malicious (1). Thus, if the prediction is 0, we key into that and update the value. Same for malicious.
			self.inference_buffer[mac_addr][prediction] += 1

			# Check evidence threshold, and flush whichever surpasses first for this mac. If a threshold is surpassed, then we make a report for this MAC. Hence, the break in the stamtent.
			if self.inference_buffer[mac_addr][0] >= self.BENIGN_THRESHOLD:
				inf_cnt = self.inference_buffer[mac_addr][0]
				self.inference_buffer[mac_addr][0] = 0
				inf_res = (mac_addr,0,inf_cnt)
				break
			if self.inference_buffer[mac_addr][1] >= self.MALICIOUS_THRESHOLD:
				inf_cnt = self.inference_buffer[mac_addr][1]
				if self.inference_buffer[mac_addr][1] != 0:
					self.inference_buffer[mac_addr][1] //= self.inference_buffer[mac_addr][1]
				if self.inference_buffer[mac_addr][0] != 0:
					self.inference_buffer[mac_addr][0] //= self.inference_buffer[mac_addr][0]
				inf_res = (mac_addr,1,inf_cnt)
				break

			mac_index += 1


		if len(self.inference_buffer) >= self.MAX_BUFFER_SIZE:
			self.inference_buffer = {}

		# Inference result format: (mac, encoding [malicious,benign], count)
		return inf_res

	
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
		
		if master_hash == self.master_hash:
			self.previous_poll_cycle_cnt = self.master_poll_cycles

		# Initial master selection to get the resolution scheme going

		if self.number_masters >= 1 and self.master_hash == '':
			self.master_hash = master_hash
			self.curr_elected_master_info = self.package_master_info(self.master_hash)



	def package_master_info(self, mhash):

		return mhash + '$' + str(self.master_queue[mhash][0]) + '$' + self.master_queue[mhash][1]


	def sniff_traffic(self, tmp_file_name, listen_interface, chroot_dir):
		# Temporary sniffing workaround for VM environment:
		#     os.system(f"sshpass -p \"{pfsense_pass}\" ssh root@{pfsense_wan_ip} \"tcpdump -i {lan_nic} -c {MAX_PACKET_SNIFF} -w - \'not (src {ssh_client_ip} and port {ssh_client_port}) and not (src {pfsense_lan_ip} and dst {ssh_client_ip} and port 22)\'\" 2>/dev/null > {tmp_file_name}")
		os.system(f"echo \"{tmp_file_name}\" > {chroot_dir}/tmp/pktname.txt") # for use in nprobe's system.
		os.system(f"tcpdump --immediate-mode -p -i {listen_interface} -c {self.MAX_PACKET_SNIFF} -w - 2>/dev/null > {chroot_dir}/{tmp_file_name}")


	# Create flows using nprobe's reading of pcap capability
	def create_fows(self, tmp_file_name, chroot_dir):
		
		if not os.path.exists(f'{chroot_dir}/flow_outs'):
			os.system(f'mkdir {chroot_dir}/flow_outs')

		# chroot can do amazing things - you can even execute binaries with full arguments! example: chroot ./debbytest/ /bin/cat /etc/os-release
		#	chroot <fs location> <binary> <args>
		os.system(f"chroot {chroot_dir} nprobe -T \"%IPV4_SRC_ADDR %IPV4_DST_ADDR %L4_SRC_PORT %L4_DST_PORT %PROTOCOL %L7_PROTO %IN_BYTES %OUT_BYTES %IN_PKTS %OUT_PKTS %FLOW_DURATION_MILLISECONDS %TCP_FLAGS %CLIENT_TCP_FLAGS %SERVER_TCP_FLAGS %DURATION_IN %DURATION_OUT %MIN_TTL %MAX_TTL %LONGEST_FLOW_PKT %SHORTEST_FLOW_PKT %MIN_IP_PKT_LEN %MAX_IP_PKT_LEN %SRC_TO_DST_SECOND_BYTES %DST_TO_SRC_SECOND_BYTES %RETRANSMITTED_IN_BYTES %RETRANSMITTED_IN_PKTS %RETRANSMITTED_OUT_BYTES %RETRANSMITTED_OUT_PKTS %SRC_TO_DST_AVG_THROUGHPUT %DST_TO_SRC_AVG_THROUGHPUT %NUM_PKTS_UP_TO_128_BYTES %NUM_PKTS_128_TO_256_BYTES %NUM_PKTS_256_TO_512_BYTES %NUM_PKTS_512_TO_1024_BYTES %NUM_PKTS_1024_TO_1514_BYTES %TCP_WIN_MAX_IN %TCP_WIN_MAX_OUT %ICMP_TYPE %ICMP_IPV4_TYPE %DNS_QUERY_ID %DNS_QUERY_TYPE %DNS_TTL_ANSWER %FTP_COMMAND_RET_CODE\" --pcap-file-list /tmp/pktname.txt --dump-path '{chroot_dir}/flow_outs' --dump-format t --csv-separator")


	# Read flows from nprobes outputs.
	def read_traffic_cap(self, base_flow_dir):
		
		# Format of flow outputs example: 2024/01/30/14/45-39.flows.temp
		# The format is then: year/month/day/hour/minute-n.file_ext
		# Realistically there should only be one at a time anyway, so that should be okay. 

		# Obtain all fragmented flows for traffic capture
		flows = os.listdir(base_flow_dir)

		# Read first csv to create dataframe
		df = pd.read_csv(flows[0], low_memory = False)

		# Concatenate all following csv files to the dataframe
		for csv in flows[1:]:
			sub_df = pd.read_csv(csv, low_memory = False)
			df = pd.concat([df, sub_df])

		# Delete old flows and finally return dataframe
		os.rmdir(flow_dir)

		return df



	def hash_value(self, val):
		hasher = hashlib.sha256()
		hasher.update(val.encode('UTF-8'))
		return hasher.hexdigest()




def main(args=None):

	if 'INTERFACE_IDS' not in os.environ:
		print('Missing environment variable for interface. Set it using \'export INTERFACE_IDS=interface\'.')
		sys.exit(0)

	if 'DOMAIN_ID' not in os.environ:
		print('Missing environment variable for domain id. Set it using \'export DOMAIN_ID=domain\' (e.g., power_plant)')
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



