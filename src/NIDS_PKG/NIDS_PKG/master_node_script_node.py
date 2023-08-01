#!/usr/bin/env python3

import os
import rclpy
import socket
import datetime
import hashlib
import time
import base64
import pickle

import pandas as pd
import numpy as np

from rclpy.node import Node
from std_msgs.msg import String
from uuid import getnode as get_mac

from NIDS_PKG.kappa_coeff import *
from NIDS_PKG.blackListAPI import *

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

class MasterNode(Node):

	def __init__(self):
		super().__init__('master_node')

		timer_period = 0.2  # seconds

		self.master_mac = get_mac()
		self.master_hash = self.hash_value('master' + str(datetime.datetime.now()) + str(self.master_mac))
		self.init_time = datetime.datetime.now()

		# Master node publishes to master node dispatch topic
		self.master_dispatch_publisher = self.create_publisher(String, 'master_node_dispatch', 10)
		self.timer = self.create_timer(timer_period, self.master_dispatch_callback)

		# Master node subcribes to IDS service topic
		self.ids_service_subscriber = self.create_subscription(String, 'ids_service', self.ids_service_listener, 10)

		self.OUTGOING_MSG_QUEUE_SIZE = 10 # Max queue size for outgoing messages to subsribers
		self.INCOMING_MSG_QUEUE_SIZE = 10 # Max queue size for incoming messages to subscribers/from publishers

		# Blacklist subsystem (TODO: Place in own node) -> everyone in the complex/enterprise will publish and subscribe to it. 
		self.blacklist_publisher = self.create_publisher(String, 'blacklist_subsytem', self.OUTGOING_MSG_QUEUE_SIZE)
		_ = self.create_timer(timer_period, self.blacklist_pub_callback)

		self.blacklist_subscriber = self.create_subscription(String, 'blacklist_subsytem', self.blacklist_sub_callback, self.INCOMING_MSG_QUEUE_SIZE)

		self.BENIGN_THRESHOLD = 150
		self.MALICIOUS_THRESHOLD = 150
		self.MAX_BUFFER_SIZE = 100

		self.evidence_buffer = {}

		# BL format: macid_integer: (mac_addr, {ap_hash: [attack_type_0_cnt, attack_type_1_cnt]})
		self.internal_blacklist = {}

		self.blacklist_obj =  None
		self.defaultMsg = String()
		self.domain_id = os.environ['DOMAIN_ID']


	def master_dispatch_callback(self):
		
		mast_hash = String()
		mast_hash.data = self.master_hash + '$' + str(self.init_time)
		self.master_dispatch_publisher.publish(mast_hash)



	def ids_service_listener(self, inf_report):

		inf_tokens = inf_report.data.split('$')

		if inf_tokens[0] != self.master_hash:
			print('Placed as backup.')
			return

		inf_mac = inf_tokens[1]
		inf_encoding = int(inf_tokens[2])
		inf_cnt = int(inf_tokens[3])

		# Fill buffer
		if inf_mac not in self.evidence_buffer:
			self.evidence_buffer[inf_mac] = {0:0,1:0}
		self.evidence_buffer[inf_mac][inf_encoding] += inf_cnt

		# Report if filled threshold
		gmtime = time.gmtime()
		dt_string = "%s:%s:%s" % (gmtime.tm_hour, gmtime.tm_min, gmtime.tm_sec)
		report_cnt = self.evidence_buffer[inf_mac][inf_encoding]

		if inf_report is not None:
			if report_cnt >= self.BENIGN_THRESHOLD:
				print(f'\033[32;1m[{dt_string}]\033[0m {inf_mac} - \033[32;1mNormal.\033[0m')
			if report_cnt >= self.MALICIOUS_THRESHOLD:
				print(f'\033[31;1m[{dt_string}]\033[0m {inf_mac} - \033[31;1mSuspicious.\033[0m')

		if len(self.evidence_buffer) >= self.MAX_BUFFER_SIZE:
			self.evidence_buffer = {}



	def hash_value(self, val):
		hasher = hashlib.sha256()
		hasher.update(val.encode('UTF-8'))
		return hasher.hexdigest()


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
					# Ban it for a time if it's not in the list already. (aka if in list do nothing.)
					# If malicious is greater, set flag to ban the mac
					topic_obj.ban_mac = True
					blockHandler(src_mac=topic_obj.mac_addr)

		if self.domain_id != topic_obj.domain_id and topic_obj.ban_mac == True:
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





def main(args=None):
	rclpy.init(args=args)

	if 'DOMAIN_ID' not in os.environ:
		print('Domain ID not set. Do so using \'export DOMAIN_ID=<domain>\'')
		sys.exit(1)
	
	master_node = MasterNode()

	rclpy.spin(master_node)
	master_node.destroy_node()
	rclpy.shutdown()
