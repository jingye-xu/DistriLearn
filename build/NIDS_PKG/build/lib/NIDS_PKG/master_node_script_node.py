#!/usr/bin/env python3

import os
import rclpy
import socket
import datetime
import hashlib
import time

from rclpy.node import Node
from std_msgs.msg import String
from uuid import getnode as get_mac


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

		self.BENIGN_THRESHOLD = 150
		self.MALICIOUS_THRESHOLD = 150
		self.MAX_BUFFER_SIZE = 100

		self.evidence_buffer = {}


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


def main(args=None):
	rclpy.init(args=args)

	master_node = MasterNode()

	rclpy.spin(master_node)
	master_node.destroy_node()
	rclpy.shutdown()