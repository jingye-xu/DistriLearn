#!/usr/bin/env python3

import os
import rclpy
import socket
import datetime
import hashlib

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

	def master_dispatch_callback(self):
		
		mast_hash = String()
		mast_hash.data = self.master_hash + '$' + str(self.init_time)
		self.master_dispatch_publisher.publish(mast_hash)

	def ids_service_listener(self, data):
		# Temporary: Only receiving hash.
		print()
		if data.data.split(';')[-1] == self.master_hash:
			print('I am elected!')
		else:
			print('Ignoring messages')

		# Fill buffer
		# Report if filled threshold

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