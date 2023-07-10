#!/usr/bin/env python3

import os
import rclpy

from rclpy.node import Node
from std_msgs.msg import String


class MasterNode(Node):

	def __init__(self):
		super().__init__('master_node')

		timer_period = 0.5  # seconds

		# Master node publishes to master node dispatch topic
		self.master_dispatch_publisher = self.create_publisher(String, 'master_node_dispatch', 10)
		self.timer = self.create_timer(timer_period, self.master_dispatch_callback)

		# Master node subcribes to IDS service topic
		self.ids_service_subscriber = self.create_subscription(String, 'ids_service', self.ids_service_listener, 10)

	def master_dispatch_callback(self):
		
		test_str = String()
		test_str.data = 'Hello from master node!'
		self.master_dispatch_publisher.publish(test_str)



	def ids_service_listener(self, data):
		print(data)
		# Fill buffer
		# Report if filled threshold


def main(args=None):
	rclpy.init(args=args)

	master_node = MasterNode()

	rclpy.spin(master_node)
	master_node.destroy_node()
	rclpy.shutdown()