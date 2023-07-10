#!/usr/bin/env python3

import os
import rclpy

from rclpy.node import Node


class MasterNode(Node):

	def __init__(self):
		super().__init__('master_node')
		# Master node publishes to master node dispatch topic
		# Master node subcribes to IDS service topic

if __name__ == "__main__":

	pass


