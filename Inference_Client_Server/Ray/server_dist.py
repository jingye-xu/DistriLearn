#!/usr/bin/env python3

"""
SERVER_DIST.PY: HEAD/MASTER NODE OF THE CLUSTER FOR THE DISTRIBUTED SYSTEM

	* Ray seems to work best with python 3.8.5 
	* Pyenv to change python versions

"""

import ray
import time
import os
import sys
import threading
import queue

from nfstream import NFPlugin, NFStreamer

# Specify remote function to run model inferencing 

@ray.remote
def run_inference():
	pass

# Setup cluster for computing


def create_data_frame_entry_from_flow(flow):
	print(dir(flow))
	pass

# Capture traffic into a flow and send as work to the worker nodes.
def capture_stream():

	print('[*] Capturing stream flows.')
	#TODO LATER: Change to external output default interface
	column_names = []
	interface = "en0"
	flow_limit = 25
	
	# Thread this into a shared queue and have the dataframe be acted upon by all actors in parallel
	# The dataframes can be placed in to the queue, while this acts in its own thread.
	streamer = NFStreamer(source=interface, promiscuous_mode=True, active_timeout=15, idle_timeout=15, n_meters=4)

	flow_count = 0
	for flow in streamer:
		if flow_count >= flow_limit:
			break
		entry = create_data_frame_entry_from_flow(flow)
		flow_count += 1


if __name__ == "__main__":
	capture_stream()


