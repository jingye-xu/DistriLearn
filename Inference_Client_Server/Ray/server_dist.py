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

import pandas as pd
import numpy as np

import psutil

from nfstream import NFPlugin, NFStreamer
from dask.distributed import Client, Queue
from scapy.all import *

shutdown_flag = False

Q_MAX_SIZE = 1_000

QUEUE = queue.Queue()
OBJ_REF_QUEUE = queue.Queue()

#TODO: Change IP address based on testbed node
client = Client("tcp://10.10.0.139:8786")

def run_inference_no_batch(dataframe):
	# Remote function to run model inferencing on dataframes 

	import socket
	h_name = socket.gethostname()
	IP_addres = socket.gethostbyname(h_name)


	return IP_addres

# Asynchronous thread to send the work asynchronously to workers
def serve_workers():

	# Send dataframe to available nodes.
	while not shutdown_flag:

		df = QUEUE.get()
		dask_future = client.submit(run_inference_no_batch, df)
		OBJ_REF_QUEUE.put(dask_future)


# Asynchronous thread to obtain results from worker nodes
def obtain_results():
	
	while not shutdown_flag:

		dask_future = OBJ_REF_QUEUE.get()
		res = dask_future.result()
		print(res)


def create_data_frame_entry_from_flow(flow):
	# Create dataframe entry with fields respective to model only.
	
	bytes_sec = flow.bidirectional_bytes / ((flow.bidirectional_duration_ms + 0.000001) * 0.001)
	packets_sec = flow.bidirectional_packets / ((flow.bidirectional_duration_ms + 0.000001) * 0.001)
	fwd_packets_sec = flow.src2dst_packets / ((flow.src2dst_duration_ms + 0.00000001) * 0.0001)
	bwd_packets_sec = flow.dst2src_packets / ((flow.dst2src_duration_ms + 0.0000001) * 0.0001)

	entry = [flow.dst_port, flow.bidirectional_duration_ms, flow.src2dst_packets, flow.dst2src_packets, flow.src2dst_bytes, flow.dst2src_bytes, flow.src2dst_max_ps, flow.src2dst_min_ps, flow.src2dst_mean_ps, flow.src2dst_stddev_ps, flow.dst2src_max_ps, flow.dst2src_min_ps, flow.dst2src_mean_ps, flow.dst2src_stddev_ps, bytes_sec, packets_sec, flow.bidirectional_mean_piat_ms, flow.bidirectional_stddev_piat_ms, flow.bidirectional_max_piat_ms, flow.bidirectional_min_piat_ms, flow.src2dst_mean_piat_ms, flow.src2dst_stddev_piat_ms, flow.src2dst_max_piat_ms, flow.src2dst_min_piat_ms, flow.dst2src_mean_piat_ms, flow.dst2src_stddev_piat_ms, flow.dst2src_max_piat_ms, flow.dst2src_min_piat_ms, flow.src2dst_psh_packets, flow.dst2src_psh_packets, flow.src2dst_urg_packets, flow.dst2src_urg_packets, fwd_packets_sec, bwd_packets_sec, flow.bidirectional_min_ps, flow.bidirectional_max_ps, flow.bidirectional_mean_ps, flow.bidirectional_stddev_ps, flow.bidirectional_fin_packets, flow.bidirectional_syn_packets, flow.bidirectional_rst_packets, flow.bidirectional_psh_packets, flow.bidirectional_ack_packets, flow.bidirectional_urg_packets, flow.bidirectional_cwr_packets, flow.bidirectional_ece_packets]
	return entry


# Capture traffic into a flow and send as work to the worker nodes.
def capture_stream():

	print('[*] Beginning stream capture.')

	#TODO LATER: Change to external output default interface
	column_names = ['Destination Port', 'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets', 'Total Length of Fwd Packets', 'Total Length of Bwd Packets', 'Fwd Packet Length Max', 'Fwd Packet Length Min', 'Fwd Packet Length Mean', 'Fwd Packet Length Std', 'Bwd Packet Length Max', 'Bwd Packet Length Min', 'Bwd Packet Length Mean', 'Bwd Packet Length Std', 'Flow Bytes/s', 'Flow Packets/s', 'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min', 'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min', 'Fwd PSH Flags', 'Bwd PSH Flags', 'Fwd URG Flags', 'Bwd URG Flags',  'Fwd Packets/s', 'Bwd Packets/s', 'Min Packet Length', 'Max Packet Length', 'Packet Length Mean', 'Packet Length Std', 'FIN Flag Count', 'SYN Flag Count', 'RST Flag Count', 'PSH Flag Count', 'ACK Flag Count', 'URG Flag Count', 'CWE Flag Count', 'ECE Flag Count']
	cols_drops = ['Down/Up Ratio', 'Average Packet Size', 'Avg Fwd Segment Size', 'Avg Bwd Segment Size', 'Fwd Header Length', 'Fwd Avg Bytes/Bulk', 'Fwd Avg Packets/Bulk', 'Fwd Avg Bulk Rate', 'Bwd Avg Bytes/Bulk', 'Bwd Avg Packets/Bulk', 'Bwd Avg Bulk Rate', 'Subflow Fwd Packets', 'Subflow Fwd Bytes', 'Subflow Bwd Packets', 'Subflow Bwd Bytes', 'Init_Win_bytes_forward', 'Init_Win_bytes_backward', 'act_data_pkt_fwd', 'min_seg_size_forward', 'Active Mean', 'Active Std', 'Fwd IAT Total', 'Active Max', 'Active Min', 'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min', 'Bwd IAT Total', 'Fwd Header Length', 'Bwd Header Length', 'Packet Length Variance']
	

	LISTEN_INTERFACE = "en0"
	flow_limit = 20
	MAX_PACKET_SNIFF = 300


	tmp_file = tempfile.NamedTemporaryFile(mode='wb')
	tmp_file_name = tmp_file.name

	while not shutdown_flag:

		dataframe = pd.DataFrame(columns=column_names)

		capture_start = time.time()
		capture = sniff(count=MAX_PACKET_SNIFF, iface=LISTEN_INTERFACE)
		wrpcap(tmp_file_name, capture)
		capture_end = time.time()

		print(f'Time to capture {MAX_PACKET_SNIFF} packets and write to tmp file: {capture_end - capture_start}')

		flow_start = time.time()
		streamer = NFStreamer(source=tmp_file_name, statistical_analysis=True, decode_tunnels=False, active_timeout=80, idle_timeout=80)
		
		for flow in streamer:
			entry = create_data_frame_entry_from_flow(flow)
			dataframe.loc[len(dataframe)] = entry
		flow_end = time.time()

		print(f'Time to create flow table: {flow_end - flow_start:.02f}')

		QUEUE.put(dataframe)


def get_process_metrics():

	global shutdown_flag

	process = psutil.Process(os.getpid())

	while not shutdown_flag:

		# Unique Set Size - Estimates unique memory to this process. 
		used_mem = process.memory_full_info().uss

		# Code snippet from Stackoverflow. 
		size = used_mem
		# 2**10 = 1024
		power = 2**10
		n = 0
		power_labels = {0 : ' ', 1: 'K', 2: 'M', 3: 'G', 4: 'T'}
		while size > power:
			size /= power
			n += 1

		used = size, power_labels[n]+'B'

		print("Memory used: ~%s%s " % ('{0:.{1}f}'.format(used[0], 2), used[1]), end='\r')


def handler(signum, frame):

	global shutdown_flag

	process = psutil.Process(os.getpid())
	children = process.children()

	for child in children:
		child.kill()


	shutdown_flag = True
	print('Shutting down, please wait.')
	

if __name__ == "__main__":

	signal.signal(signal.SIGINT, handler)
	signal.signal(signal.SIGTERM, handler)

	capture_thread = threading.Thread(target=capture_stream, args=())
	#metrics_thread = threading.Thread(target=get_process_metrics, args=())
	serve_thread = threading.Thread(target=serve_workers, args=())
	results = threading.Thread(target=obtain_results, args=())
				
	capture_thread.start()
	#metrics_thread.start()
	serve_thread.start()
	results.start()

	capture_thread.join()
	serve_thread.join()
	results.join()

