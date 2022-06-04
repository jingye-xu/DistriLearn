#!/usr/bin/env python3

"""
SERVER_DIST.PY: MAIN SCRIPT FOR THE CLUSTER

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


@ray.remote
def run_inference_no_batch(dataframe):
	# Remote function to run model inferencing on dataframes 
	pass


def serve_workers():
	# Pull dataframe from queue.
	# Send dataframe to available nodes.
	# Get back inferences
	pass


def create_data_frame_entry_from_flow(flow):
	# Create dataframe entry with fields respective to model only.
	
	bytes_sec = flow.bidirectional_bytes / ((flow.bidirectional_duration_ms + 0.000001) * 0.001)
	packets_sec = flow.bidirectional_packets / ((flow.bidirectional_duration_ms + 0.000001) * 0.001)
	fwd_packets_sec = flow.src2dst_packets / ((flow.src2dst_duration_ms + 0.00000001) * 0.0001)
	bwd_packets_sec = flow.dst2src_packets / ((flow.dst2src_duration_ms + 0.0000001) * 0.0001)

	entry = [flow.dst_port, flow.bidirectional_duration_ms, flow.src2dst_packets, flow.dst2src_packets, flow.src2dst_bytes, flow.dst2src_bytes, flow.src2dst_max_ps, flow.src2dst_min_ps, flow.src2dst_mean_ps, flow.src2dst_stddev_ps, flow.dst2src_max_ps, flow.dst2src_min_ps, flow.dst2src_mean_ps, flow.dst2src_stddev_ps, bytes_sec, packets_sec, flow.bidirectional_mean_piat_ms, flow.bidirectional_stddev_piat_ms, flow.bidirectional_max_piat_ms, flow.bidirectional_min_piat_ms, flow.src2dst_mean_piat_ms, flow.src2dst_stddev_piat_ms, flow.src2dst_max_piat_ms, flow.src2dst_min_piat_ms, flow.dst2src_mean_piat_ms, flow.dst2src_stddev_piat_ms, flow.dst2src_max_piat_ms, flow.dst2src_min_piat_ms, flow.src2dst_psh_packets, flow.dst2src_psh_packets, flow.src2dst_urg_packets, flow.dst2src_urg_packets, fwd_packets_sec, bwd_packets_sec, flow.bidirectional_max_ps, flow.bidirectional_mean_ps, flow.bidirectional_stddev_ps, flow.bidirectional_fin_packets, flow.bidirectional_syn_packets, flow.bidirectional_rst_packets, flow.bidirectional_psh_packets, flow.bidirectional_ack_packets, flow.bidirectional_urg_packets, flow.bidirectional_cwr_packets, flow.bidirectional_ece_packets]



# Capture traffic into a flow and send as work to the worker nodes.
def capture_stream():

	print('[*] Beginning stream capture.')

	#TODO LATER: Change to external output default interface
	column_names = ['Destination Port', 'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets', 'Total Length of Fwd Packets', 'Total Length of Bwd Packets', 'Fwd Packet Length Max', 'Fwd Packet Length Min', 'Fwd Packet Length Mean', 'Fwd Packet Length Std', 'Bwd Packet Length Max', 'Bwd Packet Length Min', 'Bwd Packet Length Mean', 'Bwd Packet Length Std', 'Flow Bytes/s', 'Flow Packets/s', 'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min', 'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min', 'Fwd PSH Flags', 'Bwd PSH Flags', 'Fwd URG Flags', 'Bwd URG Flags',  'Fwd Packets/s', 'Bwd Packets/s', 'Min Packet Length', 'Max Packet Length', 'Packet Length Mean', 'Packet Length Std', 'FIN Flag Count', 'SYN Flag Count', 'RST Flag Count', 'PSH Flag Count', 'ACK Flag Count', 'URG Flag Count', 'CWE Flag Count', 'ECE Flag Count']
	cols_drops = ['Down/Up Ratio', 'Average Packet Size', 'Avg Fwd Segment Size', 'Avg Bwd Segment Size', 'Fwd Header Length', 'Fwd Avg Bytes/Bulk', 'Fwd Avg Packets/Bulk', 'Fwd Avg Bulk Rate', 'Bwd Avg Bytes/Bulk', 'Bwd Avg Packets/Bulk', 'Bwd Avg Bulk Rate', 'Subflow Fwd Packets', 'Subflow Fwd Bytes', 'Subflow Bwd Packets', 'Subflow Bwd Bytes', 'Init_Win_bytes_forward', 'Init_Win_bytes_backward', 'act_data_pkt_fwd', 'min_seg_size_forward', 'Active Mean', 'Active Std', 'Fwd IAT Total', 'Active Max', 'Active Min', 'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min', 'Bwd IAT Total', 'Fwd Header Length', 'Bwd Header Length', 'Packet Length Variance']
	interface = "en0"
	flow_limit = 25

	# Thread this into a shared queue and have the dataframe be acted upon by all actors in parallel
	# The dataframes can be placed in to the queue, while this acts in its own thread.
	streamer = NFStreamer(source=interface, promiscuous_mode=True, active_timeout=15, idle_timeout=15, n_meters=4, accounting_mode=3,statistical_analysis=True, decode_tunnels=False)

	flow_count = 0
	for flow in streamer:
		if flow_count >= flow_limit:
			flow_count = 0
			# Add dataframe to queue 
		entry = create_data_frame_entry_from_flow(flow)
		# append to dataframe
		flow_count += 1

	


if __name__ == "__main__":
	# start thread for capture stream
	capture_stream()
	# start other thread for serving workers


