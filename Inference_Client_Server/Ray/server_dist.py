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


import pandas as pd
import numpy as np

import psutil

from nfstream import NFPlugin, NFStreamer
from dask.distributed import Client, Queue
from scapy.all import *

shutdown_flag = False

Q_MAX_SIZE = 100_000
MODEL_TYPE = 0 # 0 for scikit, 1 for pytorch - should be enum instead but python isn't clean like that
SCIKIT_MODEL_PATH = "./log_reg.pkl"
PYTORCH_MODEL_PATH = "./simple_model.pth"


QUEUE = queue.Queue(maxsize=0)
OBJ_REF_QUEUE = queue.Queue()

#TODO: Change IP address based on testbed node
client = Client("tcp://10.10.0.139:8786")



class ModelDriver:

	def __init__(self, path):
		self.model_path = path
		self.model = None

	def get_instance(self):
		pass

	def load_model(self):
		pass

	def predict(self, dataframe):
		pass


class ScikitModelDriver(ModelDriver):

	def __init__(self, model_path):
		super().__init__(model_path)

	def get_instance(self):		
		if self.model == None:
			self.load_model()

	def load_model(self):
		sci_model = joblib.load(self.model_path)
		self.model = sci_model

	def predict(self, dataframe):
		predictions = self.model.predict(dataframe.values)
		results = [0 if result < 0.5 else 1 for result in predictions]
		return results


class PyTorchModelDriver(ModelDriver):

	def __init__(self, model_path, net_class):
		super().__init__(model_path)
		self.net = net_class()

	def get_instance(self):
		if self.model == None:
			self.load_model()

	def load_model(self):
		model = self.net()
		model.load_state_dict(torch.load(self.model_path))
		model.eval()
		self.model = model

	def predict(self, dataframe):
		data_tensor = torch.tensor(dataframe.values, dtype=torch.float)
		data_tensor = torch.FloatTensor(data_tensor)
		results = self.model(data_tensor)
		results = [0 if result[0] < 0.5 else 1 for result in results.detach().numpy()]
		return results


model_driver = None

if MODEL_TYPE == 0:
	model_driver = ScikitModelDriver(SCIKIT_MODEL_PATH)
else:
	model_driver = PyTorchModelDriver(PYTORCH_MODEL_PATH, list)



MAX_COMPUTE_NODE_ENTRIES = 50
MAX_COMPUTE_NODE_EVIDENCE_THRESHOLD = 40

MAX_MASTER_NODE_ENTRIES = 50
MAX_MASTER_NODE_EVIDENCE_THRESHOLD = 50

evidence_buffer = {}

# Remote function for compute cluster
def run_inference_no_batch(dataframe):

	global evidence_buffer

	import socket
	h_name = socket.gethostname()
	IP_addres = socket.gethostbyname(h_name)

	model_driver.load_model()

	# Before predicting on the dataframe, we only pass in the dataframe WITHOUT the source mac (first column).
	# Because to all the models, that is the expected input dimension.

	predictions = model_driver.predict(dataframe.iloc[:,1:])

	# One-to-one mapping from dataframe to array rows
	ip_idx = 0
	while ip_idx < len(dataframe):
		ip = dataframe['Source Mac'][ip_idx]
		prediction = predictions[ip_idx]

		if ip not in evidence_buffer:
			evidence_buffer[ip] = {'benign': 0, 'malicious': 0}

		if prediction == 0:
			evidence_buffer[ip]['benign'] += 1
		else:
			evidence_buffer[ip]['malicious'] += 1

		ip_idx += 1
		

	# Flush the buffer to reduce memory usage
	if len(evidence_buffer) >= MAX_COMPUTE_NODE_ENTRIES:
		evidence_buffer = {}


	return f'Model {model_driver} predicted {evidence_buffer} \n ({len(predictions)}) from {IP_addres}.\n'


# Asynchronous thread to send the work asynchronously to workers
def serve_workers():

	# Send dataframe to available nodes.
	while not shutdown_flag:

		try:
			df = QUEUE.get(timeout=20)
			dask_future = client.submit(run_inference_no_batch, df)
			OBJ_REF_QUEUE.put(dask_future, timeout=60)
		except Empty:
			pass


# Asynchronous thread to obtain results from worker nodes
def obtain_results():
	
	while not shutdown_flag:

		try:
			dask_future = OBJ_REF_QUEUE.get(timeout=20)
			res = dask_future.result()
			print(res)
		except Empty:
			pass



def create_data_frame_entry_from_flow(flow):
	# Create dataframe entry with fields respective to model only.
	
	bytes_sec = flow.bidirectional_bytes / ((flow.bidirectional_duration_ms + 0.000001) * 0.001)
	packets_sec = flow.bidirectional_packets / ((flow.bidirectional_duration_ms + 0.000001) * 0.001)
	fwd_packets_sec = flow.src2dst_packets / ((flow.src2dst_duration_ms + 0.00000001) * 0.0001)
	bwd_packets_sec = flow.dst2src_packets / ((flow.dst2src_duration_ms + 0.0000001) * 0.0001)

	entry = [flow.src_mac, flow.dst_port, flow.bidirectional_duration_ms, flow.src2dst_packets, flow.dst2src_packets, flow.src2dst_bytes, flow.dst2src_bytes, flow.src2dst_max_ps, flow.src2dst_min_ps, flow.src2dst_mean_ps, flow.src2dst_stddev_ps, flow.dst2src_max_ps, flow.dst2src_min_ps, flow.dst2src_mean_ps, flow.dst2src_stddev_ps, bytes_sec, packets_sec, flow.bidirectional_mean_piat_ms, flow.bidirectional_stddev_piat_ms, flow.bidirectional_max_piat_ms, flow.bidirectional_min_piat_ms, flow.src2dst_mean_piat_ms, flow.src2dst_stddev_piat_ms, flow.src2dst_max_piat_ms, flow.src2dst_min_piat_ms, flow.dst2src_mean_piat_ms, flow.dst2src_stddev_piat_ms, flow.dst2src_max_piat_ms, flow.dst2src_min_piat_ms, flow.src2dst_psh_packets, flow.dst2src_psh_packets, flow.src2dst_urg_packets, flow.dst2src_urg_packets, fwd_packets_sec, bwd_packets_sec, flow.bidirectional_min_ps, flow.bidirectional_max_ps, flow.bidirectional_mean_ps, flow.bidirectional_stddev_ps, flow.bidirectional_fin_packets, flow.bidirectional_syn_packets, flow.bidirectional_rst_packets, flow.bidirectional_psh_packets, flow.bidirectional_ack_packets, flow.bidirectional_urg_packets, flow.bidirectional_cwr_packets, flow.bidirectional_ece_packets]
	return entry


# Capture traffic into a flow and send as work to the worker nodes.
def capture_stream():

	print('[*] Beginning stream capture.')

	#TODO LATER: Change to external output default interface
	column_names = ['Source Mac', 'Destination Port', 'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets', 'Total Length of Fwd Packets', 'Total Length of Bwd Packets', 'Fwd Packet Length Max', 'Fwd Packet Length Min', 'Fwd Packet Length Mean', 'Fwd Packet Length Std', 'Bwd Packet Length Max', 'Bwd Packet Length Min', 'Bwd Packet Length Mean', 'Bwd Packet Length Std', 'Flow Bytes/s', 'Flow Packets/s', 'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min', 'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min', 'Fwd PSH Flags', 'Bwd PSH Flags', 'Fwd URG Flags', 'Bwd URG Flags',  'Fwd Packets/s', 'Bwd Packets/s', 'Min Packet Length', 'Max Packet Length', 'Packet Length Mean', 'Packet Length Std', 'FIN Flag Count', 'SYN Flag Count', 'RST Flag Count', 'PSH Flag Count', 'ACK Flag Count', 'URG Flag Count', 'CWE Flag Count', 'ECE Flag Count']
	cols_drops = ['Down/Up Ratio', 'Average Packet Size', 'Avg Fwd Segment Size', 'Avg Bwd Segment Size', 'Fwd Header Length', 'Fwd Avg Bytes/Bulk', 'Fwd Avg Packets/Bulk', 'Fwd Avg Bulk Rate', 'Bwd Avg Bytes/Bulk', 'Bwd Avg Packets/Bulk', 'Bwd Avg Bulk Rate', 'Subflow Fwd Packets', 'Subflow Fwd Bytes', 'Subflow Bwd Packets', 'Subflow Bwd Bytes', 'Init_Win_bytes_forward', 'Init_Win_bytes_backward', 'act_data_pkt_fwd', 'min_seg_size_forward', 'Active Mean', 'Active Std', 'Fwd IAT Total', 'Active Max', 'Active Min', 'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min', 'Bwd IAT Total', 'Fwd Header Length', 'Bwd Header Length', 'Packet Length Variance']
	

	LISTEN_INTERFACE = "en0"
	flow_limit = 20
	MAX_PACKET_SNIFF = 100


	tmp_file = tempfile.NamedTemporaryFile(mode='wb')
	tmp_file_name = tmp_file.name

	while not shutdown_flag:

		dataframe = pd.DataFrame(columns=column_names)

		capture_start = time.time()
		capture = sniff(count=MAX_PACKET_SNIFF, iface=LISTEN_INTERFACE)
		capture_end = time.time()

		write_start = time.time()
		wrpcap(tmp_file_name, capture)
		write_end = time.time()

		print(f'Time to capture {MAX_PACKET_SNIFF} packets: {capture_end - capture_start:.02f}')
		print(f'Time to write to pcap: {write_end - write_start:.02f}')
		print(f'Size of pcap: {size_converter(os.stat(tmp_file_name).st_size)}')

		flow_start = time.time()
		streamer = NFStreamer(source=tmp_file_name, statistical_analysis=True, decode_tunnels=False, active_timeout=40, idle_timeout=40)
		
		for flow in streamer:
			entry = create_data_frame_entry_from_flow(flow)
			dataframe.loc[len(dataframe)] = entry
		flow_end = time.time()
		dataframe.iloc[:,1:] = dataframe.iloc[:,1:].astype("float32")

		print(f'Time to create flow table: {flow_end - flow_start:.02f}')
		print(f'Flow table memory size: {size_converter(dataframe.__sizeof__())}')
		print(f'Flow table sample size: {len(dataframe)}')
		QUEUE.put(dataframe, timeout=60)
		print(f'Queue size: {QUEUE.qsize()}')


def get_process_metrics():

	global shutdown_flag

	process = psutil.Process(os.getpid())

	while not shutdown_flag:

		used_mem = process.memory_full_info().uss
		size = size_converter(used_mem)

		print(f"Memory used: ~{size:.02f}", end='\r')



# Function from Stackoverflow. 
def size_converter(sz):
	size = sz
	# 2**10 = 1024
	power = 2**10
	n = 0
	power_labels = {0 : ' ', 1: 'K', 2: 'M', 3: 'G', 4: 'T'}
	while size > power:
		size /= power
		n += 1

	used = str(size) + " " + power_labels[n]+'B'

	return used



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


