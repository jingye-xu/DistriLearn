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
import torch
import torch.nn as nn


import pandas as pd
import numpy as np

import psutil

from nfstream import NFPlugin, NFStreamer
from dask.distributed import Client, Queue
from scapy.all import *


shutdown_flag = False

Q_MAX_SIZE = 200_000
MODEL_TYPE = 0 # 0 for scikit, 1 for pytorch - should be enum instead but python isn't clean like that
SCIKIT_MODEL_PATH = "./support_vector.pkl"
PYTORCH_MODEL_PATH = "./simple_model.pth"


QUEUE = queue.Queue(maxsize=Q_MAX_SIZE)
OBJ_REF_QUEUE = queue.Queue()

#TODO: Change IP address based on testbed node
client = Client("tcp://10.10.0.139:8786")

NUM_INPUT = 38
batch_size = 1

class Net(nn.Module):
	def __init__(self) -> None:
		super(Net, self).__init__()
		self.fc1 = nn.Linear(in_features=NUM_INPUT, out_features=30)
		self.fc2 = nn.Linear(in_features=30, out_features=20)
		self.fc3 = nn.Linear(in_features=20, out_features=1)

	def forward(self, x: torch.Tensor) -> torch.Tensor:
		output = self.fc1(x)
		output = torch.relu(output)
		output = self.fc2(output)
		output = torch.relu(output)
		output = self.fc3(output)
		output = torch.sigmoid(output)

		return output

class ModelDriver:

	def __init__(self, path, scaler_path):
		self.model_path = path
		print(f'Loaded model: {path}')
		self.model = None
		self.scaler = joblib.load(scaler_path)
		print(f'Loaded scaler: {scaler}')

	def get_instance(self):
		pass

	def load_model(self):
		pass

	def predict(self, dataframe):
		pass


class ScikitModelDriver(ModelDriver):

	def __init__(self, model_path, scaler_path):
		super().__init__(model_path, scaler_path)

	def get_instance(self):		
		if self.model is None:
			self.load_model()

	def load_model(self):
		sci_model = joblib.load(self.model_path)
		self.model = sci_model

	def predict(self, dataframe):
		vals = self.scaler.transform(dataframe.values)
		predictions = self.model.predict(vals)
		results = [0 if result < 0.3 else 1 for result in predictions]
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
		vals = self.scaler.transform(dataframe.values)
		data_tensor = torch.tensor(vals, dtype=torch.float)
		data_tensor = torch.FloatTensor(data_tensor)
		results = self.model(data_tensor)
		results = [0 if result[0] < 0.3 else 1 for result in results.detach().numpy()]
		return results


model_driver = None

if MODEL_TYPE == 0:
	model_driver = ScikitModelDriver(SCIKIT_MODEL_PATH)
else:
	model_driver = PyTorchModelDriver(PYTORCH_MODEL_PATH, Net())



MAX_COMPUTE_NODE_ENTRIES = 50
MAX_COMPUTE_NODE_EVIDENCE_MALICIOUS_THRESHOLD = 12
MAX_COMPUTE_NODE_EVIDENCE_BENIGN_THRESHOLD = 18

MAX_MASTER_NODE_ENTRIES = 50
MAX_MASTER_NODE_EVIDENCE_MALICIOUS_THRESHOLD = 8
MAX_MASTER_NODE_EVIDENCE_BENIGN_THRESHOLD = 18

evidence_buffer = {}

# Remote function for compute cluster
def run_inference_no_batch(dataframe):

	global evidence_buffer

	model_driver.get_instance()

	# Before predicting on the dataframe, we only pass in the dataframe WITHOUT the source mac (first column).
	# Because to all the models, that is the expected input dimension.

	predictions = model_driver.predict(dataframe.iloc[:,1:])

	# One-to-one mapping from dataframe to array rows
	res = 0
	ip_idx = 0
	while ip_idx < len(dataframe):
		ip = dataframe[0][ip_idx]
		prediction = predictions[ip_idx]

		if ip not in evidence_buffer:
			evidence_buffer[ip] = {'benign': 0, 'malicious': 0}

		if prediction == 0:
			evidence_buffer[ip]['benign'] += 1
		else:
			evidence_buffer[ip]['malicious'] += 1

		# Check evidence threshold, whichever surpasses first
		if evidence_buffer[ip]['benign'] >= MAX_COMPUTE_NODE_EVIDENCE_BENIGN_THRESHOLD:
			res = {ip : 'benign'}
			evidence_buffer[ip]['benign'] = 0
			break
		if evidence_buffer[ip]['malicious'] >= MAX_COMPUTE_NODE_EVIDENCE_MALICIOUS_THRESHOLD:
			res = {ip : 'malicious'}
			evidence_buffer[ip]['malicious'] = 0
			break

		ip_idx += 1
		
	print(f'DF: {len(dataframe)} buffer state: {evidence_buffer}')
	# Flush the buffer to reduce memory usage
	if len(evidence_buffer) >= MAX_COMPUTE_NODE_ENTRIES:
		evidence_buffer = {}


	# f'Model {model_driver} predicted {evidence_buffer} \n ({len(predictions)}) from {IP_addres}.\n'
	return res


# Asynchronous thread to send the work asynchronously to workers
def serve_workers():

	global shutdown_flag

	# Send dataframe to available nodes.
	while not shutdown_flag:

		try:
			df = QUEUE.get(timeout=1)
			dask_future = client.submit(run_inference_no_batch, df)
			OBJ_REF_QUEUE.put(dask_future, timeout=1)
		except Exception:
			pass


# Asynchronous thread to obtain results from worker nodes
def obtain_results():

	global evidence_buffer
	global shutdown_flag
	
	while not shutdown_flag:

		try:
			dask_future = OBJ_REF_QUEUE.get(timeout=1)
			res = dask_future.result()
			# we get back 0 - if nodes are not ready to give any inference
			# we get back {mac : benign/malicious} if enough evidence has been collected 
			if res == 0:
				print(f'[*] Buffer state: {len(evidence_buffer)} collections: {evidence_buffer}')
				continue
			else:
				mac = list(res)[0]
				pred = 0 if res[mac] == 'benign' else 1

				if mac not in evidence_buffer:
					evidence_buffer[mac] = {'benign': 0, 'malicious' : 0}

				if pred == 0:
					evidence_buffer[mac]['benign'] += 1
				else: 
					evidence_buffer[mac]['malicious'] += 1

				if evidence_buffer[mac]['benign'] >= MAX_MASTER_NODE_EVIDENCE_BENIGN_THRESHOLD:
					print(f'[! Inference notice !] {mac} found to be benign')
					evidence_buffer[mac]['benign'] = 0

				if evidence_buffer[mac]['malicious'] >= MAX_MASTER_NODE_EVIDENCE_MALICIOUS_THRESHOLD:
					print(f'[! Inference notice !] {mac} found to be malicious')
					evidence_buffer[mac]['malicious'] = 0

				if len(evidence_buffer) >= MAX_MASTER_NODE_ENTRIES:
					evidence_buffer = {}


		except Exception:
			pass



def create_data_frame_entry_from_flow(flow):
	# Create dataframe entry with fields respective to model only.
	# old * 0.001
	bytes_sec = flow.bidirectional_bytes / ((flow.bidirectional_duration_ms + 1) / 1000) 
	packets_sec = flow.bidirectional_packets / ((flow.bidirectional_duration_ms + 1) / 1000)
	fwd_packets_sec = flow.src2dst_packets / ((flow.src2dst_duration_ms + 1) / 1000)  
	bwd_packets_sec = flow.dst2src_packets / ((flow.dst2src_duration_ms + 1) / 1000)  
	fwd_iat_total = flow.src2dst_max_piat_ms # total time between two packets in forward direction
	bwd_iat_total = flow.dst2src_max_piat_ms # total time between two packets in the backward direction
	avg_packet_size = flow.bidirectional_bytes / flow.bidirectional_packets
	packet_length_variance = flow.bidirectional_stddev_ps ** 2
	
	return [flow.src_mac, flow.dst_port, flow.bidirectional_duration_ms, flow.src2dst_packets, flow.dst2src_packets, flow.src2dst_bytes, flow.dst2src_bytes, flow.src2dst_max_ps, flow.src2dst_min_ps, flow.src2dst_mean_ps, flow.src2dst_stddev_ps, flow.dst2src_max_ps, flow.dst2src_min_ps, flow.dst2src_mean_ps, flow.dst2src_stddev_ps, bytes_sec, packets_sec, flow.bidirectional_mean_piat_ms, flow.bidirectional_max_piat_ms, flow.bidirectional_min_piat_ms, fwd_iat_total, flow.src2dst_mean_piat_ms, flow.src2dst_stddev_piat_ms, flow.src2dst_max_piat_ms, flow.src2dst_min_piat_ms, bwd_iat_total, flow.dst2src_mean_piat_ms, flow.dst2src_stddev_piat_ms, flow.dst2src_max_piat_ms, flow.dst2src_min_piat_ms, fwd_packets_sec, bwd_packets_sec, flow.bidirectional_min_ps, flow.bidirectional_max_ps, flow.bidirectional_mean_ps, flow.bidirectional_stddev_ps, packet_length_variance, flow.bidirectional_rst_packets, avg_packet_size]


# Capture traffic into a flow and send as work to the worker nodes.
def capture_stream():


	print('[*] Beginning stream capture.')

	#TODO LATER: Change to external output default interface
	column_names = ['Source Mac', 'Destination Port', 'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets', 'Total Length of Fwd Packets', 'Total Length of Bwd Packets', 'Fwd Packet Length Max', 'Fwd Packet Length Min', 'Fwd Packet Length Mean', 'Fwd Packet Length Std', 'Bwd Packet Length Max', 'Bwd Packet Length Min', 'Bwd Packet Length Mean', 'Bwd Packet Length Std', 'Flow Bytes/s', 'Flow Packets/s', 'Flow IAT Mean', 'Flow IAT Max', 'Flow IAT Min', 'Fwd IAT Total', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min', 'Bwd IAT Total', 'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min', 'Fwd Packets/s', 'Bwd Packets/s', 'Min Packet Length', 'Max Packet Length', 'Packet Length Mean', 'Packet Length Std', 'Packet Length Variance', 'RST Flag Count', 'Average Packet Size']	

	LISTEN_INTERFACE = "en0"
	flow_limit = 20
	MAX_PACKET_SNIFF = 90


	tmp_file = tempfile.NamedTemporaryFile(mode='wb')
	tmp_file_name = tmp_file.name

	while not shutdown_flag:

		#dataframe = pd.DataFrame(columns=column_names)

		capture_start = time.time()
		#capture = sniff(count=MAX_PACKET_SNIFF, iface=LISTEN_INTERFACE)

		# Temporary sniffing workaround for VM environment:
		os.system(f"sshpass -p \"admin\" ssh root@10.10.0.178 \"tcpdump -i vtnet1 -c {MAX_PACKET_SNIFF} -w - \'not (src 10.10.0.139 and port 22) and not (src 192.168.1.1 and dst 10.10.0.139 and port 22)\'\" 2>/dev/null > {tmp_file_name}")

		capture_end = time.time()

		write_start = time.time()
		#wrpcap(tmp_file_name, capture)
		write_end = time.time()

		
		#print(f'Time to capture {MAX_PACKET_SNIFF} packets: {capture_end - capture_start:.02f}')
		#print(f'Time to write to pcap: {write_end - write_start:.02f}')
		#print(f'Size of pcap: {size_converter(os.stat(tmp_file_name).st_size)}')
		

		flow_start = time.time()
		streamer = NFStreamer(source=tmp_file_name, statistical_analysis=True, decode_tunnels=False, active_timeout=10_300, idle_timeout=10_920, accounting_mode=3)
		
		mapped = map(create_data_frame_entry_from_flow, iter(streamer))

		dataframe = pd.DataFrame(mapped)
		flow_end = time.time()


		print(f"Time to capture: {capture_end - capture_start}; Serving dataframe of size: {len(dataframe)}; Time to create flow table: {flow_end - flow_start}")
		#print(f'Flow table memory size: {size_converter(dataframe.__sizeof__())}')
		#print(f'Flow table sample size: {len(dataframe)}')

		
		
		try:
			QUEUE.put(dataframe, timeout=1)
		except Full:
			pass



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
	sys.exit(0)


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


