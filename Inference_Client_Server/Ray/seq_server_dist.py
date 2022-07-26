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
from read_local_var import var_read_json
import scapy.config

import torch
import torch.nn as nn
import torch.nn.functional as F
import torchvision.transforms as transforms


import pandas as pd
import numpy as np

import psutil

from nfstream import NFPlugin, NFStreamer
from dask.distributed import Client, Queue
from scapy.all import *

conf.bufsize = 66536
conf.ipv6_enabed = False
conf.promisc = True
conf.recv_poll_rate = 0.02

shutdown_flag = False

MODEL_TYPE = 0 # 0 for scikit, 1 for pytorch - should be enum instead but python isn't clean like that
SCIKIT_MODEL_PATH = "./ModelPack/clean_17_models/Log regression/log_reg_2017.pkl"
SCALER_PATH = "./ModelPack/clean_17_models/Log regression/scaler_log_reg_17.pkl"
PYTORCH_MODEL_PATH = "./ModelPack/clean_17_models/NN/simple_nn_17.pth"


# obtain var from local file
var = var_read_json()
pfsense_wan_ip = var["pfsense_wan_ip"]
pfsense_pass = var["pfsense_pass"]
pfsense_lan_ip = var["pfsense_lan_ip"]

lan_nic = var["lan_nic"]

ssh_client_ip = var["ssh_client_ip"]
ssh_client_port = var["ssh_client_port"]

dask_scheduler_ip = var["dask_scheduler_ip"]
dask_scheduler_port = var["dask_scheduler_port"]

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
				print(f'Loaded scaler: {self.scaler}')

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
				results = [0 if result < 0.5 else 1 for result in predictions]
				return results


class PyTorchModelDriver(ModelDriver):

		def __init__(self, model_path, net_class, scaler_path):
				super().__init__(model_path, scaler_path)
				self.net = net_class

		def get_instance(self):
				if self.model == None:
						self.load_model()

		def load_model(self):
				model = self.net
				model.load_state_dict(torch.load(self.model_path))
				model.eval()
				self.model = model

		def predict(self, dataframe):
				vals = self.scaler.transform(dataframe.values)
				data_tensor = torch.tensor(vals, dtype=torch.float)
				data_tensor = torch.FloatTensor(data_tensor)
				results = self.model(data_tensor)
				results = [0 if result[0] < 0.6 else 1 for result in results.detach().numpy()]
				return results

model_driver = None

if MODEL_TYPE == 0:
		model_driver = ScikitModelDriver(SCIKIT_MODEL_PATH, SCALER_PATH)
else:
		model_driver = PyTorchModelDriver(PYTORCH_MODEL_PATH, Net(), SCALER_PATH)


# Remote function for compute cluster
def run_inference_no_batch(dataframe):


	from datetime import datetime

	dt_string = datetime.now()

	if dataframe is None or len(dataframe) == 0:
		return 0

	instance_start = time.time()
	model_driver.get_instance()
	instance_end = time.time()
	
	#print(f"Time to obtain model object: {instance_end - instance_start}")

	# Before predicting on the dataframe, we only pass in the dataframe WITHOUT the source mac (first column).
	# Because to all the models, that is the expected input dimension.

	pred_start = time.time()
	predictions = model_driver.predict(dataframe.iloc[:,1:])
	pred_end = time.time()

	#print(f"Time to inference sequentially: {pred_end - pred_start}")

	ip_idx = 0
	while ip_idx < len(dataframe):
		mac = dataframe[0][ip_idx]
		prediction = predictions[ip_idx]

		if prediction == 0:
			print(f'[! Inference notice {dt_string} !] {mac} has been benign.')
		else:
			print(f'[! Inference notice {dt_string} !] {mac} has been detected to have malicious activity.')	

		ip_idx += 1





# Asynchronous thread to obtain results from worker nodes
def obtain_results(dataframe):


	run_inference_no_batch(dataframe)


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


	dataframe = pd.DataFrame()
	while not shutdown_flag:

		capture_start = time.time()
		capture = sniff(count=MAX_PACKET_SNIFF, iface=LISTEN_INTERFACE)

		# Temporary sniffing workaround for VM environment:
		# os.system(f"sshpass -p \"{pfsense_pass}\" ssh root@{pfsense_wan_ip} \"tcpdump -i {lan_nic} -c {MAX_PACKET_SNIFF} -w - \'not (src {ssh_client_ip} and port {ssh_client_port}) and not (src {pfsense_lan_ip} and dst {ssh_client_ip} and port 22)\'\" 2>/dev/null > {tmp_file_name}")

		capture_end = time.time()

		write_start = time.time()
		wrpcap(tmp_file_name, capture)
		write_end = time.time()

		
		#print(f'Time to capture {MAX_PACKET_SNIFF} packets: {capture_end - capture_start:.02f}')
		#print(f'Time to write to pcap: {write_end - write_start:.02f}')
		#print(f'Size of pcap: {size_converter(os.stat(tmp_file_name).st_size)}')
		

		flow_start = time.time()
		streamer = NFStreamer(source=tmp_file_name, statistical_analysis=True, decode_tunnels=False, active_timeout=10_300, idle_timeout=10_920, accounting_mode=3)
		
		mapped = map(create_data_frame_entry_from_flow, iter(streamer))

		df = pd.DataFrame(mapped)
		flow_end = time.time()

		dataframe = pd.concat([dataframe,df], ignore_index=True)

		#print(f"Time to create flow table: {flow_end - flow_start}")

		obtain_results(dataframe)

		if len(dataframe) >= 135:
			dataframe = pd.DataFrame()




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

	process = os.getpid()
	os.system(f"kill -9 {process}")


if __name__ == "__main__":

	signal.signal(signal.SIGINT, handler)
	signal.signal(signal.SIGTERM, handler)


	capture_stream()
				
