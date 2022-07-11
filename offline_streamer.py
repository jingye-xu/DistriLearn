#!/usr/bin/env python3

from nfstream import NFStreamer
import time
import pandas as pd
import torch
import os
import numpy as np
import torch.nn as nn
import torch.nn.functional as F
import torchvision.transforms as transforms
from tabulate import tabulate
from sklearn import metrics
import warnings
from net_structs import Net

#warnings.filterwarnings("ignore")

column_names = ['Destination Port', 'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets', 'Total Length of Fwd Packets', 'Total Length of Bwd Packets', 'Fwd Packet Length Max', 'Fwd Packet Length Min', 'Fwd Packet Length Mean', 'Fwd Packet Length Std', 'Bwd Packet Length Max', 'Bwd Packet Length Min', 'Bwd Packet Length Mean', 'Bwd Packet Length Std', 'Flow Bytes/s', 'Flow Packets/s', 'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min', 'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min', 'Fwd PSH Flags', 'Bwd PSH Flags', 'Fwd URG Flags', 'Bwd URG Flags',  'Fwd Packets/s', 'Bwd Packets/s', 'Min Packet Length', 'Max Packet Length', 'Packet Length Mean', 'Packet Length Std', 'FIN Flag Count', 'SYN Flag Count', 'RST Flag Count', 'PSH Flag Count', 'ACK Flag Count', 'URG Flag Count', 'CWE Flag Count', 'ECE Flag Count']

file_name = '/Users/gabem/Downloads/Thursday-WorkingHours.pcap' 
first_model_path = '/Users/gabem/Downloads/MachineLearningCVE/simple_model_v1.pth'

"""
MODEL ARCHITECTURES
"""

NUM_INPUT = 46
batch_size = 2


def create_data_frame_entry_from_flow(flow):
	# Create dataframe entry with fields respective to model only.
	
	bytes_sec = flow.bidirectional_bytes / ((flow.bidirectional_duration_ms + 0.000001) * 0.001)
	packets_sec = flow.bidirectional_packets / ((flow.bidirectional_duration_ms + 0.000001) * 0.001)
	fwd_packets_sec = flow.src2dst_packets / ((flow.src2dst_duration_ms + 0.00000001) * 0.0001)
	bwd_packets_sec = flow.dst2src_packets / ((flow.dst2src_duration_ms + 0.0000001) * 0.0001)

	entry = [flow.dst_port, flow.bidirectional_duration_ms, flow.src2dst_packets, flow.dst2src_packets, flow.src2dst_bytes, flow.dst2src_bytes, flow.src2dst_max_ps, flow.src2dst_min_ps, flow.src2dst_mean_ps, flow.src2dst_stddev_ps, flow.dst2src_max_ps, flow.dst2src_min_ps, flow.dst2src_mean_ps, flow.dst2src_stddev_ps, bytes_sec, packets_sec, flow.bidirectional_mean_piat_ms, flow.bidirectional_stddev_piat_ms, flow.bidirectional_max_piat_ms, flow.bidirectional_min_piat_ms, flow.src2dst_mean_piat_ms, flow.src2dst_stddev_piat_ms, flow.src2dst_max_piat_ms, flow.src2dst_min_piat_ms, flow.dst2src_mean_piat_ms, flow.dst2src_stddev_piat_ms, flow.dst2src_max_piat_ms, flow.dst2src_min_piat_ms, flow.src2dst_psh_packets, flow.dst2src_psh_packets, flow.src2dst_urg_packets, flow.dst2src_urg_packets, fwd_packets_sec, bwd_packets_sec, flow.bidirectional_min_ps, flow.bidirectional_max_ps, flow.bidirectional_mean_ps, flow.bidirectional_stddev_ps, flow.bidirectional_fin_packets, flow.bidirectional_syn_packets, flow.bidirectional_rst_packets, flow.bidirectional_psh_packets, flow.bidirectional_ack_packets, flow.bidirectional_urg_packets, flow.bidirectional_cwr_packets, flow.bidirectional_ece_packets]
	return entry


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


def get_simple_name(file_path):
	return file_path.split(os.path.sep)[-1]



def get_predictions(results):
	final_results = {}

	i = 0
	while i < len(results):
		pred = results[i]
		ip = source_ips[i]
		
		if not ip in final_results:
			final_results[ip] = {'benign':0, 'malicious':0}
		if pred == 0:
			final_results[ip]['benign'] += 1
		else:
			final_results[ip]['malicious'] += 1

		i += 1

	res_table_organized = []

	# For preliminary purposes, we shall use the ratio of benign or malicious and collect evidence this way.

	for res in final_results.keys():
		ip = final_results[res]
		benign = final_results[res]['benign']
		malicious = final_results[res]['malicious']

		total_flows = benign + malicious
		malicious_ratio = malicious / total_flows
		final_judgement = 'likely benign node'
		if malicious_ratio > 0.5:
			final_judgement = 'likely malicious node'

		res_table_organized.append([res, benign, malicious, final_judgement])

	return res_table_organized



def print_table(results):
	table = tabulate(get_predictions(results), headers=['source','likely benign flows', 'likely malicious flows', 'final judgment'])
	print(table)
	print('\n')



"""
PROFILE STREAMER AND OBTAIN DATAFRAME
"""

source_macs = []
source_ips = []

print('Starting stream read...')
print(f'File \"{get_simple_name(file_name)}\" size: {size_converter(os.stat(file_name).st_size)}')

stream_read_start = time.time()
streamer = NFStreamer(source=file_name, accounting_mode=3, statistical_analysis=True, decode_tunnels=False, active_timeout=250, idle_timeout=250)

dataframe = pd.DataFrame(columns=column_names)
limiter = 0 # Can reach hundreds of thousands of flows if not careful, even repetative entries. 
for flow in streamer:
	if limiter > 5_000: # at most 200 flow entries allowed for benchmarking
		break
	source_macs.append(flow.src_mac)
	source_ips.append(flow.src_ip)
	entry = create_data_frame_entry_from_flow(flow)
	dataframe.loc[len(dataframe)] = entry
	limiter += 1

stream_read_end = time.time()
total_time = stream_read_end - stream_read_start

# Convert all data to float type
dataframe = dataframe.astype("float32")

print(f'Time to read & convert to dataframe using NFStream: {total_time} seconds\n')
print(dataframe)


"""
END PROFILE
"""


"""
MODEL BENCHMARKS - PyTorch
"""
print("\n")
print("Benchmarking simple Pytorch model...")
print(f"Model \"{first_model_path.split(os.path.sep)[-1]}\" disk size: {size_converter(os.stat(first_model_path).st_size)}")
model_load_start = time.time()
model = Net()
model.load_state_dict(torch.load(first_model_path))
model_load_end = time.time()
print(f"Time to load model: {model_load_end - model_load_start} seconds")
print(f"Approx memory space taken by model: {size_converter(model.__sizeof__())}")

# Dataset in dataframe now. Next is inference benchmarking.
# WE need to inlude source mac or IP for inference only. 
# SO as we build flow entries, we need to incorporate the address or something along this vein.

model.eval()


# Convert data to tensors
data_tensor = torch.tensor(dataframe.values, dtype=torch.float)
data_tensor = torch.FloatTensor(data_tensor)


# Source IPs/MACs contain the same number of IPs and MACs as there are flows in the table.
# duplicates are allowed to show.
print(f'Number of entries (flows) in table: {len(dataframe)}')
print(f'Approx memory space taken by table: {size_converter(dataframe.__sizeof__())}')



inf_time_start = time.time()
results = model(data_tensor)
inf_time_end = time.time()

print(f'Pytorch inference time: {inf_time_end - inf_time_start} seconds')


results = [0 if result[0] < 0.5 else 1 for result in results.detach().numpy()]

print('')

print_table(results)

"""
END BENCHMARKS
"""


"""
MODEL BENCHMARKS -  Scikit 
"""

def benchmark_model(model_path):

	import joblib

	print(f'Benchmarking scikit model: {get_simple_name(model_path)}...')
	print(f'Model disk size: {size_converter(os.stat(model_path).st_size)}')

	model_load_start = time.time()
	sci_model = joblib.load(model_path)
	model_load_end = time.time()

	print(f'Model load time: {model_load_end - model_load_start} seconds')
	print(f'Approx model memory space: {size_converter(sci_model.__sizeof__())}')

	predict_time_st = time.time()
	predictions = sci_model.predict(dataframe.values)
	predict_time_end = time.time()

	print(f'Time to inference scikit model: {predict_time_end - predict_time_st} seconds')
	print()

	results = [0 if result < 0.5 else 1 for result in predictions]

	print('')

	print_table(results)





logistic_path = "/Users/gabem/Downloads/MachineLearningCVE/log_reg.pkl"
random_forest_reduced_path = "/Users/gabem/Downloads/MachineLearningCVE/RandomForest_Reduced2.pkl"
KNPath = "/Users/gabem/Downloads/MachineLearningCVE/KNeighbors.pkl"
svm_path = "/Users/gabem/Downloads/MachineLearningCVE/support_vector.pkl"

# random_forest_path = "/Users/gabem/Downloads/MachineLearningCVE/RandomForest.pkl"

model_paths = [logistic_path, random_forest_reduced_path, KNPath, svm_path]

# Benchmark all scikit-based models
for path in model_paths:
	benchmark_model(path)


"""
END BENCHMARKS
"""
