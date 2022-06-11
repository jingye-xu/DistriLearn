#!/usr/bin/env python3

from nfstream import NFStreamer
import time
import pandas as pd
import torch
import os
import torch.nn as nn
import torch.nn.functional as F
import torchvision.transforms as transforms

column_names = ['Destination Port', 'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets', 'Total Length of Fwd Packets', 'Total Length of Bwd Packets', 'Fwd Packet Length Max', 'Fwd Packet Length Min', 'Fwd Packet Length Mean', 'Fwd Packet Length Std', 'Bwd Packet Length Max', 'Bwd Packet Length Min', 'Bwd Packet Length Mean', 'Bwd Packet Length Std', 'Flow Bytes/s', 'Flow Packets/s', 'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min', 'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min', 'Fwd PSH Flags', 'Bwd PSH Flags', 'Fwd URG Flags', 'Bwd URG Flags',  'Fwd Packets/s', 'Bwd Packets/s', 'Min Packet Length', 'Max Packet Length', 'Packet Length Mean', 'Packet Length Std', 'FIN Flag Count', 'SYN Flag Count', 'RST Flag Count', 'PSH Flag Count', 'ACK Flag Count', 'URG Flag Count', 'CWE Flag Count', 'ECE Flag Count']

file_name = '/Users/gabem/Desktop/Inference_Client_Server/Pcaps/attack_test3_full_mirrors.pcapng'
first_model_path = '/Users/gabem/Downloads/MachineLearningCVE/model.pth'

"""
MODEL ARCHITECTURES
"""

NUM_INPUT = 46
batch_size = 2

# Simple Model 3-layer NN 
class Net(nn.Module):
	def __init__(self) -> None:
		super(Net, self).__init__()

		self.fc1 = nn.Sequential(
			nn.Linear(in_features=NUM_INPUT, out_features=10),
			nn.ReLU())
		self.fc2 = nn.Sequential(
			nn.Linear(in_features=10, out_features=10),
			nn.ReLU())
		self.output = nn.Linear(in_features=10, out_features=1)

	def forward(self, x: torch.Tensor) -> torch.Tensor:
		output = self.fc1(x)
		output = self.fc2(output)
		output = self.output(output)
		return output


"""
END MODELS
"""


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


"""
PROFILE STREAMER AND OBTAIN DATAFRAME
"""

print('Starting stream read...')
print(f'File \"{file_name.split(os.path.sep)[-1]}\" size: {size_converter(os.stat(file_name).st_size)}')

stream_read_start = time.time()
streamer = NFStreamer(source=file_name, accounting_mode=3, statistical_analysis=True, decode_tunnels=False, active_timeout=150, idle_timeout=150)

dataframe = pd.DataFrame(columns=column_names)
limiter = 0 # Can reach hundreds of thousands of flows if not careful, even repetative entries. 
for flow in streamer:
	if limiter > 200: # at most 200 flow entries allowed for benchmarking
		break
	entry = create_data_frame_entry_from_flow(flow)
	dataframe.loc[len(dataframe)] = entry

stream_read_end = time.time()
total_time = stream_read_end - stream_read_start


print(f'Time to read & convert to dataframe using NFStream: {total_time} seconds\n')
print(dataframe)



"""
END PROFILE
"""


"""
MODEL BENCHMARKS
"""
print("\n")
print("Benchmarking simple model...")
print(f"Model \"{first_model_path.split(os.path.sep)[-1]}\" size: {size_converter(os.stat(first_model_path).st_size)}")
model_load_start = time.time()
model = Net()
model.load_state_dict(torch.load(first_model_path))
model.eval()
model_load_end = time.time()
print(f"Time to load model: {model_load_end - model_load_start} seconds")


# Dataset in dataframe now. Next is inference benchmarking.
# WE need to inlude source mac or IP for inference only. 
# SO as we build flow entries, we need to incorporate the address or something along this vein.


"""
END BENCHMARKS
"""
