#!/usr/bin/env python3


import os
import sys
import socket
import threading
import pickle

import torch
import torch.nn as nn
import torch.nn.functional as F
import torchvision.transforms as transforms
from torch.utils.data import DataLoader, TensorDataset

import pandas as pd
import numpy as np

from scapy.all import *

SERVER_IP = "127.0.0.1"
SERVER_PORT = 3254
MAX_LISTEN_BYTES = 65536

# Model options
MODEL_PATH = './model_structure/model.pth'
DEVICE = torch.device("cuda:0" if torch.cuda.is_available() else "cpu")
NUM_INPUT = 10
batch_size = 2

# Model (simple CNN adapted from 'PyTorch: A 60 Minute Blitz')
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



if __name__ == "__main__":

	with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
		
		pickle_first_bytes = b'\x80\x04\x95'

		print('[*] Connecting to %s:%d' % (SERVER_IP, SERVER_PORT))

		client.connect((SERVER_IP, SERVER_PORT))


		# TODO: Load model here.
		print('[*] Loading model...')
		model = Net()
		model.load_state_dict(torch.load(MODEL_PATH))
		model.eval()
		print('[*] Done loading model.')
		
		while True:

			# Block receive!
			response = client.recv(MAX_LISTEN_BYTES)

			first_three_bytes = response[:3]

			if pickle_first_bytes != first_three_bytes:
				continue

			deserialized_object = pickle.loads(response)
			print(deserialized_object)

			#deserialized_object.astype(np.float64)
			data_tensor = torch.from_numpy(deserialized_object.to_numpy().astype(np.float32))
			
			#X = torch.tensor(deserialized_object.values)
		
			results = model(data_tensor)

			src_macs = [src_mac for src_mac in deserialized_object['source_mac']]
			results = [0 if result[0] < 0.5 else 1 for result in results.detach().numpy()]
			
			res_lists = []
			idx = 0
			for _ in range(0, len(src_macs)):
				res_lists.append([src_macs[idx], results[idx]])
				idx += 1

			df = pd.DataFrame(res_lists, columns=['source_mac', 'prediction'])
			
			# TODO: Send new back inferences to server
			# Serialize object and send it back
			serialized_table = pickle.dumps(df)
			client.send(serialized_table)


