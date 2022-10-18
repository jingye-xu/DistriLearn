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
import scapy.config

import torch
import torch.nn as nn
import torch.nn.functional as F
import torchvision.transforms as transforms

import pandas as pd
import numpy as np

import psutil

from nfstream import NFPlugin, NFStreamer
from scapy.all import *
import socket
from datetime import datetime


conf.bufsize = 65536
conf.ipv6_enabed = False
#conf.promisc = True
conf.recv_poll_rate = 0.02

shutdown_flag = False

Q_MAX_SIZE = 200_000
OBJ_MAX_SIZE = 10_000

MODEL_TYPE = 0 # 0 for scikit, 1 for pytorch - should be enum instead but python isn't clean like that

PATH_PREF = "./ModelPack/17_18_models/K neighbors"

SCIKIT_MODEL_PATH = f"{PATH_PREF}/kn_17_18.pkl"
SCALER_PATH = f"{PATH_PREF}/scaler_kn_17_18.pkl"
PYTORCH_MODEL_PATH = f"{PATH_PREF}/simple_nn_1718.pth"


FLOW_QUEUE = queue.Queue(maxsize=Q_MAX_SIZE)
RESULT_QUEUE = queue.Queue(maxsize=Q_MAX_SIZE)
MASTER_QUEUE = queue.Queue(maxsize=Q_MAX_SIZE)

lock = threading.Semaphore()


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
				return self.model

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
				return self.model

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



MAX_COMPUTE_NODE_ENTRIES = 50
MAX_COMPUTE_NODE_EVIDENCE_MALICIOUS_THRESHOLD = 10
MAX_COMPUTE_NODE_EVIDENCE_BENIGN_THRESHOLD = 26

MAX_MASTER_NODE_ENTRIES = 50
MAX_MASTER_NODE_EVIDENCE_MALICIOUS_THRESHOLD = 2
MAX_MASTER_NODE_EVIDENCE_BENIGN_THRESHOLD = 20


AP_INFERENCE_SERVER_PORT = 56_231

COLLABORATIVE_MODE = 0 # 0 for local inference modes, 1 for global inference modes
NUMBER_CLIENTS = 0
CURRENT_MASTER = None

BACKUP_MASTERS = queue.Queue(maxsize=Q_MAX_SIZE)

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('', AP_INFERENCE_SERVER_PORT))

PRIVATE_MASTER_TIME = ''

evidence_buffer = {}


# Inference function for node
def run_inference_no_batch(dataframe):

		global evidence_buffer
		global COLLABORATIVE_MODE

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

		#print(f"Time to inference on client: {pred_end - pred_start}")

		map_start = time.time()
		# One-to-one mapping from dataframe to array rows
		res = 0
		ip_idx = 0
		while ip_idx < len(dataframe):
				ip = dataframe[0][ip_idx]
				prediction = predictions[ip_idx]
				if ip not in evidence_buffer:
						evidence_buffer[ip] = {0: 0, 1: 0}

				evidence_buffer[ip][prediction] += 1

				# Check evidence threshold, whichever surpasses first
				if evidence_buffer[ip][0] >= MAX_COMPUTE_NODE_EVIDENCE_BENIGN_THRESHOLD:
						res = {ip : (0, evidence_buffer[ip][0])} # 0 is encoded as benign
						evidence_buffer[ip][0] = 0
						break
				if evidence_buffer[ip][1] >= MAX_COMPUTE_NODE_EVIDENCE_MALICIOUS_THRESHOLD:
						res = {ip : (1, evidence_buffer[ip][1])} # 1 is encoded as malicious
						if evidence_buffer[ip][1] != 0:
							evidence_buffer[ip][1] //= evidence_buffer[ip][1]
						if evidence_buffer[ip][0] != 0:
							evidence_buffer[ip][0] //= evidence_buffer[ip][0]
						break

				ip_idx += 1
			
		map_end = time.time()
		#print(f"Map time: {map_end - map_start}\n")
		# print()

		#print(f'DF: {len(dataframe)} buffer state: {evidence_buffer}')
		# Flush the buffer to reduce memory usage
		if len(evidence_buffer) >= MAX_COMPUTE_NODE_ENTRIES:
				evidence_buffer = {}

		RESULT_QUEUE.put(res)
		# return res


# Asynchronous thread to send the work asynchronously to workers
def serve_workers():

		global shutdown_flag

		# Send dataframe to available nodes.
		while not shutdown_flag:

			df = FLOW_QUEUE.get()

			if df is None:
				continue

			run_inference_no_batch(df)


# Asynchronous thread to obtain results from worker nodes
def obtain_results():

		
		global evidence_buffer
		global shutdown_flag

		print('[*] Starting results thread...')
		
		while not shutdown_flag:

			result = RESULT_QUEUE.get()

			if result is None:
				continue

			dt_string = datetime.now()
			
			 # we get back 0 - if nodes are not ready to give any inference
			 # we get back {mac : benign/malicious} if enough evidence has been collected 
			if result == 0:
				continue
			else:
				mac = list(result)[0]
				pred = result[mac][0] # Use the mac to extract the tuple prediction (benign or malicious)
				pred_num = result[mac][1] # Use the mac to extract the tuple number

				if mac not in evidence_buffer:
					evidence_buffer[mac] = {0: 0, 1: 0}

				evidence_buffer[mac][pred] += pred_num

				if evidence_buffer[mac][0] >= MAX_MASTER_NODE_EVIDENCE_BENIGN_THRESHOLD:
					print(f'[! Inference notice {dt_string} !] {mac} has been benign.')
					evidence_buffer[mac][0] = 0

				if evidence_buffer[mac][1] >= MAX_MASTER_NODE_EVIDENCE_MALICIOUS_THRESHOLD:
					print(f'[! Inference notice {dt_string} !] {mac} has had suspicious activity.')
					evidence_buffer[mac][1] = 0

				if len(evidence_buffer) >= MAX_MASTER_NODE_ENTRIES:
					evidence_buffer = {}



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
def capture_stream(listen_interface):

		print('[*] Beginning stream capture.')

		column_names = ['Source Mac', 'Destination Port', 'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets', 'Total Length of Fwd Packets', 'Total Length of Bwd Packets', 'Fwd Packet Length Max', 'Fwd Packet Length Min', 'Fwd Packet Length Mean', 'Fwd Packet Length Std', 'Bwd Packet Length Max', 'Bwd Packet Length Min', 'Bwd Packet Length Mean', 'Bwd Packet Length Std', 'Flow Bytes/s', 'Flow Packets/s', 'Flow IAT Mean', 'Flow IAT Max', 'Flow IAT Min', 'Fwd IAT Total', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min', 'Bwd IAT Total', 'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min', 'Fwd Packets/s', 'Bwd Packets/s', 'Min Packet Length', 'Max Packet Length', 'Packet Length Mean', 'Packet Length Std', 'Packet Length Variance', 'RST Flag Count', 'Average Packet Size']      

		flow_limit = 20
		MAX_PACKET_SNIFF = 90

		tmp_file = tempfile.NamedTemporaryFile(mode='wb')
		tmp_file_name = tmp_file.name

		dataframe = pd.DataFrame()

		while not shutdown_flag:

				#dataframe = pd.DataFrame(columns=column_names)

				#capture_start = time.time()
				capture = sniff(iface=listen_interface, count=MAX_PACKET_SNIFF) 

				# Temporary sniffing workaround for VM environment:
				#os.system(f"sshpass -p \"{pfsense_pass}\" ssh root@{pfsense_wan_ip} \"tcpdump -i {lan_nic} -c {MAX_PACKET_SNIFF} -w - \'not (src {ssh_client_ip} and port {ssh_client_port}) and not (src {pfsense_lan_ip} and dst {ssh_client_ip} and port 22)\'\" 2>/dev/null > {tmp_file_name}")
				#os.system(f"tcpdump -i {listen_interface} -c {MAX_PACKET_SNIFF} -w - 2>/dev/null > {tmp_file_name}")

				#capture_end = time.time()

				# write_start = time.time()
				wrpcap(tmp_file_name, capture)
				# write_end = time.time()
				
				#print(f'Time to capture {MAX_PACKET_SNIFF} packets: {capture_end - capture_start:.02f}')
				#print(f'Time to write to pcap: {write_end - write_start:.02f}')
				#print(f'Size of pcap: {size_converter(os.stat(tmp_file_name).st_size)}')
				

				flow_start = time.time()
				streamer = NFStreamer(source=tmp_file_name, statistical_analysis=True, decode_tunnels=False, accounting_mode=3)
				
				mapped = map(create_data_frame_entry_from_flow, iter(streamer))

				df = pd.DataFrame(mapped)
				dataframe = pd.concat([dataframe,df], ignore_index=True)
				dataframe.dropna(how='all', inplace=True) 

				if len(dataframe) >= 30:
					for start in range(0, len(dataframe), 30):
						subdf = dataframe[start:start+30]
						subdf.reset_index(drop=True, inplace=True)
						FLOW_QUEUE.put(subdf)
						dataframe = df
				else:
					FLOW_QUEUE.put(dataframe)

				if len(dataframe) >= 105:
					dataframe = df
				
				flow_end = time.time()


				#print(f"Time to capture: {capture_end - capture_start}; Time to create flow table: {flow_end - flow_start}")
				#print(f'Flow table memory size: {size_converter(dataframe.__sizeof__())}')
				#print(f'Flow table sample size: {len(dataframe)}')


# Interval specified number of seconds to wait between broadcasts.
def broadcast_service(interval=0.8):
	
	global COLLABORATIVE_MODE
	global NUMBER_CLIENTS
	global PRIVATE_MASTER_TIME

	BROADCAST_PORT = 5882 # something not likely used by other things on the system
	BROADCAST_GROUP = '224.0.1.119' # multicasting subnet 
	BROADCAST_MAGIC = 'n1d5mlm4gk' # service magic
	MULTICAST_TTL = 100

	PRIVATE_AP_MULTICAST = '224.0.1.120'
	PRIVATE_AP_MAGIC = 'n1ds4PM4g1k'
	PRIVATE_PORT = 5882 

	print('[*] Beginning broadcast thread...')


	with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as udp_socket:

		udp_socket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, MULTICAST_TTL)
		udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

		data = f'{BROADCAST_MAGIC}:ids_service:{AP_INFERENCE_SERVER_PORT}'.encode('UTF-8')
		data = bytes(data)

		PREV_CLIENTS = NUMBER_CLIENTS
		while True:

			# multicast
			bytes_sent = udp_socket.sendto(data, (BROADCAST_GROUP, BROADCAST_PORT))
			lock.acquire()
			if PREV_CLIENTS != NUMBER_CLIENTS:
				PREV_CLIENTS = NUMBER_CLIENTS
				print(f'Collab mode: {COLLABORATIVE_MODE} Clients connected: {NUMBER_CLIENTS} Current Master: {CURRENT_MASTER[1] if CURRENT_MASTER is not None else None}')
			
			# Multicast private AP to make them aware of each other
			if CURRENT_MASTER is not None:
				data_ap_private = f'{PRIVATE_AP_MAGIC}$private_ap${CURRENT_MASTER[1][0]}${CURRENT_MASTER[1][1]}${PRIVATE_MASTER_TIME}'.encode('UTF-8')
			else:
				data_ap_private = f'{PRIVATE_AP_MAGIC}$private_ap$no_master$no_master_port$no_time'.encode('UTF-8')
			

			data_ap_private = bytes(data_ap_private)
			bytes_sent = udp_socket.sendto(data_ap_private, (PRIVATE_AP_MULTICAST, PRIVATE_PORT))
			lock.release()

			time.sleep(interval)


def ap_server():

	global COLLABORATIVE_MODE
	global NUMBER_CLIENTS
	global CURRENT_MASTER
	global PRIVATE_MASTER_TIME

	server_socket.listen(10)


	while True:

		connection_object, addr = server_socket.accept()

		print(f'[+] Accepted connection from {addr}')

		lock.acquire()
		COLLABORATIVE_MODE = 1
		NUMBER_CLIENTS += 1
		
		if CURRENT_MASTER is None and NUMBER_CLIENTS == 1:
			CURRENT_MASTER = [connection_object, addr]
			PRIVATE_MASTER_TIME = datetime.now()
		elif CURRENT_MASTER is None and NUMBER_CLIENTS > 1 and BACKUP_MASTERS.qsize() > 0:
			CURRENT_MASTER = BACKUP_MASTERS.get()
			PRIVATE_MASTER_TIME = datetime.now()
		
		if addr != CURRENT_MASTER[1]:
			print(f'[+] Queueing {addr}')
			BACKUP_MASTERS.put([connection_object,addr])

		lock.release()

		
		
def private_ap_thread():

	global CURRENT_MASTER
	global PRIVATE_MASTER_TIME

	PRIVATE_AP_MULTICAST = '224.0.1.120'
	PRIVATE_AP_MAGIC = 'n1ds4PM4g1k'
	PRIVATE_PORT = 5882
	

	private_receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
	private_receiver.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	private_receiver.bind((PRIVATE_AP_MULTICAST, PRIVATE_PORT))
	mreq = struct.pack("4sl", socket.inet_aton(PRIVATE_AP_MULTICAST), socket.INADDR_ANY)
	private_receiver.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)	

	# TODO: Make this better instead of trying to get the hostname infinitely
	IP_address = '10.10.0.252'


	while True:
		try:
			private_receipt, addr = private_receiver.recvfrom(2048)

			if addr[0] == IP_address:
				continue

			private_receipt = private_receipt.decode('UTF-8')
			private_receipt_tokens = private_receipt.split('$')

			if private_receipt_tokens[0] == PRIVATE_AP_MAGIC and private_receipt_tokens[1] == 'private_ap':

				master_ip = private_receipt_tokens[2]
				master_port = int(private_receipt_tokens[3]) if private_receipt_tokens[3] != 'no_master_port' else 0
				master_time = private_receipt_tokens[4]
				master_result = (master_ip, master_port)
				
				if master_result[0] != 'no_master':
					# compare our master and timestamp versus what we received
					lock.acquire()
					# Assume that we will never get duplicate master IPs.
					if CURRENT_MASTER[1][0] != master_result[0]:
						# if they are different, take the youngest one and update our info.
						# if they are different, but the times are not easy to tell apart, tale the higher IP
						received_time = datetime.fromisoformat(master_time)
						if received_time < PRIVATE_MASTER_TIME or (CURRENT_MASTER[1][0] < master_result[0]):

							PRIVATE_MASTER_TIME = received_time
							# Probably change this to a hashmap instead for speed.
							for master in BACKUP_MASTERS.queue:
								if master[1][0] == master_result[0]:
									old_master = CURRENT_MASTER
									CURRENT_MASTER = [master[0], master[1]]
									master[0] = 'X'
									master[1] = 'X'
									print(f'[*] Synchronized master to: {CURRENT_MASTER[1][0]}')
									BACKUP_MASTERS.put(old_master)
									break

					lock.release()
		except Exception as e:
			print(e)
			lock.release()
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

		process = os.getpid()
		os.system(f"kill -9 {process}")


def make_pretty_interfaces():
	interfaces = psutil.net_if_addrs()
	interface_dict_list = len(interfaces)
	interface_selector = {i + 1 : j for i, j in zip(range(interface_dict_list), interfaces.keys())} 

	message = []
	for key in interface_selector:
		message.append(f"{key}.) {interface_selector[key]}")

	return interface_selector, "\n".join(message)

if __name__ == "__main__":


		arg_length = len(sys.argv)

		if arg_length != 2:
			print('Missing argument for interface.')
			print('Usage: ./ap_unified_ids <interface_name>')
			sys.exit(0)

		interface_selector, int_choice_msg = make_pretty_interfaces()

		interface = sys.argv[1]

		print(f'Checking interface: {interface}...')

		if interface not in psutil.net_if_addrs():

			user_selection = 1_000_000

			while user_selection not in interface_selector:
				print(f'Interface not available. Select one of the ones below:')
				print(int_choice_msg)
				print(f'\nSelect an interface: ', end='')
				user_selection = int(input())

			interface = interface_selector[user_selection]
		print(f'Interface set to {interface}')

		signal.signal(signal.SIGINT, handler)
		signal.signal(signal.SIGTERM, handler)

		broadcast_thread = threading.Thread(target=broadcast_service, args=())
		broadcast_thread.start()

		capture_thread = threading.Thread(target=capture_stream, args=(interface,))
		capture_thread.start()

		serve_thread = threading.Thread(target=serve_workers, args=())
		serve_thread.start()

		ap_server_thread = threading.Thread(target=ap_server, args=())
		ap_server_thread.start()

		private_ap_mc = threading.Thread(target=private_ap_thread, args=())
		private_ap_mc.start()

		# resul_thread = threading.Thread(target=obtain_results, args=())
		# resul_thread.start()

		capture_thread.join()
		serve_thread.join()
		# resul_thread.join()
		broadcast_thread.join()
		ap_server_thread.join()
		private_ap_mc.join()


								
		
