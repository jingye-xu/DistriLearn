#!/usr/bin/env python3

import socket
import threading
import struct
import queue 
import time
import copy
import pickle
import signal
import psutil
import json
import os

from datetime import datetime


Q_MAX_SIZE = 200_000

SERVER_QUEUE = queue.Queue(maxsize=Q_MAX_SIZE)

lock = threading.Semaphore(1)
sq_lock = threading.Semaphore(1)

open_sockets = []


MAX_COMPUTE_NODE_ENTRIES = 50
MAX_COMPUTE_NODE_EVIDENCE_MALICIOUS_THRESHOLD = 10
MAX_COMPUTE_NODE_EVIDENCE_BENIGN_THRESHOLD = 26

MAX_MASTER_NODE_ENTRIES = 50
MAX_MASTER_NODE_EVIDENCE_MALICIOUS_THRESHOLD = 2
MAX_MASTER_NODE_EVIDENCE_BENIGN_THRESHOLD = 20


# Master acts as client 
def client_connection_thread():

	global open_sockets

	servers_connected_to = dict()

	while True:

		sq_lock.acquire()
		server_list = copy.deepcopy(SERVER_QUEUE.queue)
		sq_lock.release()

		for server in server_list:

			if server in servers_connected_to:
				continue

			try:

				client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

				print(f'[*] Attempting connection to {server}')
				client.connect(server)
				servers_connected_to[server] = 1

				lock.acquire()
				open_sockets.append(client)
				lock.release()

				print(f'[+] Connected to {server}')


			except Exception as e:
				print(f'[!] Connection to {server} failed: {e}')
				del servers_connected_to[server]
				lock.release()

		time.sleep(0.5)


# For receiving inferences of buffers

def client_listener_thread():

	evidence_buffer = {}
	prior_len = 0

	while True:

		lock.acquire()
		open_socket_len = len(open_sockets)
		lock.release()

		if prior_len != open_socket_len:
			print(f'[*] Total Access Points Connected: {open_socket_len}')

		item = 0
		while item < open_socket_len:

			socket = open_sockets[item]
			init_message = socket.recv(1024)
			result = json.loads(init_message) #init_message.decode('UTF-8')

			if result["mac"] == "0": # where collab mode 1 is connected to cluster
				continue
			else:
				#mac = list(result)[0]
				#pred = result[mac][0] # Use the mac to extract the tuple prediction (benign or malicious)
				#pred_num = result[mac][1] # Use the mac to extract the tuple number

				mac = result["mac"]
				pred = int(result["encode"])
				pred_num = int(result["evidence"])

				if mac not in evidence_buffer:
					evidence_buffer[mac] = {0: 0, 1: 0}

				evidence_buffer[mac][pred] += pred_num

				dt_string = datetime.now()

				if evidence_buffer[mac][0] >= MAX_MASTER_NODE_EVIDENCE_BENIGN_THRESHOLD:
					print(f'[! Inference notice {dt_string} !] {mac} has been benign.')
					evidence_buffer[mac][0] = 0

				if evidence_buffer[mac][1] >= MAX_MASTER_NODE_EVIDENCE_MALICIOUS_THRESHOLD:
					print(f'[! Inference notice {dt_string} !] {mac} has had suspicious activity.')
					evidence_buffer[mac][1] = 0

				if len(evidence_buffer) >= MAX_MASTER_NODE_ENTRIES:
					evidence_buffer = {}



			item += 1
		prior_len = open_socket_len
			


def discover_services():

	MAX_BUFFER_SIZE = 20046
	BROADCAST_PORT = 5882 # something not likely used by other things on the system
	BROADCAST_GROUP = '224.0.1.119' # multicasting subnet 
	SERVICE_MAGIC = 'n1d5mlm4gk' # service magic


	print('[*] Setting up service scan...')
	with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as receiver:

		service_addresses = dict()
		
		receiver.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

		receiver.bind((BROADCAST_GROUP, BROADCAST_PORT))

		#mreq = struct.pack('4sl' if interface_ip is None else '4s4s', socket.inet_aton(BROADCAST_GROUP), socket.INADDR_ANY if interface_ip is None else socket.inet_aton(interface_ip))
		mreq = struct.pack("4sl", socket.inet_aton(BROADCAST_GROUP), socket.INADDR_ANY)

		receiver.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)	

		print('[*] Starting scanning service...')

		while True:

			data, addr = receiver.recvfrom(MAX_BUFFER_SIZE)
			data_decoded = data.decode('UTF-8')
			data_split = data_decoded.split(':')

			proposed_magic = data_split[0]
			extra_info = data_split[1]
			server_port = data_split[2]

			if (proposed_magic == SERVICE_MAGIC) and (extra_info == "ids_service"):

				if addr not in service_addresses:
					service_addresses[addr] = 1
					print(f'[!] Detected IDS service from: {addr} Advertised Target TCP Port: {server_port}')
					SERVER_QUEUE.put((addr[0], int(server_port)))




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
	
	discovery_thread = threading.Thread(target=discover_services, args=())
	discovery_thread.start()

	client_thread = threading.Thread(target=client_connection_thread, args=())
	client_thread.start()

	client_listener = threading.Thread(target=client_listener_thread, args=())
	client_listener.start()

	discovery_thread.join()
	client_thread.join()
	client_listener.join()

