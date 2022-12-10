#!/usr/bin/env python3

import socket
import threading
import _thread
import struct
import queue 
import time
import copy
import pickle
import signal
import psutil
import json
import os
import select



Q_MAX_SIZE = 200_000

SERVER_QUEUE = queue.Queue(maxsize=Q_MAX_SIZE)
#SERVER_QUEUE = []

#lock = threading.Semaphore(1)
#sq_lock = threading.Semaphore(1)

lock = _thread.allocate_lock()
sq_lock = _thread.allocate_lock()

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
		#server_list = copy.deepcopy(SERVER_QUEUE.queue)
		server_list = copy.deepcopy(SERVER_QUEUE.queue)
		sq_lock.release()

		for server in server_list:

			if server in servers_connected_to:
				continue

			try:

				client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

				print('[*] Attempting connection to %s' % (server,))
				client.connect(server)
				print('[+] Connected to %s' % (server,))
				servers_connected_to[server] = 1

				lock.acquire()
				open_sockets.append(client)
				lock.release()

			except Exception as e:
				print('[!] Connection to %s failed: %s' % (server, e,))
				del servers_connected_to[server]



# For receiving inferences of buffers

def client_listener_thread():

	evidence_buffer = {}

	while True:

		lock.acquire()
		open_socket_len = len(open_sockets)
		lock.release()

		item = 0
		while item < open_socket_len:

			try:

				ap_socket = open_sockets[item]
				ap_socket.setblocking(0)
				ready = select.select([ap_socket], [], [], 0.25)
				result = {"mac": "0", "encode": "0", "evidence": "0"}
				if ready[0]:
					init_message = ap_socket.recv(1024)
					init_message = init_message.decode('UTF-8').split('}')[0] + '}'
					result = json.loads(init_message)

					#print(result)
					#init_message.decode('UTF-8')
				
				#data = [json.loads(line) for line in init_message]

				if result["mac"] == "0": # where collab mode 1 is connected to cluster
					item += 1
					continue
				else:
					mac = result["mac"]
					pred = int(result["encode"])
					pred_num = int(result["evidence"])

					if mac not in evidence_buffer:
						evidence_buffer[mac] = {0: 0, 1: 0}

					evidence_buffer[mac][pred] += pred_num

					gmtime = time.gmtime()
					dt_string = "%s:%s:%s" % (gmtime.tm_hour, gmtime.tm_min, gmtime.tm_sec)

					if evidence_buffer[mac][0] >= MAX_MASTER_NODE_EVIDENCE_BENIGN_THRESHOLD:
						print('\033[32;1m[ %s ]\033[0m %s - \033[32;1mNormal.\033[0m' % (dt_string, mac,))
						evidence_buffer[mac][0] = 0

					if evidence_buffer[mac][1] >= MAX_MASTER_NODE_EVIDENCE_MALICIOUS_THRESHOLD:
						print('\033[31;1m[ %s ]\033[0m %s - \033[31;1mSuspicious.\033[0m' % (dt_string, mac,))
						evidence_buffer[mac][1] = 0

					if len(evidence_buffer) >= MAX_MASTER_NODE_ENTRIES:
						evidence_buffer = {}

			except Exception as e:
				print(e)
				item += 1
				continue

			item += 1
			
		time.sleep(0.25)

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
					print('[!] Detected IDS service from: %s Advertised Target TCP Port: %s' % (addr, server_port,))
					sq_lock.acquire()
					SERVER_QUEUE.put_nowait((addr[0], int(server_port)))
					sq_lock.release()
			time.sleep(0.20)



def handler(signum, frame):

		global shutdown_flag

		process = psutil.Process(os.getpid())
		children = process.children()

		for child in children:
				child.kill()

		process = os.getpid()
		os.system("kill -9 %s" % (process,))




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


