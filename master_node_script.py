#!/usr/bin/env python3

import socket
import threading
import struct
import queue 
import time
import copy


Q_MAX_SIZE = 200_000

SERVER_QUEUE = queue.Queue(maxsize=Q_MAX_SIZE)

lock = threading.Semaphore(1)
sq_lock = threading.Semaphore(1)

open_sockets = []

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
				client.close()
				lock.release()

		time.sleep(0.5)


# For receiving inferences of buffers

def client_listener_thread():

	while True:

		lock.acquire()
		open_socket_len = len(open_sockets)
		lock.release()

		item = 0
		while item < open_socket_len:

			socket = open_sockets[item]
			init_message = socket.recv(1024)
			init_msg_decoded = init_message.decode('UTF-8')

			item += 1
			


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






if __name__ == "__main__":
	
	discovery_thread = threading.Thread(target=discover_services, args=())
	discovery_thread.start()

	client_thread = threading.Thread(target=client_connection_thread, args=())
	client_thread.start()

	# client_listener = threading.Thread(target=client_listener_thread, args=())
	# client_listener.start()

	discovery_thread.join()
	client_thread.join()
	# client_listener.join()

