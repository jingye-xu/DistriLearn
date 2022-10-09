#!/usr/bin/env python3

import socket
import threading
import struct


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

			if (proposed_magic == SERVICE_MAGIC) and (extra_info == "ids_service"):

				if addr not in service_addresses:
					service_addresses[addr] = 1
					print(f'[!] Detected IDS service from: {addr}')
		





if __name__ == "__main__":
	
	discovery_thread = threading.Thread(target=discover_services, args=())
	discovery_thread.start()


	discovery_thread.join()
