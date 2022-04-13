#!/usr/bin/env python3

import os
import sys
import threading
import socket
import pickle
import queue

from scapy.all import *


BIND_IP = "127.0.0.1"
BIND_PORT = 3254
BACKLOG_LIMIT = 20
MAX_LISTEN_BYTES = 65536

Q_MAX_SIZE = 100

LISTEN_INTERFACE = 'en0'

QUEUE = queue.Queue(maxsize=Q_MAX_SIZE)

def setup_server(server):

	# Bind to address and port first 
	server.bind((BIND_IP, BIND_PORT))

	# Begin listening for connections. Limit backlog of unaccepted connections thru parameter
	server.listen(BACKLOG_LIMIT)
		
	print('[*] Listening on %s:%d...' % (BIND_IP, BIND_PORT))


def service_client(client_socket, client_ip):
	
	pickle_first_bytes = b'\x80\x04\x95'

	while True:
		
		try:
			# Dequeue data and send to client
			packed_packet = QUEUE.get(block=True)

			first_three_bytes = packed_packet[:3]

			if pickle_first_bytes != first_three_bytes:
				continue

			client_socket.send(packed_packet)
			QUEUE.task_done()

			# Block receive! Listen for inferences, and aggregate
			# msg = client_socket.recv(MAX_LISTEN_BYTES)
		except:
			client_socket.close()
			print(f'[!] Disconnected client {client_ip[0]}:{client_ip[1]}')
			break
		


def accept_clients(server):
	
	while True:
		# Accept incoming connections
		client_socket, client_ip = server.accept()
		print('[*] Accepting connection from %s:%d' % (client_ip[0], client_ip[1]))
		client_thread = threading.Thread(target=service_client, args=(client_socket, client_ip))
		client_thread.start()



def capture_populate_queue():

	MAX_PACKET_SNIFF = 20

	pickle_first_bytes = b'\x80\x04\x95'

	while True:
		# capture packets
		capture = sniff(count=MAX_PACKET_SNIFF, iface=LISTEN_INTERFACE)
		# serialize with pickle (turn to bytes)
		serialized_cap = pickle.dumps(capture)

		first_three_bytes = serialized_cap[:3]

		if pickle_first_bytes != first_three_bytes:
			continue

		QUEUE.put(serialized_cap, block=True)


if __name__ == "__main__":


	print("[*] Opening socket for connections...")
	with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
		try:
			producer_thread = threading.Thread(target=capture_populate_queue)
			producer_thread.start()
			setup_server(server)
			accept_clients(server)
		except:
			# TODO: make this more resilient to individual clients disconnecting.
			print('Closing the socket connection.')
			server.shutdown(socket.SHUT_RDWR)
			server.close()
		



