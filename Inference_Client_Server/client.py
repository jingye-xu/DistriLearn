#!/usr/bin/env python3


import os
import sys
import socket
import threading
import pickle

from scapy.all import *

SERVER_IP = "127.0.0.1"
SERVER_PORT = 3254
MAX_LISTEN_BYTES = 65536

if __name__ == "__main__":
	

	with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
		
		pickle_first_bytes = b'\x80\x04\x95'
		
		print('[*] Connecting to %s:%d' % (SERVER_IP, SERVER_PORT))

		client.connect((SERVER_IP, SERVER_PORT))

		# TODO: Load model and begin running inferences. Send to server. 
		
		while True:

			# Block receive!
			response = client.recv(MAX_LISTEN_BYTES)

			first_three_bytes = response[:3]

			if pickle_first_bytes != first_three_bytes:
				continue

			deserialized_packet = pickle.loads(response) 
			print(deserialized_packet)


