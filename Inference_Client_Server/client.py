#!/usr/bin/env python3


import os
import sys
import socket
import threading

SERVER_IP = "0.0.0.0"
SERVER_PORT = 3254
MAX_LISTEN_BYTES = 4096

if __name__ == "__main__":
	

	with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
		
		print('[*] Connecting to %s%d' % (SERVER_IP, SERVER_PORT))

		client.connect((SERVER_IP, SERVER_PORT))
		# TODO: Load model and begin running inferences. Send to server. 
		while True:
			msg = input('Enter your message: ')
			client.send(bytes(msg, encoding='UTF-8'))
			response = client.recv(MAX_LISTEN_BYTES)
			print(response)