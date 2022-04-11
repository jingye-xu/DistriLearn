#!/usr/bin/env python3

import os
import sys
import threading
import socket


BIND_IP = "0.0.0.0"
BIND_PORT = 3254
BACKLOG_LIMIT = 20
MAX_LISTEN_BYTES = 4096


def setup_server(server):

	# Bind to address and port first 
	server.bind((BIND_IP, BIND_PORT))

	# Begin listening for connections. Limit backlog of unaccepted connections thru parameter
	server.listen(BACKLOG_LIMIT)
		
	print('[*] Listening on %s:%d...' % (BIND_IP, BIND_PORT))


def service_client(client_socket, client_ip):
	
	while True:
		# Listen for inferences, and aggregate
		msg = client_socket.recv(MAX_LISTEN_BYTES)
		print(msg)
		client_socket.send(b'Got your message!')


def accept_clients(server):
	
	while True:
		# Accept incoming connections
		client_socket, client_ip = server.accept()
		print('[*] Accepting connection from %s:%d' % (client_ip[0], client_ip[1]))
		client_thread = threading.Thread(target=service_client, args=(client_socket, client_ip))
		client_thread.run()


if __name__ == "__main__":
	
	with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
		try:
			setup_server(server)
			accept_clients(server)
		except:
			# TODO: make this more resilient to individual clients disconnecting.
			print('Closing the socket connection.')
			server.shutdown(socket.SHUT_RDWR)
			server.close()
		



