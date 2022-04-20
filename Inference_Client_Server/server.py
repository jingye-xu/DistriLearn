#!/usr/bin/env python3

import os
import sys
import threading
import socket
import pickle
import queue
import signal

from scapy.all import *
import pandas as pd


# Hello world for OpenWRT

# Inference vectors for the vectors on our packets -- how can we use this info post-learning process?


BIND_IP = "127.0.0.1"
BIND_PORT = 3254
BACKLOG_LIMIT = 20
MAX_LISTEN_BYTES = 65536

Q_MAX_SIZE = 100

LISTEN_INTERFACE = 'en0'

QUEUE = queue.Queue(maxsize=Q_MAX_SIZE)

mac_key = dict()

def setup_server(server):

	# Bind to address and port first 
	server.bind((BIND_IP, BIND_PORT))

	# Begin listening for connections. Limit backlog of unaccepted connections thru parameter
	server.listen(BACKLOG_LIMIT)
	
	print('[*] Listening on %s:%d...' % (BIND_IP, BIND_PORT))



def handle_interrupt(sig, frame):
    stop_event.set()


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
			received_data_frame_pickled = client_socket.recv(MAX_LISTEN_BYTES)
			
			df = pickle.loads(received_data_frame_pickled)
			df['source_mac'] = df.apply(obtain_mac, axis=1)
			df['prediction'] = df.apply(obtain_label, axis=1)
			
			print(f'{df}\n')

		except Exception as e:
			client_socket.close()
			print(f'[!] Disconnected client {client_ip[0]}:{client_ip[1]} - {e}')
			break
		


def accept_clients(server):
	
	while True:
		# Accept incoming connections
		client_socket, client_ip = server.accept()
		print('[*] Accepting connection from %s:%d' % (client_ip[0], client_ip[1]))
		client_thread = threading.Thread(target=service_client, args=(client_socket, client_ip))
		client_thread.start()


def obtain_label(x):
	return 'benign' if x.prediction == 0 else 'malicious'

def obtain_mac(x):
	return mac_key[x.source_mac]

def protocol_parse(x):

	prot = {"tcp": 1,
                "udp": 2,
                "icmp": 3,
                "arp": 4}

	return prot[x.protocol]

def state_parse(x):
	state = {"0": 0,
                 "request": 1,
                 "reply": 2,
                 "respond": 2,
                 "ack": 3,
                 "finish": 4,
                 "other": 5}

	return state[x.state]

def mac_src_parse(x):

	# remove :
	mac_add = x.source_mac.split(":")

	result = 0
	for i in mac_add:
		result += int(i, 16)

	mac_key[result] = x.source_mac

	return result

def mac_dst_parse(x):

	# remove :
	mac_add = x.destination_mac.split(":")

	result = 0
	for i in mac_add:
		result += int(i, 16)

	return result

def ip_src_parse(x):

	# remove .
	ip_add = x.source_ip.split(".")

	return int(ip_add[3])


def ip_dst_parse(x):

	# remove .
	ip_add = x.destination_ip.split(".")

	return int(ip_add[3])


def capture_populate_queue():

	MAX_PACKET_SNIFF = 20

	pickle_first_bytes = b'\x80\x04\x95'

	data_header = ["timestamp", "protocol", "state", "source_mac", "destination_mac", "source_ip", "destination_ip", "source_port", "destination_port", "payload"]
	dataframe = pd.DataFrame(columns=data_header)

	while True:

		# capture packets
		capture = sniff(count=MAX_PACKET_SNIFF, iface=LISTEN_INTERFACE)

		# coding=utf-8
		# OUTPUT of csv file: "timestamp", "protocol", "state", "source_mac", "destination_mac",
		# "source_ip", "destination_ip", "source_port", "destination_port", "payload (length)"

		packet_list = []
		for packet in capture:
			
			proto_choice = None
			packet_src_mac = packet.src
			packet_dst_mac = packet.dst

			if IP in packet:

				packet_ip_layer = packet[IP]
				packet_byte_field = packet_ip_layer.get_field('proto')
				packet_proto = packet_byte_field.i2s[packet_ip_layer.proto]
				packet_src_ip = packet_ip_layer.src
				packet_dst_ip = packet_ip_layer.dst
				packet_state = "0"

				if packet_proto == 'tcp':
					packet_tcp_info = packet[TCP]
					packet_src_port = packet_tcp_info.sport
					packet_dst_port = packet_tcp_info.dport
					packet_flags = packet_tcp_info.flags
					packet_payload = len(packet_tcp_info.payload.original)
					flagrepr = packet_flags.flagrepr()

					if flagrepr == 'S':
						packet_state = 'request'
					elif flagrepr == 'SA':
						packet_state = 'reply'
					elif flagrepr == 'F':
						packet_state = 'finish'
					elif flagrepr == 'A':
						packet_state = 'ack'
					else:
						packet_state = 'other'


					packet_data = [packet.time, packet_proto, packet_state, packet_src_mac, packet_dst_mac,
					packet_src_ip, packet_dst_ip, packet_src_port, packet_dst_port, packet_payload]
					

				if packet_proto == 'udp':
					packet_state = "0"
					packet_udp_info = packet[UDP]
					packet_src_port = int(packet_udp_info.sport)
					packet_dst_port = int(packet_udp_info.dport)
					packet_payload = len(packet_udp_info.payload.original)

					packet_data = [packet.time, packet_proto, packet_state, packet_src_mac, packet_dst_mac,
					packet_src_ip, packet_dst_ip, packet_src_port, packet_dst_port, packet_payload]
				

			elif ARP in packet:

				packet_ip_layer = packet[ARP]
				packet_src_ip = packet_ip_layer.psrc
				packet_dst_ip = packet_ip_layer.pdst
				packet_src_port = 65536
				packet_dst_port = 65536
				packet_payload = "0"
				opcode = packet_ip_layer.get_field('op')
				packet_state = opcode.i2s[packet_ip_layer.op]

				if packet_state == 'who-has':
					packet_state = 'request'
				if packet_state == 'is-at':
					packet_state = 'reply'

				packet_data = [packet.time, 'arp', packet_state, packet_src_mac, packet_dst_mac,
				packet_src_ip, packet_dst_ip, packet_src_port, packet_dst_port, packet_payload]


			elif IPv6 in packet:

				# ignore ipv6 packets for now
				# packet_ip_layer = packet[IPv6]
				continue

			packet_list.append(packet_data)

		df = pd.DataFrame(packet_list, columns=data_header)

		df["protocol"] = df.apply(protocol_parse, axis=1)
		df["state"] = df.apply(state_parse, axis=1)
		df["source_ip"] = df.apply(ip_src_parse, axis=1)
		df["destination_ip"] = df.apply(ip_dst_parse, axis=1)
		df["source_mac"] = df.apply(mac_src_parse, axis=1)
		df["destination_mac"] = df.apply(mac_dst_parse, axis=1)

		# serialize with pickle (turn to bytes)
		serialized_cap = pickle.dumps(df)

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
			server.close()




