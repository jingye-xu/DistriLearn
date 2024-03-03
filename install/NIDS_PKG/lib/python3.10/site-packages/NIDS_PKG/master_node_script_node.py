#!/usr/bin/env python3

"""
Master runs bert model :)
"""


import os
import rclpy
import socket
import datetime
import hashlib
import time
import base64
import pickle

import pandas as pd
import numpy as np

from rclpy.node import Node
from std_msgs.msg import String
from uuid import getnode as get_mac

from NIDS_PKG.kappa_coeff import *
from NIDS_PKG.blackListAPI import *
from setfit import SetFitModel

import lancedb
import pyarrow as pa

# This is to accomadate packages on the home directory (i.e. the bert mdl)
sys.path.append(f'{os.environ["HOME"]}/bertbased_ids')
from BertFlowLM import BertFlowLM


class SetFitWrapper:

	def __init__(self, device='cpu', use_dh=True):
		self.setfit = SetFitModel.from_pretrained(f"{os.environ['HOME']}/bertbased_ids/setfit_mobile_siamese", device=device, use_differentiable_head=use_dh)

	def obtain_embedding(self, flow_entry):
		return self.setfit.encode(flow_entry)

	def infer(self, flow_entry):
		pred = self.setfit.predict(flow_entry)
		confidence = self.setfit.predict_proba(flow_entry)
		return pred.item(), confidence.data[np.argmax(confidence)].item()


class BlackListComposition:

	def __init__(self, ma, attack_type, model_name, model_type, ap_hash, flow):

		self.mac_addr = ma
		#self.mac_id = int(f'{ma[0:2]}{ma[3:5]}{ma[6:8]}{ma[9:11]}{ma[12:14]}{ma[15:17]}',16)
		self.attack_type = attack_type
		self.model_name = model_name
		self.model_type = model_type
		self.flow = flow
		self.domain_id = os.environ['DOMAIN_ID']
		self.ap_hash = ap_hash
		self.kappa = 0.0
		self.ban_mac = False

class MasterNode(Node):

	def __init__(self):
		super().__init__('master_node')

		timer_period = 0.1  # seconds

		

		self.BENIGN_THRESHOLD = 150
		self.MALICIOUS_THRESHOLD = 150
		self.MAX_BUFFER_SIZE = 100

		self.evidence_buffer = {}

		# BL format: macid_integer: (mac_addr, {ap_hash: [attack_type_0_cnt, attack_type_1_cnt]})
		self.internal_blacklist = {}

		self.blacklist_obj =  None
		self.defaultMsg = String()
		self.domain_id = os.environ['DOMAIN_ID']



		db = lancedb.connect(f"{os.environ['HOME']}/flow_db")

		# create a table for the embeddings
		schema = pa.schema(
		[ # 985 and 512 or 768
			pa.field("vector", pa.list_(pa.float64(), list_size=512)),
			pa.field("flow", pa.string()),
			pa.field("confidence", pa.float64()),
			pa.field("pred", pa.int32()),
			pa.field("inference_sum", pa.int32()),
			pa.field("total_inferences", pa.int32()),
		])


		# self.model = BertFlowLM(hf_path=f'{os.environ["HOME"]}/bertbased_ids/BERT_FlowLM_PT', hf_path_t=f'bert-base-uncased')
		self.model = SetFitWrapper()

		self.tbl = None
		try:
			# Create empty table using defined schema.
			self.tbl = db.create_table("flow_table", schema=schema)

			# Initialize database with data from training. Create embeddings using model with confidences' metadata too. 
			data = pd.read_csv(f'{os.environ["HOME"]}/NF-UNSW-NB15-v2.csvLabelWiseSentenceClass.csv',low_memory=False)
			data = data.sample(frac=1).reset_index(drop=True)
			print(f'Initializing database... ({len(data)} Entries)')
			for index, row in data.iterrows():
				print(f'({index + 1} / {len(data)})', end='\r')
				flow = row['Flow']
				prediction = row['Label']
				confidence = 1.0 # because it is ground truth, it has highest weight (i.e., 100%).
				#embedding = self.model.obtain_embedding_for(flow)
				embedding = self.model.obtain_embedding(flow)
				entry = [{"vector":embedding, "flow": flow, "confidence" : confidence, "pred":int(prediction), "inference_sum": int(prediction), "total_inferences": 1}]
				self.tbl.add(entry)
			print('Done initializing database')
		except Exception as e:
			print(e)
			print('Loading database...')
			# Already exists, so just move on.
			self.tbl = db.open_table("flow_table")
			print('Done loading database.')

		self.master_mac = get_mac()
		self.master_hash = self.hash_value('master' + str(datetime.datetime.now()) + str(self.master_mac))
		self.init_time = datetime.datetime.now()

		# Master node publishes to master node dispatch topic
		self.master_dispatch_publisher = self.create_publisher(String, 'master_node_dispatch', 10)
		self.timer = self.create_timer(timer_period, self.master_dispatch_callback)

		# Master node subcribes to IDS service topic
		self.ids_service_subscriber = self.create_subscription(String, 'ids_service', self.ids_service_listener, 10)

		self.OUTGOING_MSG_QUEUE_SIZE = 10 # Max queue size for outgoing messages to subsribers
		self.INCOMING_MSG_QUEUE_SIZE = 10 # Max queue size for incoming messages to subscribers/from publishers

		# Blacklist subsystem (TODO: Place in own node) -> everyone in the complex/enterprise will publish and subscribe to it. 
		self.blacklist_publisher = self.create_publisher(String, 'blacklist_subsytem', self.OUTGOING_MSG_QUEUE_SIZE)
		_ = self.create_timer(timer_period, self.blacklist_pub_callback)

		self.blacklist_subscriber = self.create_subscription(String, 'blacklist_subsytem', self.blacklist_sub_callback, self.INCOMING_MSG_QUEUE_SIZE)

		



	def master_dispatch_callback(self):
		
		mast_hash = String()
		mast_hash.data = self.master_hash + '$' + str(self.init_time)
		self.master_dispatch_publisher.publish(mast_hash)

	def sig(self, x):
		return 1/(1 + np.exp(-x))


	def ids_service_listener(self, inf_report):

		# format: master hash $ mac $ type (0 or 1) $ count $ BERT_sentences
		inf_tokens = inf_report.data.split('$')

		if inf_tokens[0] != self.master_hash:
			print('Placed as backup.')
			return

		inf_mac = inf_tokens[1]
		inf_encoding = int(inf_tokens[2]) # type
		inf_cnt = float(inf_tokens[3]) # confidence.
		print(inf_cnt)
		# Select top k from the database
		# Make sure to iterate after index 4 because that's ALL the flows. 
		for flow_s in inf_tokens[4:]:
			if flow_s == '$' or flow_s == '':
				continue
			
			# Predict on flow sentence and get confidence.
			# pred, confidence = self.model.infer(flow_s)
			pred, confidence = self.model.infer(flow_s)

			# This isn't inflating the benign counts in any way. This allows us to add strength to malicious ONLY when the probability is high enough to say so.
			if pred == 1 and confidence <= 0.55:
				pred = 0
				confidence = 0.5
			
			# confidence = float(confidence.data[0])
			# Obtain embedding for the flow sentence
			# embedding = self.model.obtain_embedding_for(flow_s)
			embedding = self.model.obtain_embedding(flow_s)

			search_results = self.tbl.search(embedding).metric("cosine").limit(10).to_pandas()
			
			
			# Now we have k similar flows with the values "vector" "flow" "confidence" "pred" "inference_sum" "total_inferences"
			# The confidence updates via the inference sum, and its total inferences. 
			search_results['total_inferences'] = search_results['total_inferences'].apply(lambda x : x + 1)
			
			# Apply a weighted sum to see which values actually have a higher weight. The highest weight value is the decision.
			sums = [0, 0] # mapped directly to 0 or 1.
			for _, row in search_results.iterrows():
				# For each flow in the k that we pulled out, update its inference sum and confidence with the new values.
				row['inference_sum'] += pred
				row['confidence'] = self.sig((row['inference_sum'] / row['total_inferences']) * row['confidence'])

				entry = [{"vector": row['vector'], "flow": row['flow'], "confidence" : row['confidence'], "pred": row['pred'], "inference_sum": row['inference_sum'], "total_inferences": row['total_inferences']}]
				
				# Now, update the table with this new flow metadata (flows are usually always unique). We can turn the dataframe back into its original state of a dictionary.
				self.tbl.update(where=f"flow = \"{row['flow']}\"", values={'inference_sum' : int(row['inference_sum']), 'confidence' : float(row['confidence']), 'total_inferences' : int(row['total_inferences'])})
				
				sums[row['pred']] += row['confidence']


			print(search_results)
			# # Once we iterate through everything, now we need to take all values under consideration. 
			# # Use all the confidences we have for the nn, the BERT model, and the k flows to make a determination for this source address. 
			# # So make the decision and report.
			# # Since each prediction is binary, and the confidences are technically weights, we can then use that as a pseudo neural network input; that is, we can use a sigmoid function.
			# 	# Sigmoid : Take in a vector of values, along with weights, sum it and produce a value between 0 and 1.
			# 	# 1/(1 + e^x); to use it as a neural activation it is sum(weight * input) + bias
			# # This is initialized with BERT's weights (left) + autoencoder weights (right)
			# cumulative_sum = (pred * confidence) + (inf_encoding * inf_cnt)
			# # Even though we can do this quicker and more effectively, for correctness, I will just use a loop.
			# for _, row in search_results.iterrows():
			# 	cumulative_sum += (row['confidence'] * row['pred'])
			# # Apply sigmoid after weighted sum calculation like the NN.
			# cumulative_sum = self.sig(cumulative_sum)


			
			# Since we are using sigmoid, we can use a threshold to say whether it is 0 or 1.
			# I will just maximize what I can and say anything above 0.6 (60%) is malicious, and anything below 0.6 is benign (<= 50%)
			gmtime = time.gmtime()
			dt_string = "%s:%s:%s" % (gmtime.tm_hour, gmtime.tm_min, gmtime.tm_sec)
			report = 0
			cumulative_sum = np.argmax(sums)
			if cumulative_sum == 0:
				report = 0
				print(f'\033[32;1m[{dt_string}]\033[0m {inf_mac} - \033[32;1mNormal.\033[0m')
			if cumulative_sum == 1:
				report = 1
				print(f'\033[31;1m[{dt_string}]\033[0m {inf_mac} - \033[31;1mSuspicious.\033[0m')

			# Insert data back into the database 
			entry = [{"vector": embedding, "flow": flow_s, "confidence" : confidence, "pred":report, "inference_sum": report, "total_inferences": 1}]
			self.tbl.add(entry)
	




	def hash_value(self, val):
		hasher = hashlib.sha256()
		hasher.update(val.encode('UTF-8'))
		return hasher.hexdigest()


	# This subsystem is subscribed to by ALL masters, and ALL access points for preemptive decision making. 
	def blacklist_sub_callback(self, data):

		topic_encoded_b64_str = data.data
		topic_decoded_b64_bytes = bytes(topic_encoded_b64_str, 'UTF-8') 
		topic_obj_decoded = base64.b64decode(topic_decoded_b64_bytes)
		topic_obj = pickle.loads(topic_obj_decoded)

		# On receiving, we use Domain ID to fill internal blacklist. Then, we check agreement (for malicious/non-benign), and if it's
		# high agreement of malicious, we blacklist it. LATER: Use some metric to perform online learning based on flow info for the 
		# incoming flow once we decide to blacklist. 

		# Agreement is an INTERNAL DOMAIN PROCESS: Rows - MAC addresses (i.e., subjects); columns - categories (i.e, attack type [1+] or non-malicious [0]); cells - agreements; 
		kap = 0.0
		if self.domain_id == topic_obj.domain_id:
			# BL format: {mac_addr : {ap_hash: [attack_type_0_cnt, attack_type_1_cnt]}
			# AP hash will allow us to count votes per access point and not double-, triple-, or n-count
			if topic_obj.mac_addr not in self.internal_blacklist:
				self.internal_blacklist[topic_obj.mac_addr] = np.zeros((1,2))

			table = self.internal_blacklist[topic_obj.mac_addr]
			if topic_obj.attack_type == 0:
				table[0][0] += 1
			else:
				table[0][1] += 1 

			# Rule for memory constraint and runtime use: For real-time, we will keep a singular table of 1x2, in which the cells represent benign/mal agreement
			kap = fleiss_kappa(self.internal_blacklist[topic_obj.mac_addr], method='randolph')
			
			if np.abs(kap) >= 0.50:
				# check to see which is greater, benign or malicious;
				if table[0][1] > table[0][0]:
					# Ban it for a time if it's not in the list already. (aka if in list do nothing.)
					# If malicious is greater, set flag to ban the mac
					topic_obj.ban_mac = True
					blockHandler(src_mac=topic_obj.mac_addr)

		if self.domain_id != topic_obj.domain_id and topic_obj.ban_mac == True:
			# simply check to see if the object has a ban flag. If so, ban it for the same time. If it is already in the list, however, do nothing. 
			blockHandler(src_mac=topic_obj.mac_addr)



	def blacklist_pub_callback(self):

		# If the determination is that a malicious node is found in buffers: Publishing MAC of adversary + Attack Type + Model Type + Flow Info
		# Meaning if blacklist object is not none, we transmit.

		if self.blacklist_obj is None:
			return


		# Check to see if the object is in the banlist. If so, set ban flag.
		
		topic_obj = pickle.dumps(self.blacklist_obj)
		topic_obj_encoded = base64.b64encode(topic_obj)
		topic_obj_str = topic_obj_encoded.decode('UTF-8')

		self.defaultMsg.data = topic_obj_str
		self.blacklist_publisher.publish(self.defaultMsg)





def main(args=None):
	rclpy.init(args=args)

	if 'DOMAIN_ID' not in os.environ:
		print('Domain ID not set. Do so using \'export DOMAIN_ID=<domain>\'')
		sys.exit(1)
	
	master_node = MasterNode()

	rclpy.spin(master_node)
	master_node.destroy_node()
	rclpy.shutdown()
