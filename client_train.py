#!/usr/bin/env python3
import time
from collections import OrderedDict
import warnings

import flwr as fl
import torch
import torch.nn as nn
import torch.nn.functional as F
import torchvision.transforms as transforms

from sklearn.metrics import confusion_matrix
from torch.utils.data import DataLoader, TensorDataset
from sklearn.preprocessing import StandardScaler, MinMaxScaler
from sklearn import metrics

import sklearn

import joblib
from joblib import parallel_backend

import pandas as pd
import os
import sys


warnings.filterwarnings("ignore", category=UserWarning)
DEVICE = torch.device("cuda:0" if torch.cuda.is_available() else "cpu")

# was 46 features.
NUM_INPUT = 38
batch_size = 1

# #############################################################################
# 1. PyTorch pipeline: model/train/test/dataloader
# #############################################################################


# Model 3-layer Linear reg NN 
class Net(nn.Module):
	def __init__(self) -> None:
		super(Net, self).__init__()
		self.fc1 = nn.Linear(in_features=NUM_INPUT, out_features=30)
		self.fc2 = nn.Linear(in_features=30, out_features=20)
		self.fc3 = nn.Linear(in_features=20, out_features=1)

	def forward(self, x: torch.Tensor) -> torch.Tensor:
		output = self.fc1(x)
		output = torch.relu(output)
		output = self.fc2(output)
		output = torch.relu(output)
		output = self.fc3(output)
		output = torch.sigmoid(output)

		return output


# Train/test loops adapted from: credit - https://github.com/AnupamMicrosoft/PyTorch-Classification/blob/master/LogisticsRegressionPyTorch.py

def train(net, train_loader, epochs):
	"""Train the network on the training set."""
	loss_fn = torch.nn.BCELoss()
	optimizer = torch.optim.SGD(net.parameters(), lr=0.0001, weight_decay=0.03) 
	net.train()

	for epoch in range(epochs):
		avg_loss_epoch = 0
		batch_loss = 0
		total_batches = 0

		for i, (features, labels) in enumerate(train_loader):
			outputs = net(features)               
			loss = loss_fn(outputs, labels)    
			
			# Backward and optimize
			optimizer.zero_grad()
			loss.backward()
			optimizer.step()   

			total_batches += 1     
			batch_loss += loss.item()

		avg_loss_epoch = batch_loss/total_batches
		print ('Epoch [{}/{}], Average Loss: for epoch [{}, {:.4f}]'
					   .format(epoch+1, epochs, epoch+1, avg_loss_epoch ))
	


def test(net, test_loader):

	y_pred = []
	y_true = []

	correct = 0.
	total = 0.
	for features, labels in test_loader:

		outputs_test = net(features)

		y_true.extend(labels.data.cpu().numpy())

		predicted = outputs_test.data >= 0.5 

		y_pred.extend(predicted.detach().numpy())
	 
		total += labels.size(0) 
		
		correct += (predicted.view(-1).long() == labels).sum()


		
	accuracy = (100 * (correct.float() / total))
	tn, fp, fn, tp = metrics.confusion_matrix(y_true, y_pred).ravel()
	f1_score = metrics.f1_score(y_true, y_pred)
	precision = metrics.precision_score(y_true, y_pred)
	recall = metrics.recall_score(y_true, y_pred)


	test_length = len(test_loader)
	print('Accuracy of the model on the samples: %f %%' % accuracy)
	print(f"Number of total test samples {total}")
	print(f"Numbers of correctly predicted test samples {correct} out of {len(test_loader)}")
	print(f"Calculated ({correct} / {total}) * 100.0 = {accuracy}")
	print(f"F1 score: {f1_score}")
	print(f"Precision - for malicious: {precision * 100.0}%")
	print(f"Recall - for malicious: {recall * 100.0}%")
	print(f"-=-=-=-=-=-=-=-=-=-=-")
	print(f"True positives/malicious: {tp} out of {tp + fp + fn + tn} ({ (tp / (tp + fp + fn + tn)) * 100.0 }%)")
	print(f"False positives/malicious: {fp} out of {tp + fp + fn + tn} ({ (fp / (tp + fp + fn + tn)) * 100.0 }%)")
	print(f"True negatives/benign: {tn} out of {tp + fp + fn + tn} ({ (tn / (tp + fp + fn + tn)) * 100.0 }%)")
	print(f"False negatives/benign: {fn} out of {tp + fp + fn + tn} ({ (fn / (tp + fp + fn + tn)) * 100.0 }%)\n")

	return 0.0, accuracy


def load_data(path=None, filename=None):
	if path is None:
		path = "./"
	if filename is None:
		filename = "package_result_processed"
	if not os.path.exists(path + filename + ".csv"):
		print("File does not exist")
		sys.exit(1)

	print(f'Loading dataset from : {filename}')
	#pd.options.mode.use_inf_as_na = True
	data_dataframe = pd.read_csv(path + filename + ".csv")
	#data_dataframe.dropna(inplace=True)
	data_dataframe = data_dataframe.sample(frac = 1)

	print('Done loading.')

	# we will let 0 represent benign data
	# we will let 1 represent malicious data

	#data_dataframe.loc[data_dataframe['Label'] == 'BENIGN', 'Label'] = 0.0
	#data_dataframe.loc[data_dataframe['Label'] == 'MALICIOUS', 'Label'] = 1.0

	X = data_dataframe.iloc[:, 0:-1] # Features
	Y = data_dataframe.iloc[:, -1] # Labels
	
	# Convert all data to float type
	X = X.astype("float32")
	Y = Y.astype("float32")

	cols = ['Fwd PSH Flags',
'Bwd PSH Flags',
'Bwd URG Flags',
'SYN Flag Count',
'Fwd Avg Bytes/Bulk',
'Fwd Avg Packets/Bulk',
'Fwd Avg Bulk Rate',
'Bwd Avg Bytes/Bulk',
'Bwd Avg Packets/Bulk',
'Bwd Avg Bulk Rate',
'URG Flag Count',
'CWE Flag Count',
'Fwd URG Flags',
'FIN Flag Count',
'Down/Up Ratio',
'Active Min',
'ECE Flag Count',
'Idle Mean',
'act_data_pkt_fwd',
'Flow IAT Std',
'Idle Std',
'Active Mean',
'Idle Max',
'Active Std',
'ACK Flag Count',
'PSH Flag Count',
'Avg Bwd Segment Size',
'Idle Min',
'Active Max',
'Subflow Fwd Bytes',
'Subflow Bwd Bytes',
'Avg Fwd Segment Size',
'Subflow Bwd Packets',
'Subflow Fwd Packets',
'Bwd Header Length',
'Fwd Header Length',
'min_seg_size_forward',
'Init_Win_bytes_backward',
'Init_Win_bytes_forward']

	
	X.drop(columns=cols, axis=1, inplace=True)

	scaler = StandardScaler()
	X = scaler.fit_transform(X)

	print('Saving scaler.')
	joblib.dump(scaler, f'scaler_nn_17.pkl')
	print('Saved scaler.')

	# Convert data to tensors
	X = torch.tensor(X, dtype=torch.float)
	Y = torch.tensor(Y, dtype=torch.float)

	X = torch.FloatTensor(X)
	Y = torch.unsqueeze(torch.FloatTensor(Y), dim=1)


	# split to train and test subset
	train_size = int(0.75 * len(Y))
	test_size = len(Y) - train_size

	print('Splitting.')
	Y_train, Y_test = torch.split(Y, [train_size, test_size])
	X_train, X_test = torch.split(X, [train_size, test_size])

	train_dataset = TensorDataset(X_train, Y_train)
	test_Dataset = TensorDataset(X_test, Y_test)

	trainloader = DataLoader(train_dataset, batch_size=batch_size, shuffle=True)
	testloader = DataLoader(test_Dataset, batch_size=batch_size, shuffle=False)

	num_examples = {"trainset": len(train_dataset), "testset": len(test_Dataset)}
	return trainloader, testloader, num_examples


# #############################################################################
# 2. Federation of the pipeline with Flower
# #############################################################################


def main():
	"""Create model, load data, define Flower client, start Flower client."""

	# Load model
	# net = Net().to(DEVICE)
	net = Net().to(DEVICE)

	# Load data 
	trainloader, testloader, num_examples = load_data(filename='17_18_merged_no_dup_1')

	# Flower client
	class ClientTrainer(fl.client.NumPyClient):
		def get_parameters(self):
			return [val.cpu().numpy() for _, val in net.state_dict().items()]

		def set_parameters(self, parameters):
			params_dict = zip(net.state_dict().keys(), parameters)
			state_dict = OrderedDict({k: torch.tensor(v) for k, v in params_dict})
			net.load_state_dict(state_dict, strict=True)

		def fit(self, parameters, config):
			self.set_parameters(parameters)

			train_s = time.time()
			train(net, trainloader, epochs=1)
			train_e = time.time()
			print(f"Train duration time of this round is {train_e - train_s}")

			# save model
			modelPath = "./simple_nn_17.pth"
			torch.save(net.state_dict(), modelPath)

			print(f"Model saved here {modelPath}")
			return self.get_parameters(), num_examples["trainset"], {}

		def evaluate(self, parameters, config):
			self.set_parameters(parameters)

			test_s = time.time()
			loss, accuracy = test(net, testloader)
			test_e = time.time()
			print(f"Test duration time of this round is {test_e - test_s}\n\n")

			return float(loss), num_examples["testset"], {"accuracy": float(accuracy)}

	# Start client
	fl.client.start_numpy_client("127.0.0.1:8080", client=ClientTrainer())


if __name__ == "__main__":
	main()
