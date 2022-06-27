#!/usr/bin/env python3 

from collections import OrderedDict
import warnings

import flwr as fl
import torch
import torch.nn as nn
import torch.nn.functional as F
import torchvision.transforms as transforms
from torch.utils.data import DataLoader, TensorDataset
import pandas as pd
import os
import sys

transform = transforms.Compose(
	[transforms.Normalize((0.5, 0.5, 0.5), (0.5, 0.5, 0.5))])

warnings.filterwarnings("ignore", category=UserWarning)
DEVICE = torch.device("cuda:0" if torch.cuda.is_available() else "cpu")

NUM_INPUT = 46
batch_size = 3

# #############################################################################
# 1. PyTorch pipeline: model/train/test/dataloader
# #############################################################################


# Model 3-layer Linear reg NN 
class Net(nn.Module):
	def __init__(self) -> None:
		super(Net, self).__init__()
		self.fc1 = nn.Linear(in_features=NUM_INPUT, out_features=30)
		self.fc2 = nn.Linear(in_features=30, out_features=20)
		self.fc3 = nn.Linear(in_features=20, out_features=10)
		self.fc4 = nn.Linear(in_features=10, out_features=1)

	def forward(self, x: torch.Tensor) -> torch.Tensor:
		output = self.fc1(x)
		output = F.tanh(output)
		output = self.fc2(output)
		output = F.tanh(output)
		output = self.fc3(output)
		output = F.tanh(output)
		output = self.fc4(output)
		output = F.sigmoid(output)

		return output


# https://github.com/KelvinHong/svm-pytorch/blob/main/model.py
class SVM(nn.Module):
    def __init__(self):
        super(SVM, self).__init__()
        self.input_dim = NUM_INPUT
        self.linear = nn.Linear(NUM_INPUT, 1)
        
    def forward(self, input):
        # Expect input to be shape (N, self.input_dim)
        output = self.linear(input) # Shape (N, 1)
        output = output.flatten() # Shape (N)
        return output 

def HingeLoss(pred, truth):
    loss_tensor = nn.ReLU()(1-pred*truth)
    return torch.mean(loss_tensor)

###########################################


def train(net, trainloader, epochs):
	"""Train the network on the training set."""
	loss_fn = torch.nn.BCELoss()
	optimizer = torch.optim.Adam(net.parameters(), lr=0.00001, weight_decay=0.002)
	net.train()
	
	for _ in range(epochs):
		
		for images, labels in trainloader:
			running_loss = 0.0
			images, labels = images.to(DEVICE), labels.to(DEVICE)
			optimizer.zero_grad()

			predicted = net(images)
			loss = loss_fn(predicted, labels)
			loss.backward()
			optimizer.step()
			torch.nn.utils.clip_grad_norm_(net.parameters(),  max_norm=10, norm_type=2.0)

			running_loss += loss.item()

			if running_loss <= 0.01:
				break

			print(f'Running Loss: {running_loss}', end='\r')


def test(net, testloader):
	"""Validate the network on the entire test set."""
	loss_fn = torch.nn.BCELoss()
	correct, total, loss = 0, 0, 0.0
	net.eval()
	with torch.no_grad():
		for images, labels in testloader:
			images, labels = images.to(DEVICE), labels.to(DEVICE)
			outputs = net(images)
			loss += loss_fn(outputs, labels).item()
			_, predicted = torch.max(outputs.data, 1)
			total += labels.size(0)
			correct += (predicted == labels).sum().item()
	loss /= len(testloader.dataset)
	accuracy = (correct // batch_size) / total
	print(f'Testing accuracy: {accuracy * 100}%')

	return loss, accuracy


def load_data(path=None, filename=None):
	if path is None:
		path = "./"
	if filename is None:
		filename = "package_result_processed"
	if not os.path.exists(path + filename + ".csv"):
		print("file does not exist")
		sys.exit(1)

	pd.options.mode.use_inf_as_na = True
	data_dataframe = pd.read_csv(path + filename + ".csv")
	data_dataframe.dropna(inplace=True)

	# we will let 0 represent benign data
	# we will let 1 represent malicious data

	data_dataframe.loc[data_dataframe['Label'] == 'BENIGN', 'Label'] = 0.0
	data_dataframe.loc[data_dataframe['Label'] == 'MALICIOUS', 'Label'] = 1.0

	X = data_dataframe.iloc[:, 0:-1] # Features
	Y = data_dataframe.iloc[:, -1] # Labels
	
	# Convert all data to float type
	X = X.astype("float32")
	Y = Y.astype("float32")

	# Convert data to tensors
	X = torch.tensor(X.values, dtype=torch.float)
	Y = torch.tensor(Y.values, dtype=torch.float)

	X = torch.FloatTensor(X)
	Y = torch.unsqueeze(torch.FloatTensor(Y), dim=1)

	X = torch.nn.functional.normalize(X)

	# split to train and test subset
	train_size = int(0.8 * len(Y))
	test_size = len(Y) - train_size

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
	trainloader, testloader, num_examples = load_data(filename='aggregate_total_data')

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
			train(net, trainloader, epochs=1)
			
			# save model
			modelPath = "./svm.pth"
			torch.save(net.state_dict(), modelPath)

			print("model saved here")
			return self.get_parameters(), num_examples["trainset"], {}

		def evaluate(self, parameters, config):
			self.set_parameters(parameters)
			loss, accuracy = test(net, testloader)
			return float(loss), num_examples["testset"], {"accuracy": float(accuracy)}

	# Start client
	fl.client.start_numpy_client("127.0.0.1:8080", client=ClientTrainer())


if __name__ == "__main__":
	main()
