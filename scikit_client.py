#!/usr/bin/env python3

from collections import OrderedDict
from torch.utils.data import DataLoader, TensorDataset
from sklearn.model_selection import train_test_split
from sklearn import svm
from sklearn.linear_model import LogisticRegression
from sklearn import metrics
from sklearn.ensemble import RandomForestClassifier

import joblib
from joblib import parallel_backend
import warnings
import flwr as fl
import pandas as pd
import os
import sys
import numpy as np


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

	# 20 % Test set size.
	X_train, X_test, Y_train, Y_test = train_test_split(X, Y, test_size=0.2, random_state=120) 

	num_examples = {"trainset": len(X_train), "testset": len(X_test)}

	return X_train, X_test, Y_train, Y_test, num_examples


def train(model, X_train, Y_train):

	model.fit(X_train.values, Y_train.values)



def test(model, X_test, Y_test):
	
	predictions = model.predict(X_test.values)
	accuracy = metrics.accuracy_score(Y_test.values, predictions) 
	loss = 0.0 #metrics.log_loss(Y_test.values, predictions)
	print(f"Testing accuracy: { accuracy * 100.0 }% ")

	return loss, accuracy


# https://github.com/adap/flower/blob/main/examples/sklearn-logreg-mnist/utils.py
def set_initial_params(model):
	n_classes = 2
	n_features = 46  # Number of features in dataset
	model.classes_ = np.array([i for i in range(n_classes)])

	model.coef_ = np.zeros((n_classes, n_features))
	model.intercept_ = np.zeros((n_classes,))



def main():
	"""Create model, load data, define Flower client, start Flower client."""

	#model = LogisticRegression(max_iter=100_000, tol=0.0001, solver='saga')
	model = RandomForestClassifier(min_samples_leaf=20)
	set_initial_params(model)

	# Load data 
	X_train, X_test, Y_train, Y_test, num_examples = load_data(filename='aggregate_total_data')

	# Flower client
	class ClientTrainer(fl.client.NumPyClient):
		def get_parameters(self):
			# return local model parameters
			# hyperparams = inspect.signature(model.__init__)
			#return hyperparams
			#return [model.get_params()]
			return [model.coef_, model.intercept_]


		def set_parameters(self, parameters):
			# for parameter in parameters[0]:
			# 	st_param = str(parameter)
			# 	val = model.get_params()[st_param]
			# 	model.set_params(**{st_param: val})

			model.coef_ = parameters[0]
			model.intercept_ = parameters[1]
			

		def fit(self, parameters, config):

			modelPath = "./RandomForest.pkl"

			"""
			Defines the steps to train the model on the locally held dataset. 
			It also receives global model parameters and other configuration information from the server.
			"""
			try:
				self.set_parameters(parameters)
				with warnings.catch_warnings():
					warnings.simplefilter("ignore")
					train(model, X_train, Y_train)
			except:
				# save model
				joblib.dump(model, modelPath)
				print("model saved here after exception.")
				return self.get_parameters(), num_examples["trainset"], {}
			
			# save model
			joblib.dump(model, modelPath)
			

			print("model saved here")
			return self.get_parameters(), num_examples["trainset"], {}


		def evaluate(self, parameters, config):
			# evaluating the provided parameters using a locally held dataset
			self.set_parameters(parameters)
			loss, accuracy = test(model, X_test, Y_test)
			return float(loss), num_examples["testset"], {"accuracy": float(accuracy)}


	# Start client
	fl.client.start_numpy_client("127.0.0.1:8080", client=ClientTrainer())


if __name__ == "__main__":
	main()
