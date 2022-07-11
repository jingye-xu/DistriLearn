#!/usr/bin/env python3

from collections import OrderedDict
from torch.utils.data import DataLoader, TensorDataset
from sklearn.model_selection import train_test_split
from sklearn import svm
from sklearn.linear_model import LogisticRegression
from sklearn import metrics
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler, MinMaxScaler
from sklearn import neighbors

import sklearn

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

	#X = sklearn.preprocessing.normalize(X)

	percent_split = 0.25

	print(f"Size of whole dataset: {len(X)}")
	print(f"Size of test dataset: {len(X) * percent_split}")
	print(f"Size of train dataset: {len(X)  - (len(X) * percent_split)}")

	# 20 % Test set size.
	X_train, X_test, Y_train, Y_test = train_test_split(X, Y, test_size=percent_split, shuffle=True) 

	num_examples = {"trainset": len(X_train), "testset": len(X_test)}

	return X_train, X_test, Y_train, Y_test, num_examples


def train(model, X_train, Y_train):

	model.fit(X_train.values, Y_train.values)



def test(model, X_test, Y_test):
	
	predictions = model.predict(X_test.values)

	# balanced accuracy score is applied on unbalanced datasets.
	# accuracy is better for close-to-balanced sets.
	test_length = len(Y_test.values)
	loss = 0.0

	accuracy = metrics.balanced_accuracy_score(Y_test.values, predictions) 
	f1_score = metrics.f1_score(Y_test.values, predictions)
	precision = metrics.precision_score(Y_test.values, predictions)
	recall = metrics.recall_score(Y_test.values, predictions)

	tn, fp, fn, tp = metrics.confusion_matrix(Y_test.values, predictions).ravel()

	print(f"Number of test samples: {test_length}")
	print(f"Testing accuracy: { accuracy * 100.0 }% ")
	print(f"F1 score: {f1_score}")
	print(f"Precision - for malicious: {precision * 100.0}%")
	print(f"Recall - for malicious: {recall * 100.0}%")
	print(f"-=-=-=-=-=-=-=-=-=-=-")
	print(f"True positives/malicious: {tp} out of {tp + fp + fn + tn} ({ (tp / test_length) * 100.0 }%)")
	print(f"False positives/malicious: {fp} out of {tp + fp + fn + tn} ({ (fp / test_length) * 100.0 }%)")
	print(f"True negatives/benign: {tn} out of {tp + fp + fn + tn} ({ (tn / test_length) * 100.0 }%)")
	print(f"False negatives/benign: {fn} out of {tp + fp + fn + tn} ({ (fn / test_length) * 100.0 }%)")
	print()


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

	#model = LogisticRegression(max_iter=550_000, solver='lbfgs', class_weight='balanced', C=0.28)
	#model = svm.LinearSVC(class_weight='balanced', C=0.52, max_iter=940, tol=0.0008)
	#model = RandomForestClassifier(n_estimators=40, max_depth=5, class_weight='balanced')
	model = neighbors.KNeighborsClassifier(algorithm='kd_tree')

	set_initial_params(model)

	# Load data 
	X_train, X_test, Y_train, Y_test, num_examples = load_data(filename='aggregate_total_data_balanced_drop')

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

			modelPath = "./KNeighbors.pkl"

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
				print("fmodel saved here after exception. {modelPath}")

				return self.get_parameters(), num_examples["trainset"], {}
			
			# save model
			joblib.dump(model, modelPath)
			
			# # get importance
			# importance = model.feature_importances_
			# # summarize feature importance
			# for i,v in enumerate(importance):
			# 	print('Feature: %0d %s, Score: %.5f' % (i, X_train.columns[i], v))
					

			print(f"model saved here: {modelPath}")
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
