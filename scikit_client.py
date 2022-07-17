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

from random import *

def load_data(path=None, filename=None):
	
	if path is None:
		path = "./"
	if filename is None:
		filename = "package_result_processed"
	if not os.path.exists(path + filename + ".csv"):
		print("file does not exist")
		sys.exit(1)



	print(f'Loading dataset from : {filename}')
	#pd.options.mode.use_inf_as_na = True
	data_dataframe = pd.read_csv(path + filename + ".csv")

	print(f'Done loading.')


	# we will let 0 represent benign data
	# we will let 1 represent malicious data

	#data_dataframe.loc[data_dataframe['Label'] == 'BENIGN', 'Label'] = 0.0
	#data_dataframe.loc[data_dataframe['Label'] == 'MALICIOUS', 'Label'] = 1.0

	X = data_dataframe.iloc[:, 0:-1] # Features
	Y = data_dataframe.iloc[:, -1] # Labels
	
	# Convert all data to float type
	X = X.astype("float64")
	Y = Y.astype("float64")

	# If correlation between features A and B is a theshold value, then we can predict B using A threshold% of the time. So we can discard either or. 
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
	#X = sklearn.preprocessing.normalize(X)

	percent_split = 0.35

	print(f"Number of features without label: {len(X.columns)}")
	print(f"Size of whole dataset: {len(X)}")
	print(f"Size of test dataset: {len(X) * percent_split}")
	print(f"Size of train dataset: {len(X)  - (len(X) * percent_split)}")



	print('Splitting.')
	# 20 % Test set size.
	X_train, X_test, Y_train, Y_test = train_test_split(X, Y, test_size=percent_split, shuffle=True) 


	print('Scaling...')
	scaler = StandardScaler()
	
	X_train = pd.DataFrame(scaler.fit_transform(X_train.values), columns=X.columns)
	X_test = pd.DataFrame(scaler.transform(X_test.values), columns=X.columns)

	print('Done scaling.')

	print('Saving scaler.')
	joblib.dump(scaler, f'scaler_kn_17.pkl')
	print('Saved scaler.')

	print(f"Number of benign in test set: {Y_test.value_counts()[0.0]}")
	print(f"Number of malicious in test set: {Y_test.value_counts()[1.0]}")
	print(f"Number of benign in train set: {Y_train.value_counts()[0.0]}")
	print(f"Number of malicious in train set: {Y_train.value_counts()[1.0]}")
	print(f"-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-")

	num_examples = {"trainset": len(X_train), "testset": len(X_test)}

	return X_train, X_test, Y_train, Y_test, num_examples


def train(model, X_train, Y_train):


	print(f"Training...")

	model.fit(X_train.values, Y_train.values)

	print(f"Trained.")



def test(model, X_test, Y_test):
	
	print(f"Testing...")
	predictions = model.predict(X_test.values)
	print(f"Tested.")

	# balanced accuracy score is applied on unbalanced datasets.
	# accuracy is better for close-to-balanced sets.
	test_length = len(Y_test.values)
	loss = 0.0

	accuracy = metrics.accuracy_score(Y_test.values, predictions) 
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


# From towards data science: Feature selection / Dimensionality reduction techniques
def identify_correlated(df, threshold):
	matrix = df.corr().abs()
	mask = np.triu(np.ones_like(matrix, dtype=bool))
	reduced_matrix = matrix.mask(mask)
	to_drop = [c for c in reduced_matrix if any(reduced_matrix[c] > threshold)]
	return to_drop


# https://github.com/adap/flower/blob/main/examples/sklearn-logreg-mnist/utils.py
def set_initial_params(model):
	n_classes = 2
	n_features = 38  # Number of features in dataset
	model.classes_ = np.array([i for i in range(n_classes)])

	model.coef_ = np.zeros((n_classes, n_features))
	model.intercept_ = np.zeros((n_classes,))



def main():
	"""Create model, load data, define Flower client, start Flower client."""

	#model = LogisticRegression(max_iter=30_000, solver='lbfgs')
	#model = svm.LinearSVC(C=0.82, max_iter=1_000, tol=0.0001, dual=False)
	#model = RandomForestClassifier(n_estimators=40, max_depth=5)
	

	# Load data 
	X_train, X_test, Y_train, Y_test, num_examples = load_data(filename="./CICIDS17/aggregate_2017_cleaned_numerical_nonbalanced_balanced_drop")


	model = neighbors.KNeighborsClassifier(algorithm='brute', n_neighbors=5, metric='euclidean')

	set_initial_params(model)

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

			modelPath = "./kn_2017.pkl"

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
				print(f"model saved here after exception. {modelPath}")

				return self.get_parameters(), num_examples["trainset"], {}
			
			# save model
			joblib.dump(model, modelPath)

			print(f"model saved here: {modelPath}")
			return self.get_parameters(), num_examples["trainset"], {}


		def evaluate(self, parameters, config):
			# evaluating the provided parameters using a locally held dataset
			self.set_parameters(parameters)
			loss, accuracy = test(model, X_test, Y_test)
			return float(loss), num_examples["testset"], {"accuracy": float(accuracy)}


	# Start client
	fl.client.start_numpy_client("127.0.0.1:8080", client=ClientTrainer())
	#train(model, X_train, Y_train)
	#test(model, X_test, Y_test)

	# # get importance
	# importance = model.feature_importances_
	# # # summarize feature importance
	# importances = [(X_train.columns[i], v) for i,v in enumerate(importance)]
	# importances.sort(key=lambda x: x[1])
	# print("importances...")
	
	# for i,v in importances:
	# 	print(f"Feature: {i}, Importance score: {v}")




if __name__ == "__main__":
	main()
