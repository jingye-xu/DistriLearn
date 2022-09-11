# DistriLearn
This repository is used to store scripts, tutorial, data, and any information about the distributed learning project.
![Topo](Network.svg)


# Models

All models used in this project are located in the ModelPack subdirectory. K-Neighbors is not included in this repo since they are all so large. 

Each model is organized based off of the dataset used to train it. 
 * CIC-IDS-2017: /ModelPack/clean_17_models/
 * CSE-CIC-IDS 2018: /ModelPack/clean_18_models/
 * 2018 + 2017: /ModelPack/17_18_models/

Each model is saved as a pickle (except NN which is saved as a \*.pth). Furthermore, we include the scaler used for each model when loaded on deployment, prefixed by the name "scaler", also saved as a pickle file. 

To load these models into the cluster, the following variables should be changed in server_dist.py:

```python
MODEL_TYPE = 0 

PATH_PREF = "./ModelPack/17_18_models/NN"

SCIKIT_MODEL_PATH = f"{PATH_PREF}/kn_17_18.pkl"
SCALER_PATH = f"{PATH_PREF}/scaler_nn_1718.pkl"
PYTORCH_MODEL_PATH = f"{PATH_PREF}/simple_nn_1718.pth"

```

* MODEL_TYPE is 0 for Sklearn models, and 1 for PyTorch models, based on the strategy pattern to load them.
* PATH_REF is the model prefix path as shown in the example.
* SCIKIT_MODEL_PATH is the suffix of the path for the model as shown in the example.
* SCALER_PATH is the suffix scaler name for the model as shown in the example.
* PYTORCH_MODEL_PATH is the same as SCIKIT_MODEL_PATH, except for PyTorch.


NOTE: The directory of the models, or wherever the models are, should be in the same directory as the server_dist script.


# Cluster Instructions

Dask enables plug-and-play functionality. Each of the nodes in the cluster must have the following packages installed:
```
numpy 
pytorch
pandas
sklearn
dask
joblib
scapy
nfstream
```
To launch the cluster, you must use the following command on the coordinating machine:
```
dask-scheduler
```

For each process or additional compute node, use the following command:
```
dask-worker tcp://<scheduler-ip>:<scheduler-port>
```

Finally, to launch the IDS launch the server_dist.py script on the coordinating machine (i.e., the scheduler).

TODO: Add known issues

# DISCLAIMER

This work and the accompanying NIDS is a proof-of-concept for research purposes only, and should be treated as such. 
