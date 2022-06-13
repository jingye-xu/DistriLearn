#!/usr/bin/env python3

import os
import sys
import pandas as pd

pd.options.mode.use_inf_as_na = True

files = os.listdir()
files = list(filter(lambda x : x.endswith('.csv') and not x.startswith('aggregate'), files))

data = pd.read_csv(files[0])

for file in files[1:]:
	sub_data = pd.read_csv(file)
	data = pd.concat([data, sub_data], ignore_index=True)

data.loc[data[' Label'] != 'BENIGN', ' Label'] = 'MALICIOUS'
cols = list(map(lambda x : x.lstrip('\t'), data.columns))
cols = list(map(lambda x : x.lstrip(' '), cols))
cols = list(map(lambda x : x.rstrip('\t'), cols))
cols = list(map(lambda x : x.rstrip(' '), cols))

cols_drops = ['Down/Up Ratio', 'Average Packet Size', 'Avg Fwd Segment Size', 'Avg Bwd Segment Size', 'Fwd Header Length', 'Fwd Avg Bytes/Bulk', 'Fwd Avg Packets/Bulk', 'Fwd Avg Bulk Rate', 'Bwd Avg Bytes/Bulk', 'Bwd Avg Packets/Bulk', 'Bwd Avg Bulk Rate', 'Subflow Fwd Packets', 'Subflow Fwd Bytes', 'Subflow Bwd Packets', 'Subflow Bwd Bytes', 'Init_Win_bytes_forward', 'Init_Win_bytes_backward', 'act_data_pkt_fwd', 'min_seg_size_forward', 'Active Mean', 'Active Std', 'Fwd IAT Total', 'Active Max', 'Active Min', 'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min', 'Bwd IAT Total', 'Fwd Header Length', 'Bwd Header Length', 'Packet Length Variance']

for name in cols_drops:
	i = 0
	while i < len(cols):
		if cols[i].find(name) != -1:
			cols[i] = name
		i += 1


data.columns = cols


data.dropna(inplace=True)

data.drop(cols_drops, axis=1, inplace=True)
data.to_csv('aggregate_total_data.csv', index=False)
