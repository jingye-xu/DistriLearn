import pandas as pd
import numpy as np
import os
import sys


def data_balance_dropping(path=None, filename=None, label_name=None, save=False):
    """
    this function is used to balance dataset using dropping
    :param path: orginal file path
    :param filename: original file prefix - without suffix
    :param label_name: specifiy which header is used to balance data
    :param save: boolean, Ture: save balanced data and return it, False: only return
    :return: dataframe type dataset
    """
    # default value
    if path is None:
        path = "./"
    if filename is None:
        filename = "package_result_processed"
    if label_name is None:
        label_name = "Label"

    # file existing check
    if not os.path.exists(path + filename + ".csv"):
        print("file does not exist")
        sys.exit(1)

    data_original = pd.read_csv(path + filename + ".csv")

    # obtain data distribution
    value_counts = data_original[label_name].value_counts()

    print("before balancing data")
    print(value_counts)
    i = np.where(value_counts.values == min(value_counts.values))[0][0]
    print(f"index of minimal count values is: {i}")

    indices = value_counts.index

    for j, k in enumerate(value_counts.values):

        # filter dataset that only contains data with label equals to indeces[j]
        label = data_original[data_original["Label"] == indices[j]]

        # calculate the drop rate
        fraction = 1 - min(value_counts.values) / k

        # apply drop and changes inplace
        data_original.drop(label.sample(frac=fraction).index, inplace=True)

    print("after balancing data")
    print(data_original["Label"].value_counts())

    if save:
        data_original.to_csv(path + filename + "_balanced_drop.csv", index=False)
    return data_original


if __name__ == "__main__":
    data_balance_dropping(filename="aggregate_total_data_cleaned", label_name="Label", save=True)