# incomplete, dont use
import pandas as pd
import numpy as np
import os
import sys


def data_normalization_file(path=None, filename=None, label_name=None, mu=None, std=None, save=False):

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

    if mu is not None:
        if os.path.exists(path + mu + ".csv"):
            mu = pd.read_csv(path + mu + ".csv", header=None)
            mu = mu.values
            mu = np.reshape(mu, (-1))
        else:
            print(f"Does not find {path + mu}.csv")
            sys.exit(1)

    if std is not None:
        if os.path.exists(path + std + ".csv"):
            std = pd.read_csv(path + std + ".csv", header=None)
            std = std.values
            std = np.reshape(std, (-1))
        else:
            print(f"Does not find {path + std}.csv")
            sys.exit(1)

    # processing
    data_dataframe = pd.read_csv(path + filename + ".csv")

    data_label = data_dataframe[label_name]

    data_feature = data_dataframe.drop(label_name, axis=1)

    data_normalized, mu, std = data_normalization(data_feature, mu, std)

    data_normalized_with_label = pd.concat([data_normalized, data_label], axis=1)

    pd.DataFrame(mu).to_csv(path + "zscore_mean.csv", header=False, index=False)
    pd.DataFrame(std).to_csv(path + "zscore_std.csv", header=False, index=False)

    if save:
        print("Start saving")
        data_normalized_with_label.to_csv(path + filename + "_normalized.csv", index=False)
        print("Saved")
    return data_normalized_with_label, mu, std


def data_normalization(x: np.ndarray or pd.DataFrame, mu=None, std=None, save=False):
    """
    this function takes np.ndarray | dataframe type as input to calculate normalized data
    :param x: input: np.ndarray | dataframe
    :param mu: mean of the array
    :param std: std of the array

    :return: normalized x, mean array, standard deviation
    """

    # calculate mean
    if mu is None:
        print("Mean is none, calculating...")
        mu = np.mean(x, axis=0)
        print("Done.")

    # calculate std
    if std is None:
        print("Std is none, calculating...")
        std = np.std(x, axis=0)
        print("Done.")

    for i in range(len(std)):
        if std[i] == 0:
            std[i] = 1

    # calculate normalized value
    x_norm = (x - mu) / std

    print(f"x_norm: \n {x_norm} \n mean: \n {mu} \n std: \n {std} \n")

    if save:
        pd.DataFrame(mu).to_csv("./" + "zscore_mean.csv", header=False, index=False)
        pd.DataFrame(std).to_csv("./" + "zscore_std.csv", header=False, index=False)

    return x_norm, mu, std


if __name__ == "__main__":
    np.set_printoptions(precision=1)
    a = np.random.random_sample((8, 6))
    b = pd.DataFrame(a)
    # test case 1: nparray
    data_normalization(a)
    # test case 2: dataframe
    data_normalization(b)

    mu = [0.48130356, 0.60656946, 0.46602288, 0.62920112, 0.42316389, 0.60163084]
    std = [0.3656252,  0.18669239, 0.30053784, 0.29270538, 0.25004703, 0.29321477]

    # test case 3: nparray + list: mean and std
    data_normalization(a, mu, std)

    # test case 4: dataframe + list: mean and std
    data_normalization(b, mu, std)

    data_normalization_file("./", filename="aggregate_total_data_cleaned", save=True)

    data_normalization_file("./", filename="aggregate_total_data_cleaned", mu="zscore_mean", std="zscore_std", save=True)
