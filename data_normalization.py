import pandas as pd
import numpy as np
import os
import sys


def data_normalization_file(path=None, filename=None, label_name=None, save=False):

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

    # processing
    data_dataframe = pd.read_csv(path + filename + ".csv")


def data_normalization(x: np.ndarray or pd.DataFrame, mu=None, sigma=None):
    """
    this function takes np.ndarray | dataframe type as input to calculate normalized data
    :param x: input: np.ndarray | dataframe
    :param mu: mean of the array
    :param sigma: std of the array

    :return: normalized x, mean array, standard deviation
    """

    # calculate mean
    if mu is None:
        mu = np.mean(x, axis=0)

    # calculate std
    if sigma is None:
        sigma = np.std(x, axis=0)

    # calculate normalized value
    x_norm = (x - mu) / sigma

    print(f"x_norm: \n {x_norm} \n mean: \n {mu} \n std: \n {sigma} \n")

    return x_norm, mu, sigma


if __name__ == "__main__":
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

    mu_df = pd.DataFrame(mu)
    std_df = pd.DataFrame(std)

    # test case 5: nparray + df: mean and std
    data_normalization(a, mu, std)

    # test case 6: dataframe + df: mean and std
    data_normalization(b, mu, std)
