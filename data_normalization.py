import pandas as pd
import numpy as np
import os
import sys
import time


def data_normalization_file(path=None, filename=None, label_name=None, mu=None, std=None, save_data=False, save_mu_std=False):
    """
    this function will calculate normalized data from a file
    :param path: string, path of the file
    :param filename: string, prefix of the file
    :param label_name: string, indicate the column that is the label
    :param mu: string, prefix of the mean file
    :param std: string, prefix of the std file
    :param save_data: boolean, will save normalized data
    :param save_mu_std: boolean, will save mean and std

    :return: normalized x, mean array, standard deviation array
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

    # if provided mean and std file, read them
    read_csv_s = time.time()
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
    read_csv_e = time.time()
    diff_read = read_csv_e - read_csv_s
    print(f"read_csv time: {diff_read:.3f} seconds")

    # save for future merge after normalization
    data_label = data_dataframe[label_name]

    # filter out feature columns
    data_feature = data_dataframe.drop(label_name, axis=1)

    # normalize
    data_normalized, mu, std = data_normalization(data_feature, mu, std, save=save_mu_std)

    data_normalized_with_label = pd.concat([data_normalized, data_label], axis=1)

    # save normalized data
    if save_data:
        print("Start saving")
        to_csv_s = time.time()
        data_normalized_with_label.to_csv(path + filename + "_normalized.csv", index=False)
        print("Saved")
        to_csv_e = time.time()
        diff_to_csv = to_csv_e - to_csv_s

        print(f"to_csv time: {diff_to_csv:.3f} seconds")

    # return
    return data_normalized_with_label, mu, std


def data_normalization(x: np.ndarray or pd.DataFrame, mu=None, std=None, save=False):
    """
    this function takes np.ndarray | dataframe type as input to calculate normalized data
    :param x: input: np.ndarray | dataframe
    :param mu: mean of the array
    :param std: std of the array
    :param save: boolean, will save the mean and std for future use if True

    :return: normalized x, mean array, standard deviation array
    """
    norm_s = time.time()
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

    # avoid divide operand is zero
    for i in range(len(std)):
        if std[i] == 0:
            std[i] = 1

    # calculate normalized value
    x_norm = (x - mu) / std

    # print(f"x_norm: \n {x_norm} \n mean: \n {mu} \n std: \n {std} \n")

    if save:
        pd.DataFrame(mu).to_csv("./" + "zscore_mean.csv", header=False, index=False)
        pd.DataFrame(std).to_csv("./" + "zscore_std.csv", header=False, index=False)
    norm_e = time.time()
    diff_norm = norm_e - norm_s
    print(f"normalization time: {diff_norm:.3f} seconds")

    # return
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

    # test case 5: do normalization on a file, only save mean and std
    data_normalization_file("./", filename="aggregate_total_data_cleaned", save_data=False, save_mu_std=True)

    # test case 6: do normalization on a file, save all
    data_normalization_file("./", filename="aggregate_total_data_cleaned", save_data=True, save_mu_std=True)

    # test case 7: do normalization on a file using previous saved mean and std
    data_normalization_file("./", filename="aggregate_total_data_cleaned", mu="zscore_mean", std="zscore_std")
