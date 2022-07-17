import pandas as pd
import sys
import os


def data_split(path=None, filename=None, save=False):
    """
    this function is used to split data
    :param path: orginal file path
    :param filename: original file prefix - without suffix
    :param save: boolean, Ture: save cleaned data and return it, False: only return

    :return: dataframe type dataset
    """
    # default value
    if path is None:
        path = "./"
    if filename is None:
        filename = "package_result_processed"

    # file existing check
    if not os.path.exists(path + filename + ".csv"):
        print("file does not exist")
        sys.exit(1)

    # processing
    data_dataframe = pd.read_csv(path + filename + ".csv")

    split_index = len(data_dataframe) // 2
    data_dataframe_1 = data_dataframe.iloc[:split_index, :]
    data_dataframe_2 = data_dataframe.iloc[split_index:, :]

    # dataset save
    if save:
        data_dataframe_1.to_csv(path + filename + "_1.csv", index=False)
        data_dataframe_2.to_csv(path + filename + "_2.csv", index=False)

    # return dataset
    return data_dataframe_1, data_dataframe_2


if __name__ == "__main__":
    # test
    data_split(filename="aggregate_data_2017_clean_numerical_balanced_drop", save=True)
    data_split(filename="aggregate_2018_cleaned_balanced_drop", save=True)
    data_split(filename="17_18_merged_no_dup", save=True)
