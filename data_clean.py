import pandas as pd
import sys
import os


def data_clean(path=None, filename=None, save=False):
    """
    this function is used to drop those rows that contains inf, blank, and any other invalid valurs
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
    pd.options.mode.use_inf_as_na = True
    data_dataframe = pd.read_csv(path + filename + ".csv")
    data_dataframe.dropna(inplace=True)

    # dataset save
    if save:
        data_dataframe.to_csv(path + filename + "_cleaned.csv", index=False)

    # return dataset
    return data_dataframe


if __name__ == "__main__":
    # test
    data_clean(filename="aggregate_total_data", save=True)
