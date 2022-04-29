#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
@File    :   concat_attack.py
@Time    :   2021/07/10 15:30:24
@Author  :   Guanglin Duan 
@Version :   1.0
'''

from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report,confusion_matrix
import pandas as pd
import numpy as np
from datetime import datetime
import re
import os

data_set = ["caida-A", "univ1", "IoT", "wide"]

def file_name_walk(file_dir):
    file_list = []
    for root, dirs, files in os.walk(file_dir):
        # print("root", root)  # 当前目录路径
        # print("dirs", dirs)  # 当前路径下所有子目录
        # print("files", files)  # 当前路径下所有非目录子文件
        for file in files:
            if os.path.splitext(file)[1] == ".csv":
                file_list.append("{}/{}".format(root, file))
    print(file_list)
    return file_list
def process(dec_fileName, bin_fileName, save_fileName):

    dec_df = pd.read_csv(dec_fileName)
    bin_df = pd.read_csv(bin_fileName)
    # dec_df = dec_df.drop("type", axis=1)
    dec_df["class"] = bin_df["class"]
    bin_df = bin_df.drop("class", axis=1)

    print(dec_df.shape)
    print(bin_df.shape)

    df_concat = pd.concat([bin_df, dec_df], axis=1)
    # print(bin_df)
    # print(dec_df)
    # print(df_concat)
    df_concat.to_csv(save_fileName, index=False)

def main():
    save_dir = "/home/dyt/IForest_IoT/DataSets/normal-concat-feature"
    if not os.path.exists(save_dir):
        os.makedirs(save_dir)
    dec_file_list = file_name_walk('/home/dyt/IForest_IoT/DataSets/normal-dec-feature')
    for i, dec_file in enumerate(dec_file_list):
        bin_file = "/home/dyt/IForest_IoT/DataSets/normal-bin-feature/{}.csv".format(i)
        save_path = "/home/dyt/IForest_IoT/DataSets/normal-concat-feature/{}.csv".format(i)
        process(dec_file, bin_file, save_path)
        print("finish: {}/{}".format(i, len(dec_file_list)))

if __name__ == '__main__':
    a = datetime.now()
    print("start time", a)
    main()
    b = datetime.now()
    print("end time", b)
    durn = (b-a).seconds
    print("duration", durn)
