from sklearn.neural_network import MLPClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report,confusion_matrix
import pandas as pd
import numpy as np
from datetime import datetime
import re
import os

data_set = ["caida-A", "univ1", "IoT", "wide"]
normal_type = 10

def file_name_walk(file_dir):
    file_list = []
    for root, dirs, files in os.walk(file_dir):
        # print("root", root)
        # print("dirs", dirs)
        # print("files", files)
        for file in files:
            if os.path.splitext(file)[1] == ".csv":
                file_list.append("{}/{}".format(root, file))
    print(file_list)
    return file_list

def process(fileName, saveName, class_type):
    original_col_names = ["srcPort", "dstPort", "protocol","ip_ihl", "ip_tos", 
                          "ip_flags", "ip_ttl", "tcp_dataofs", "tcp_flag", "tcp_window", "udp_len", "length",
                          "srcAddr1", "srcAddr2", "srcAddr3", "srcAddr4", "dstAddr1", "dstAddr2", "dstAddr3", "dstAddr4"]

    df = pd.read_csv(fileName)
    print(df.shape)

    #bit: number of bits, n: number to transfer
    getBits = lambda bits: lambda n: pd.Series(list(('{0:0%db}'%bits).format(int(n))))
    # bit length
    length_map = {"srcPort": 16, "dstPort": 16, "protocol": 8, "ip_ihl": 4, "ip_tos": 8, "ip_flags": 8, "ip_ttl": 8,"tcp_dataofs": 4, "tcp_flag": 8, "tcp_window": 16, "udp_len": 16, "length": 16}
    # print(df['tcp_flag'].unique())
    
    for key, value in length_map.items():
        tmp_cols = ['{}-{}'.format(key, i) for i in range(value)]
        df[tmp_cols] = df[key].apply(getBits(value))
    tmp_class = [class_type for i in range(df.shape[0])]
    df = df.drop(original_col_names, axis=1)
    df["class"] = tmp_class
    print(df.shape)
    df.to_csv(saveName, index=False)

def main():    
    save_dir = "../DataSets/normal-bin-feature"
    if not os.path.exists(save_dir):
        os.makedirs(save_dir)
    file_list = file_name_walk('../DataSets/normal-dec-feature')
    for i, file_name in enumerate(file_list):
        save_path = "../DataSets/normal-bin-feature/{}.csv".format(i)
        process(file_name, save_path, normal_type)
        print("finish: {}/{}".format(i, len(file_list)))
    

if __name__ == '__main__':
    a = datetime.now()
    print("start time", a)
    main()
    b = datetime.now()
    print("end time", b)
    durn = (b-a).seconds
    print("duration", durn)

    
