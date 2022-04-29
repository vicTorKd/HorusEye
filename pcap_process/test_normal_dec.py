#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2021/7/14 下午3:51
# @Author  : Yutao Dong
# @Site    : 
# @File    : test_normal_dec.py
# @Software: PyCharm
import pandas as pd
import numpy as np
from datetime import datetime
import re
import os

normal_type = 10

def file_name_walk(file_dir):
    file_list = []
    for root, dirs, files in os.walk(file_dir):
        # print("root", root)  # 当前目录路径
        # print("dirs", dirs)  # 当前路径下所有子目录
        # print("files", files)  # 当前路径下所有非目录子文件
        for file in files:
            if os.path.splitext(file)[1] == ".pcap":
                file_list.append("{}/{}".format(root, file))
    print(file_list)
    return file_list

file_list = file_name_walk('/home/dyt/IForest_IoT/DataSets/Normal/data/aqara_gateway')
print(file_list[27])
