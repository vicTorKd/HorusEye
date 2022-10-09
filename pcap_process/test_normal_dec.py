import pandas as pd
import numpy as np
from datetime import datetime
import re
import os

normal_type = 10

def file_name_walk(file_dir):
    file_list = []
    for root, dirs, files in os.walk(file_dir):
        for file in files:
            if os.path.splitext(file)[1] == ".pcap":
                file_list.append("{}/{}".format(root, file))
    print(file_list)
    return file_list

file_list = file_name_walk('../DataSets/Normal/data/aqara_gateway')
print(file_list[27])
