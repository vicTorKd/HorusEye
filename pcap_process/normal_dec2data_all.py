import pandas as pd
import os
import numpy as np
def file_name_walk(file_dir):
    file_list = []
    for root, dirs, files in os.walk(file_dir):
        for file in files:
            if os.path.splitext(file)[1] == ".csv":
                file_list.append("{}/{}".format(root, file))
    return file_list

def main():
    df_normal = pd.DataFrame()
    normal_path = '../DataSets/normal-dec-feature/'
    # load attack
    file_list = file_name_walk(normal_path)
    total_len=len(file_list)
    for i,file_path in enumerate(file_list):
        # old:error int16
        # tmp_df = pd.read_csv(file_path, dtype=np.int16)
        # new: int32
        tmp_df = pd.read_csv(file_path)
        df_normal = df_normal.append(tmp_df, ignore_index=True)
        print('loading {:}/{:}'.format(i,total_len))
    df_normal.to_csv('/home/dyt/IForest_IoT/DataSets/normal-dec-feature/all_data.csv')
    print('success to transfer file_list to all_data.csv')

main()
