import random
import numpy as np
import pandas as pd
import time
from sklearn.model_selection import train_test_split
import os


def file_name_walk(file_dir):
    file_list = []
    for root, dirs, files in os.walk(file_dir):
        for file in files:
            if os.path.splitext(file)[1] == ".csv":
                file_list.append("{}/{}".format(root, file))
    return file_list
def dir_name_walk(file_dir):
    dir_list = []
    for root, dirs, files in os.walk(file_dir):
        for dir in dirs:

            dir_list.append("{}/{}".format(root, dir))
    return dir_list


def load_iot_attack(attack_name='all',thr_time=10):
    # load attack
    df_attack = pd.DataFrame()
    attack_path = './DataSets/Anomaly/attack-flow-level-device_{:}_dou_burst_14_add_pk/'.format(thr_time)
    if (attack_name=='all'):#load all
        attack_list=os.listdir(attack_path)
    else: #load specfic attack
        attack_list = [attack_name]
    for type_index, type_name in enumerate(attack_list):
        # if type_name in skip:
        #     continue
        file_list = file_name_walk('./DataSets/Anomaly/attack-flow-level-device_{:}_dou_burst_14_add_pk/{:}'.format(thr_time,type_name))
        for i, file_path in enumerate(file_list):
            tmp_df = pd.read_csv(file_path)
            df_attack = df_attack.append(tmp_df, ignore_index=True)
            print(file_path)
    df_attack['class'] = -1
    df_attack.dropna(axis=0, inplace=True)
    return df_attack


def load_iot_data(device_list=['philips_camera'],thr_time=10,begin=0,end=5):
    df_normal = pd.DataFrame()

    # load normal
    normal_list = device_list
    device_info = device_list
    for type_index, type_name in enumerate(normal_list):
        if type_name in device_info:
            file_list = file_name_walk('./DataSets/normal-flow-level-device_{:}_dou_burst_14_add_pk/{:}'.format(thr_time,type_name))
            file_list.sort()
            df_normal_type = pd.DataFrame()
            begin_num = begin
            end_num = end
            for i, file_path in enumerate(file_list[begin_num:end_num]):
                # old:error int16
                # tmp_df = pd.read_csv(file_path, dtype=np.int16)
                # new: int32
                print(file_path)
                tmp_df = pd.read_csv(file_path)
                df_normal_type = df_normal_type.append(tmp_df, ignore_index=True)

            df_normal = df_normal.append(df_normal_type, ignore_index=True)
    df_normal['class']=1 #in iforest the anomaly is negative number, thus the 1 is the normal flow
    df_normal.dropna(axis=0,inplace=True)
    return  df_normal


def open_source_load_iot_data(thr_time=10, selected_list=[0]):
    df_normal = pd.DataFrame()

    # load normal
    normal_path = './DataSets/Open-Source/normal-flow-level-device_{:}_dou_burst_14_add_pk'.format(thr_time)
    file_list = file_name_walk(normal_path)
    file_list.sort()
    df_normal_type = pd.DataFrame()
    for i, file_path in enumerate(file_list):
        # old:error int16
        # tmp_df = pd.read_csv(file_path, dtype=np.int16)
        # new: int32
        if i in selected_list:
            print(file_path)
            tmp_df = pd.read_csv(file_path)
            df_normal_type = df_normal_type.append(tmp_df, ignore_index=True)

    df_normal = df_normal.append(df_normal_type, ignore_index=True)
    df_normal['class']=1 #in iforest the anomaly is negative number, thus the 1 is the normal flow
    df_normal.dropna(axis=0,inplace=True)
    return df_normal

def load_iot_data_seq(device_list=['philips_camera'],begin=0,end=5):
    df_normal = pd.DataFrame()

    # load normal
    normal_list = device_list
    for type_index, type_name in enumerate(normal_list):
        file_list = file_name_walk(
            './DataSets/normal-kitsune_test/{:}'.format(type_name))
        file_list.sort()
        df_normal_type = pd.DataFrame()
        begin_num = begin
        end_num = end
        for i, file_path in enumerate(file_list[begin_num:end_num]):
            # old:error int16
            # tmp_df = pd.read_csv(file_path, dtype=np.int16)
            # new: int32
            try:
                tmp_df = pd.read_csv(file_path, header=None)
                df_normal_type = df_normal_type.append(tmp_df, ignore_index=True)
            except:
                print(file_path)
        df_normal = df_normal.append(df_normal_type, ignore_index=True)
    df_normal['class'] = 0

    df_normal.fillna(0,inplace=True)
    return df_normal

def open_source_load_iot_data_seq(selected_list=[0]):
    df_normal = pd.DataFrame()

    # load normal
    normal_path = './DataSets/Open-Source/normal_kitsune'
    file_list = file_name_walk(normal_path)
    file_list.sort()
    df_normal_type = pd.DataFrame()
    for i, file_path in enumerate(file_list):
        # old:error int16
        # tmp_df = pd.read_csv(file_path, dtype=np.int16)
        # new: int32
        if i in selected_list:
            try:
                tmp_df = pd.read_csv(file_path, header=None)
                df_normal_type = df_normal_type.append(tmp_df, ignore_index=True)
            except:
                print(file_path)
    df_normal = df_normal.append(df_normal_type, ignore_index=True)
    df_normal['class'] = 0

    df_normal.fillna(0,inplace=True)
    return df_normal


def load_iot_attack_seq(attack_name='all'):
    # load attack
    df_attack = pd.DataFrame()
    df_attack_label = pd.DataFrame()
    attack_path = './DataSets/Anomaly/attack_kitsune/'
    if (attack_name=='all'):#load all
        attack_list=os.listdir(attack_path)
        # print(attack_list)
    else: #load specfic attack
        attack_list = [attack_name]
    for type_index, type_name in enumerate(attack_list):
        file_list = file_name_walk('./DataSets/Anomaly/attack_kitsune/{:}'.format(type_name))
        #print(file_list)
        for i, file_path in enumerate(file_list):
            if 'label' in file_path:
                continue
            tmp_df = pd.read_csv(file_path, header=None)
            df_attack = df_attack.append(tmp_df, ignore_index=True)
            if file_path.replace('.csv', '_label.csv') in file_list:
                tmp_label = pd.read_csv(file_path.replace('.csv', '_label.csv'), header=None)
            else:
                tmp_label = pd.DataFrame(data=([1]*len(tmp_df)), index=None)
            df_attack_label = df_attack_label.append(tmp_label, ignore_index=True)
    df_attack['class'] = df_attack_label.values
    df_attack.fillna(0,inplace=True)
    return df_attack

