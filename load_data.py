import random
import numpy as np
import pandas as pd
import time
# import Cython
import copy
from sklearn.model_selection import train_test_split
import os
from sklearn.preprocessing import Normalizer


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

def drop_dec_features(df):
    drop_cols = ["srcPort", "dstPort", "protocol", 'srcIP', 'dstIP',
                 "ip_ihl", "ip_tos", "ip_flags", "ip_ttl", "tcp_dataofs", "tcp_flag", "tcp_window",
                 "udp_len",
                 "length",
                 'srcAddr1', 'srcAddr2', 'srcAddr3', 'srcAddr4', 'dstAddr1', 'dstAddr2', 'dstAddr3',
                 'dstAddr4']
    df.drop(drop_cols, axis=1, inplace=True)
    return df


def split_train_test(df, train_percent=0.8,bin=True):
    drop_cols = ["srcPort", "dstPort", "protocol", 'srcIP', 'dstIP',
                 "ip_ihl", "ip_tos", "ip_flags", "ip_ttl", "tcp_dataofs", "tcp_flag", "tcp_window",
                 "udp_len",
                 "length",
                 'srcAddr1', 'srcAddr2', 'srcAddr3', 'srcAddr4', 'dstAddr1', 'dstAddr2', 'dstAddr3',
                 'dstAddr4']
    for col_names in ['srcAddr{}'.format(i) for i in range(1, 5)]:
        df[col_names] = df[col_names].astype('str')
    for col_names in ['dstAddr{}'.format(i) for i in range(1, 5)]:
        df[col_names] = df[col_names].astype('str')
    df['srcIP'] = df['srcAddr1'].str.cat([df['srcAddr2'], df['srcAddr3'], df['srcAddr4']], sep='.')
    df['dstIP'] = df['dstAddr1'].str.cat([df['dstAddr2'], df['dstAddr3'], df['dstAddr4']], sep='.')
    group = df.groupby(["srcIP", "srcPort", "dstIP", "dstPort", "protocol"])

    # ngroups: the number of groups
    total_index = np.arange(group.ngroups)
    print('total flow number', len(total_index))
    np.random.seed(1234)
    np.random.shuffle(total_index)
    split_index = int(len(total_index) * train_percent)
    # ngroup(): Number each group from 0 to the number of groups - 1.
    df_train = df[group.ngroup().isin(total_index[: split_index])]
    df_test = df[group.ngroup().isin(total_index[split_index:])]
    df_train.reset_index(drop=True, inplace=True)
    df_test.reset_index(drop=True, inplace=True)
    if bin:
        df_train.drop(drop_cols, axis=1, inplace=True)
        df_test.drop(drop_cols, axis=1, inplace=True)
    else:
        iot_feature_names = ["tcp_dataofs", "tcp_flag", "tcp_window","udp_len", "ip_ttl","srcPort", "dstPort", "protocol","ip_ihl", "ip_tos", "ip_flags","length", 'class']#

        df_train = df_train[iot_feature_names]
        df_test = df_test[iot_feature_names]



    return df_train, df_test


def get_bin_feature(df_total, feature_count):

    port_col = []
    for j in range(16):
        port_col.append('srcPort-{}'.format(j))
    for j in range(16):
        port_col.append('dstPort-{}'.format(j))
    flag_col = []
    for j in range(8):
        flag_col.append('ip_flags-{}'.format(j))
    for j in range(8):
        flag_col.append('tcp_flag-{}'.format(j))
    if feature_count == 80:
        df_total.drop(port_col, axis=1, inplace=True)
        df_total.drop(flag_col, axis=1, inplace=True)
    elif feature_count == 96:
        df_total.drop(port_col, axis=1, inplace=True)
    elif feature_count == 112:
        df_total.drop(flag_col, axis=1, inplace=True)
    elif feature_count == 120:
        return df_total
    return df_total
def filter_loc_com(df,device_type='philips_camera'):

    condition1 = np.array([df['srcAddr1'] == 192]) & np.array([df['srcAddr2'] == 168]) & np.array(
        [df['srcAddr3'] == 1]) & np.array([df['dstAddr1'] == 192]) & np.array(
        [df['dstAddr2'] == 168]) & np.array([df['dstAddr3'] == 1])
    filter1 = (~condition1[0])
    df = df[filter1]

    df = df[df['dstAddr4'] != 255]
    return df

def load_iot_attack(attack_name='all',thr_time=10,skip=[]):
    # load attack
    df_attack = pd.DataFrame()
    attack_path = './DataSets/Anomaly/attack-flow-level-device_{:}_dou_burst_14_add_pk/'.format(thr_time)
    if (attack_name=='all'):#load all
        attack_list=os.listdir(attack_path)
    else: #load specfic attack
        attack_list = [attack_name]
    for type_index, type_name in enumerate(attack_list):
        if type_name in skip:
            continue
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

