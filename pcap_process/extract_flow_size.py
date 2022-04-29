#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2021/8/30 上午9:37
# @Author  : Yutao Dong
# @Site    : 
# @File    : extract_flow_size.py
# @Software: PyCharm

import pandas as pd
import os
import numpy as np
# load_iot_data_cum_pac_l
from collections import defaultdict
import hashlib
import time


def filter_loc_com(df):
    # condition1 Filter out intranet IP traffic
    condition1 = np.array([df['srcAddr1'] == 192]) & np.array([df['srcAddr2'] == 168]) & np.array(
        [df['srcAddr3'] == 1]) & np.array([df['dstAddr1'] == 192]) & np.array(
        [df['dstAddr2'] == 168]) & np.array([df['dstAddr3'] == 1])
    # filter1 = (~condition1[0])  # 取反
    # df = df[filter1]
    # condition2 delete broadcast message, dstAddr4==255，will not enter the external network switch
    df = df[df['dstAddr4'] != 255]
    # condition3 keep pnly udp and tcp
    tcp = df[df['protocol'] == 6]
    udp = df[df['protocol'] == 17]
    return tcp.append(udp)


def extract_flow_size_burst(in_csv, out_csv, thr_time, manul_cut, count_pk, pk_thr):
    df = pd.read_csv(in_csv)
    df = filter_loc_com(df)
    df.dropna(axis=0, inplace=True)
    for col_names in ['srcAddr{}'.format(i) for i in range(1, 5)]:
        df[col_names] = df[col_names].astype('int').astype('str')
    for col_names in ['dstAddr{}'.format(i) for i in range(1, 5)]:
        df[col_names] = df[col_names].astype('int').astype('str')
    df['srcIP'] = df['srcAddr1'].str.cat([df['srcAddr2'], df['srcAddr3'], df['srcAddr4']], sep='.')
    df['dstIP'] = df['dstAddr1'].str.cat([df['dstAddr2'], df['dstAddr3'], df['dstAddr4']], sep='.')
    # group = df.groupby(["srcIP", "srcPort", "dstIP", "dstPort", "protocol"])

    real_pack_len_sum = defaultdict(list)  # hash_key :{'cur_timestamp','sum_len','5-tuple',pk_num}
    pack_len_sum = pd.DataFrame(columns=['5-tuple', 'sum_len', 'udp_tcp', 'pk_num'])  # udp-0 tcp-1,for one burst
    # thr_time=10
    # thr_interval=5
    # thr_time=10 #every 1 min to extract UDP flow.
    old_time = df.iloc[0]['time']
    for i in range(len(df)):
        cur_time = df.iloc[i]['time']
        key1 = str(df[["srcIP", "srcPort", "protocol"]].iloc[i].tolist())  # count double dir str
        key2 = str(df[["dstIP", "dstPort", "protocol"]].iloc[i].tolist())
        # key = hash(key1) + hash(key2)
        h1 = hashlib.md5(key1.encode('utf-8'))
        h2 = hashlib.md5(key2.encode('utf-8'))
        key = int.from_bytes(h1.digest(), byteorder='big') + int.from_bytes(h2.digest(), byteorder='big')
        value = real_pack_len_sum[key]
        if (len(value) != 0):
            if (cur_time - value[0] > thr_time or value[4] > pk_thr):
                pack_len_sum = pack_len_sum.append(
                    pd.DataFrame({'5-tuple': value[3], 'sum_len': value[1], 'udp_tcp': value[2], 'pk_num': value[4],
                                  'key': str(key)}, index=[0]))
                count_pk[value[4]] += 1  # Count the number of packets in different burst
                del real_pack_len_sum[key]  # free register
                continue
            else:  # update
                value[0] = cur_time
                value[1] += df['length'].iloc[i]
                value[4] += 1
        else:  # new burst
            value = [cur_time, df['length'].iloc[i]]
            five_tuple = str(df[["srcIP", "srcPort", "dstIP", "dstPort", "protocol"]].iloc[i].tolist())
            if (df['protocol'].iloc[i] == 17):  # udp-0 tcp-1
                value.append(0)
            elif (df['protocol'].iloc[i] == 6):
                value.append(1)
            else:
                continue
            value.append(five_tuple)
            value.append(1)  # pk_num is 1 :value[4]
        real_pack_len_sum[key] = value

    if manul_cut:  # Manually terminate all streams, some abnormal pcap files have only a few streams
        iter_keys = real_pack_len_sum.keys()
        for key in list(iter_keys):
            value = real_pack_len_sum[key]
            pack_len_sum = pack_len_sum.append(
                pd.DataFrame({'5-tuple': value[3], 'sum_len': value[1], 'udp_tcp': value[2], 'pk_num': value[4],
                              'key': str(key)}, index=[0]))
            count_pk[value[4]] += 1
            del real_pack_len_sum[key]
    print('finish the file {:}'.format(in_csv))
    pack_len_sum.to_csv(out_csv)
    # pd_pk=pd.DataFrame(count_pk,index=[0])
    # print(pd_pk)
    return count_pk


def extract_flow_size(in_csv, out_csv, thr_time, manul_TCP_cut):
    df = pd.read_csv(in_csv)
    df = filter_loc_com(df)
    df.dropna(axis=0, inplace=True)
    for col_names in ['srcAddr{}'.format(i) for i in range(1, 5)]:
        df[col_names] = df[col_names].astype('int').astype('str')
    for col_names in ['dstAddr{}'.format(i) for i in range(1, 5)]:
        df[col_names] = df[col_names].astype('int').astype('str')
    df['srcIP'] = df['srcAddr1'].str.cat([df['srcAddr2'], df['srcAddr3'], df['srcAddr4']], sep='.')
    df['dstIP'] = df['dstAddr1'].str.cat([df['dstAddr2'], df['dstAddr3'], df['dstAddr4']], sep='.')
    # group = df.groupby(["srcIP", "srcPort", "dstIP", "dstPort", "protocol"])

    real_pack_len_sum = defaultdict(list)  # '5-tuple':{'cur_timestamp','sum_len'}
    pack_len_sum = pd.DataFrame(columns=['5-tuple', 'sum_len', 'udp_tcp'])  # udp-0 tcp-1
    # thr_time=10
    # thr_interval=5
    # thr_time=10 #every 1 min to extract UDP flow.
    old_time = df.iloc[0]['time']
    for i in range(len(df)):
        cur_time = df.iloc[i]['time']
        # If it is FIN, ReSet message, end packet length statistics
        if (df.iloc[i]['tcp_flag'] & 5):  # 0000 0101
            key = str(df[["srcIP", "srcPort", "dstIP", "dstPort", "protocol"]].iloc[i].tolist())
            value = real_pack_len_sum[key]
            if (len(value) != 0):
                pack_len_sum = pack_len_sum.append(
                    pd.DataFrame({'5-tuple': key, 'sum_len': value[1], 'udp_tcp': 1}, index=[0]))
            del real_pack_len_sum[key]
            continue
        #   print('error')
        if ((cur_time - old_time) > thr_time):  # greater than the time threshold, perform statistical operations
            old_time = cur_time
            iter_keys = real_pack_len_sum.keys()
            for key in list(iter_keys):
                value = real_pack_len_sum[key]
                if value[2] == 0:  # If it is a UDP flow, count the flow size within the time window.
                    pack_len_sum = pack_len_sum.append(
                        pd.DataFrame({'5-tuple': key, 'sum_len': value[1], 'udp_tcp': value[2]}, index=[0]))
                    del real_pack_len_sum[key]
                    # print('1')
                    # print(pack_len_sum)
        # perform 5-tuple hash
        key = str(df[["srcIP", "srcPort", "dstIP", "dstPort", "protocol"]].iloc[i].tolist())
        temp_pack = real_pack_len_sum[key]
        if (len(temp_pack) == 0):
            temp_pack = [cur_time, df['length'].iloc[i]]
            if (df['udp_len'].iloc[i] > 0):  # udp-0 tcp-1
                temp_pack.append(0)
            else:
                temp_pack.append(1)
        else:
            temp_pack[0] = cur_time
            temp_pack[1] += df['length'].iloc[i]
        real_pack_len_sum[key] = temp_pack
        # if (i%1000==0):
        # print('finish {:}'.format(i))
    iter_keys = real_pack_len_sum.keys()
    if manul_TCP_cut:  # 手动终止所有TCP流，部分异常pcap文件没有FIN RST结束符。
        for key in list(iter_keys):
            value = real_pack_len_sum[key]
            if value[2] == 1:
                pack_len_sum = pack_len_sum.append(
                    pd.DataFrame({'5-tuple': key, 'sum_len': value[1], 'udp_tcp': value[2]}, index=[0]))  # 输出结果
                del real_pack_len_sum[key]  # 释放寄存器
    print('finish the file {:}'.format(in_csv))
    pack_len_sum.to_csv(out_csv)


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


def open_source_data_process():
    thr_time = 1
    pk_thr = 14
    manul_TCP_cut = True
    count_pk = defaultdict(int)
    print('main')
    # file_list = file_name_walk('../DataSets/Open-Source/attack-dec-feature-device')
    # save_root = '../DataSets/Open-Source/attack-flow-level-device_{}_dou_burst_{}_add_pk'.format(str(thr_time),pk_thr)
    file_list = file_name_walk('../DataSets/Open-Source/normal-dec-feature-device')
    save_root = '../DataSets/Open-Source/normal-flow-level-device_{}_dou_burst_{}_add_pk'.format(str(thr_time), pk_thr)
    if not os.path.exists(save_root):
        os.makedirs(save_root)
    file_list.sort()
    for i, file_name in enumerate(file_list):
        print(file_name)
        print(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()))
        if file_name <= '../DataSets/Open-Source/normal-dec-feature-device/file-10.csv':
            print('skip the file {}'.format(file_name))
            continue
        if i < 10:  # for file sort, because '.' > {0-9}
            save_path = save_root + '/file-0{}.csv'.format(i)
        else:
            save_path = save_root + '/file-{}.csv'.format(i)
        try:
            count_pk = extract_flow_size_burst(file_name, save_path, thr_time, manul_TCP_cut, count_pk, pk_thr)
        except:
            print('fail', file_name)


def main():
    """Program main entry"""
    # normal_list=os.listdir('/home/dyt/IForest_IoT/DataSets/Normal/data/')
    # normal_list = ['aqara_gateway', 'gree_gateway', 'gree_plug', 'wiz_led', 'xiaomi_plug']
    # normal_list = ['philips_camera']
    # normal_list=os.listdir('/home/dyt/IForest_IoT/DataSets/Attack_iot_filter/Pcap/')
    # normal_list = ['mirai']
    thr_time = 1
    pk_thr = 14
    manul_TCP_cut = True
    count_pk = defaultdict(int)
    normal_list = ['360_camera', 'ezviz_camera', 'hichip_battery_camera', 'mercury_wirecamera', 'skyworth_camera',
                   'tplink_camera',
                   'xiaomi_camera']  # 'philips_camera','360_camera','ezviz_camera','hichip_battery_camera','mercury_wirecamera','skyworth_camera','tplink_camera','xiaomi_camera'
    for type_index, type_name in enumerate(normal_list):
        # file_list = file_name_walk('/home/dyt/IForest_IoT/DataSets/Anomaly/attack-dec-feature-device/{}'.format(type_name))
        # save_root = '/home/dyt/IForest_IoT/DataSets/Anomaly/attack-flow-level-device_{}_dou_burst_{}_add_pk/{}'.format(str(thr_time),pk_thr,type_name)
        file_list = file_name_walk('/home/dyt/IForest_IoT/DataSets/normal-dec-feature-device/{}'.format(type_name))
        save_root = '/home/dyt/IForest_IoT/DataSets/normal-flow-level-device_{}_dou_burst_{}_add_pk/{}'.format(
            str(thr_time), pk_thr, type_name)
        if not os.path.exists(save_root):
            os.makedirs(save_root)
        file_list.sort()
        for i, file_name in enumerate(file_list):
            if i < 10:  # for file sort, because '.' > {0-9}
                save_path = save_root + '/{}-0{}.csv'.format(type_name, i)
            else:
                save_path = save_root + '/{}-{}.csv'.format(type_name, i)
            # print(file_name)
            try:
                count_pk = extract_flow_size_burst(file_name, save_path, thr_time, manul_TCP_cut, count_pk, pk_thr)
            except:
                print('fail', file_name)
    # pd_count_pk=pd.DataFrame(count_pk,index=[0])
    ##print(pd_count_pk)
    # pd_count_pk.to_csv('/home/dyt/IForest_IoT/result/anomaly_count_pk.csv')


# main()
open_source_data_process()
