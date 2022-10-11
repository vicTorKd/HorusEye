import pandas as pd
import os
import numpy as np
from collections import defaultdict
import hashlib
import time

import warnings
warnings.filterwarnings('ignore')

def add_server_port(df_data, open_source=False):
    MAC_list = []
    open_source_MAC_list = ['70:ee:50:18:34:43', 'f4:f2:6d:93:51:f1', '00:16:6c:ab:6b:88', '30:8c:fb:2f:e4:b2',
                            '00:62:6e:51:27:2e', 'e8:ab:fa:19:de:4f', '00:24:e4:11:18:a8', 'ec:1a:59:83:28:11',
                            '18:b4:30:25:be:e4', '70:ee:50:03:b8:ac', 'd0:73:d5:01:83:08', '30:8c:fb:b6:ea:45']
    our_MAC_list = ['e4:aa:ec:23:97:db', 'b0:59:47:a2:b2:ab', '54:ef:44:cd:f4:5d', '54:ef:44:cd:42:95',
                    'b8:c6:aa:08:45:26', 'f8:8c:21:0b:ec:26', '7c:25:da:62:14:52', 'd4:b7:61:bc:ac:10',
                    'b0:f8:93:42:22:bf', '90:76:9f:50:27:d9', '68:6d:bc:a9:7d:7c', 'dc:bd:7a:c6:b8:ae',
                    '50:2c:c6:04:e2:7c']
    if open_source:
        MAC_list = open_source_MAC_list
    else:
        MAC_list = our_MAC_list
    df_data['server_port'] = 0
    for i in range(len(df_data)):
        src_port = int(df_data.at[i, '5-tuple'].split(',')[1].replace(" ", ""))
        dst_port = int(df_data.at[i, '5-tuple'].split(',')[3].replace(" ", ""))
        src_MAC = df_data.at[i, 'MAC'].split('\'')[1]
        dst_MAC = df_data.at[i, 'MAC'].split('\'')[3]
        if src_MAC in MAC_list:
            df_data.at[i, 'server_port'] = dst_port
        else:
            df_data.at[i, 'server_port'] = src_port
    return df_data

def filter_loc_com(df):
    condition1 = np.array([df['srcAddr1'] == 192]) & np.array([df['srcAddr2'] == 168]) & np.array(
        [df['srcAddr3'] == 1]) & np.array([df['dstAddr1'] == 192]) & np.array(
        [df['dstAddr2'] == 168]) & np.array([df['dstAddr3'] == 1])
    # filter1 = (~condition1[0])
    # df = df[filter1]
    df = df[df['dstAddr4'] != 255]
    tcp = df[df['protocol'] == 6]
    udp = df[df['protocol'] == 17]
    return tcp.append(udp)


def extract_flow_size_burst(in_csv, out_csv, thr_time, manul_cut,count_pk,pk_thr):
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
    pack_len_sum = pd.DataFrame(columns=['5-tuple', 'sum_len', 'udp_tcp','pk_num','MAC'])  # udp-0 tcp-1,for one burst
    # thr_time=10
    # thr_interval=5
    # thr_time=10 #every 1 min to extract UDP flow.
    old_time = df.iloc[0]['time']
    for i in range(len(df)):
        cur_time = df.iloc[i]['time']
        key1 = str(df[["srcIP", "srcPort", "protocol"]].iloc[i].tolist())# count double dir str
        key2 = str(df[["dstIP", "dstPort", "protocol"]].iloc[i].tolist())
        #key = hash(key1) + hash(key2)
        h1 = hashlib.md5(key1.encode('utf-8'))
        h2 = hashlib.md5(key2.encode('utf-8'))
        key = int.from_bytes(h1.digest(), byteorder='big') + int.from_bytes(h2.digest(), byteorder='big')
        value = real_pack_len_sum[key]
        if (len(value) != 0):
            if (cur_time - value[0] > thr_time or value[4] > pk_thr):
                pack_len_sum = pack_len_sum.append(
                    pd.DataFrame({'5-tuple': value[3], 'sum_len': value[1], 'udp_tcp': value[2], 'pk_num': value[4],
                                  'MAC': value[5], 'key': str(key)}, index=[0]))
                count_pk[value[4]]+=1
                del real_pack_len_sum[key]
                continue
            else:
                value[0] = cur_time
                value[1] += df['length'].iloc[i]
                value[4] += 1
        else:# new burst
            value = [cur_time, df['length'].iloc[i]]
            five_tuple = str(df[["srcIP", "srcPort", "dstIP", "dstPort", "protocol"]].iloc[i].tolist())
            MAC = str(df[["srcMAC", "dstMAC"]].iloc[i].tolist())
            if (df['protocol'].iloc[i] == 17):  # udp-0 tcp-1
                value.append(0)
            elif(df['protocol'].iloc[i] == 6):
                value.append(1)
            else:
                continue
            value.append(five_tuple)
            value.append(1) #pk_num is 1 :value[4]
            value.append(MAC)
        real_pack_len_sum[key] = value

    if manul_cut:  
        iter_keys = real_pack_len_sum.keys()
        for key in list(iter_keys):
            value = real_pack_len_sum[key]
            pack_len_sum = pack_len_sum.append(
                pd.DataFrame({'5-tuple': value[3], 'sum_len': value[1], 'udp_tcp': value[2], 'pk_num': value[4],
                              'MAC': value[5], 'key': str(key)}, index=[0])) 
            count_pk[value[4]] += 1
            del real_pack_len_sum[key]
    print('finish the file {:}'.format(in_csv))
    pack_len_sum.to_csv(out_csv)

    # add server port
    port_list = ['port_' + str(15-i) for i in range(16)]
    # df_data = pack_len_sum
    df_data = pd.read_csv(out_csv)
    # df_data['dst_port'] = 0
    df_data = add_server_port(df_data, open_source=True)
    for feature in port_list:
        df_data[feature] = 0
    for i in range(len(df_data)):
        # dst_port = df_data.iloc[i]['5-tuple'].split(',')[3]
        # df_data['dst_port'][i] = dst_port
        bin_port = bin(df_data.at[i, 'server_port'])[2:].rjust(16, '0')
        for j, bit in enumerate(bin_port):
            df_data.at[i, port_list[j]] = int(bit)
    # df_data = add_server_port(df_data, open_source=False)
    df_data.to_csv(out_csv, index=False)

    #pd_pk=pd.DataFrame(count_pk,index=[0])
    #print(pd_pk)
    return count_pk


def extract_flow_size(in_csv, out_csv,thr_time,manul_TCP_cut):
    df=pd.read_csv(in_csv)
    df=filter_loc_com(df)
    df.dropna(axis=0,inplace=True)
    for col_names in ['srcAddr{}'.format(i) for i in range(1, 5)]:
        df[col_names] = df[col_names].astype('int').astype('str')
    for col_names in ['dstAddr{}'.format(i) for i in range(1, 5)]:
        df[col_names] = df[col_names].astype('int').astype('str')
    df['srcIP'] = df['srcAddr1'].str.cat([df['srcAddr2'], df['srcAddr3'], df['srcAddr4']], sep='.')
    df['dstIP'] = df['dstAddr1'].str.cat([df['dstAddr2'], df['dstAddr3'], df['dstAddr4']], sep='.')
    #group = df.groupby(["srcIP", "srcPort", "dstIP", "dstPort", "protocol"])

    real_pack_len_sum=defaultdict(list)# '5-tuple':{'cur_timestamp','sum_len'}
    pack_len_sum=pd.DataFrame(columns=['5-tuple','sum_len','udp_tcp'])#udp-0 tcp-1
    #thr_time=10
    #thr_interval=5
    #thr_time=10 #every 1 min to extract UDP flow.
    old_time=df.iloc[0]['time']
    for i in range(len(df)):
        cur_time=df.iloc[i]['time']
        if(df.iloc[i]['tcp_flag']&5): #0000 0101
            key=str(df[["srcIP", "srcPort", "dstIP", "dstPort", "protocol"]].iloc[i].tolist())
            value=real_pack_len_sum[key]
            if (len(value)!=0):
                pack_len_sum=pack_len_sum.append(pd.DataFrame({'5-tuple':key,'sum_len':value[1],'udp_tcp':1},index=[0]))
            del real_pack_len_sum[key]
            continue
         #   print('error')
        if((cur_time-old_time)>thr_time):
            old_time=cur_time
            iter_keys=real_pack_len_sum.keys()
            for key in list(iter_keys):
                value=real_pack_len_sum[key]
                
                if value[2] == 0:
                    pack_len_sum=pack_len_sum.append(pd.DataFrame({'5-tuple':key,'sum_len':value[1],'udp_tcp':value[2]},index=[0]))
                    del real_pack_len_sum[key]
                    #print('1')
                    #print(pack_len_sum)
        
        key=str(df[["srcIP", "srcPort", "dstIP", "dstPort", "protocol"]].iloc[i].tolist())
        temp_pack=real_pack_len_sum[key]
        if (len(temp_pack)==0):
            temp_pack=[cur_time,df['length'].iloc[i]]
            if(df['udp_len'].iloc[i]>0): #udp-0 tcp-1
                temp_pack.append(0)
            else:
                temp_pack.append(1)
        else:
            temp_pack[0]=cur_time
            temp_pack[1] +=df['length'].iloc[i]
        real_pack_len_sum[key]=temp_pack
        #if (i%1000==0):
            #print('finish {:}'.format(i))
    iter_keys = real_pack_len_sum.keys()
    if manul_TCP_cut:
        for key in list(iter_keys):
            value = real_pack_len_sum[key]
            if value[2] == 1:
                pack_len_sum = pack_len_sum.append(
                    pd.DataFrame({'5-tuple': key, 'sum_len': value[1], 'udp_tcp': value[2]}, index=[0]))
                del real_pack_len_sum[key]
    print('finish the file {:}'.format(in_csv))
    pack_len_sum.to_csv(out_csv)
def file_name_walk(file_dir):
    file_list = []
    for root, dirs, files in os.walk(file_dir):
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
    file_list = file_name_walk('../DataSets/Open-Source/normal-dec-feature-device')
    save_root = '../DataSets/Open-Source/normal-flow-level-device_{}_dou_burst_{}_add_pk'.format(str(thr_time), pk_thr)
    if not os.path.exists(save_root):
        os.makedirs(save_root)
    file_list.sort()
    for i, file_name in enumerate(file_list):
        print(file_name)
        print(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()))
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
    # normal_list=os.listdir('../DataSets/Attack_iot_filter/Pcap/')
    thr_time=1
    pk_thr=14
    manul_TCP_cut=True
    count_pk=defaultdict(int)
    normal_list = ['philips_camera','360_camera','ezviz_camera','hichip_battery_camera','mercury_wirecamera','skyworth_camera','tplink_camera','xiaomi_camera']#'philips_camera','360_camera','ezviz_camera','hichip_battery_camera','mercury_wirecamera','skyworth_camera','tplink_camera','xiaomi_camera'
    normal_list.extend(['aqara_gateway', 'gree_gateway', 'ihorn_gateway', 'tcl_gateway', 'xiaomi_gateway'])
    for type_index, type_name in enumerate(normal_list):
        if type_name not in ['gree_gateway', 'ihorn_gateway', 'tcl_gateway', 'xiaomi_gateway']:
            print("skip: ", type_name)
            continue
        # file_list = file_name_walk('../DataSets/Anomaly/attack-dec-feature-device/{}'.format(type_name))
        # save_root = '../DataSets/Anomaly/attack-flow-level-device_{}_dou_burst_{}_add_pk/{}'.format(str(thr_time),pk_thr,type_name)
        # file_list = file_name_walk('../DataSets/normal-dec-feature-device/{}'.format(type_name))
        # save_root = '../DataSets/normal-flow-level-device_{}_dou_burst_{}_add_pk/{}'.format(str(thr_time),pk_thr,type_name)
        file_list = file_name_walk('../NewDataSets/normal-dec-feature-device/{}'.format(type_name))
        save_root = '../NewDataSets/normal-flow-level-device_{}_dou_burst_{}_add_pk/{}'.format(str(thr_time),pk_thr,type_name)
        if not os.path.exists(save_root):
            os.makedirs(save_root)
        file_list.sort()
        for i, file_name in enumerate(file_list):
            print(file_name)
            print(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()))
            if i<10:# for file sort, because '.' > {0-9}
                save_path = save_root + '/{}-0{}.csv'.format(type_name, i)
            else:
                save_path = save_root+'/{}-{}.csv'.format(type_name, i)
            count_pk=extract_flow_size_burst(file_name, save_path,thr_time,manul_TCP_cut,count_pk,pk_thr)
# main()
open_source_data_process()

