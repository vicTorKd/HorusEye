#!/usr/bin/env python3

"""pcap2csv
Script to extract specific pieces of information from a pcap file and
render into a csv file.
Usage: <program name> --pcap <input pcap file> --csv <output pcap file>
"""

import argparse
import os.path
import sys
import os

from scapy.utils import RawPcapReader
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP, TCP

ISIP = False
#--------------------------------------------------

def render_csv_row(timeInfo, pkt_sc, fh_csv):
    """Write one packet entry into the CSV file.
    pkt_sc is a 'bytes' representation of the packet as returned from
    scapy's RawPcapReader
    fh_csv is the csv file handle
    """
    ans_list = [0 for i in range(17)]
    # Each line of the CSV has this format
    fmt = '{0}|{1}|{2}|{3}|{4}|{5}|{6}|{7}|{8}|{9}|{10}|{11}|{12}|{13}|{14}|{15}|{16}'
    # timestamp
    ans_list[0] = timeInfo.sec
    if ISIP:
        eth_length = 0
        ip_pkt_sc = IP(pkt_sc)
    else:
        eth_length = 14
        ether_pkt_sc = Ether(pkt_sc)
        if ether_pkt_sc is None:
            return False
        # eth_src = ether_pkt_sc.src
        # print('has IP: ', ether_pkt_sc.haslayer('IP'))
        # print('has UDP: ', ether_pkt_sc.haslayer('UDP'))
        if not ether_pkt_sc.haslayer('IP'):
            print(fmt.format(*ans_list),file=fh_csv)
            return True
        else:
            ip_pkt_sc = ether_pkt_sc[IP]

    # src & dst MAC
    ans_list[15] = ether_pkt_sc.src
    ans_list[16] = ether_pkt_sc.dst
    # srcIP
    ans_list[1] = ip_pkt_sc.src
    # dstIP
    ans_list[3] = ip_pkt_sc.dst
    if ip_pkt_sc.version != 4:
        print(fmt.format(*ans_list),file=fh_csv)
        return True
    # ipv4
    # protocol

    ans_list[5] = pkt_sc[9 + eth_length]
    # len
    ans_list[14] = ip_pkt_sc.len
    # ip_ihl
    ans_list[6] = ip_pkt_sc.ihl
    # ip_tos
    ans_list[7] = ip_pkt_sc.tos
    # ip_flags
    ans_list[8] = pkt_sc[6 + eth_length] >> 5
    # ip_ttl
    ans_list[9] = ip_pkt_sc.ttl
    if ip_pkt_sc.haslayer('UDP'):
        udp_pkt_sc = ip_pkt_sc[UDP]
        ans_list[2] = udp_pkt_sc.sport
        ans_list[4] = udp_pkt_sc.dport
        # udp_len
        ans_list[13] = udp_pkt_sc.len
    elif ip_pkt_sc.haslayer('TCP'):
        tcp_pkt_sc = ip_pkt_sc[TCP]
        ans_list[2] = tcp_pkt_sc.sport
        ans_list[4] = tcp_pkt_sc.dport
        # tcp_window
        ans_list[12] = tcp_pkt_sc.window
        # tcp_flag
        ans_list[11] = pkt_sc[33 + eth_length]
        # tco_dataofs
        ans_list[10] = tcp_pkt_sc.dataofs
    print(fmt.format(*ans_list),file=fh_csv)
    return True
    #--------------------------------------------------

def pcap2csv(in_pcap, out_csv):
    """Main entry function called from main to process the pcap and
    generate the csv file.
    in_pcap = name of the input pcap file (guaranteed to exist)
    out_csv = name of the output csv file (will be created)
    This function walks over each packet in the pcap file, and for
    each packet invokes the render_csv_row() function to write one row
    of the csv.
    """
    frame_num = 0
    ignored_packets = 0
    with open(out_csv, 'w') as fh_csv:
        # Open the pcap file with scapy's RawPcapReader, and iterate over each packet
        # packets = myrdpcap(in_pcap)
        # for packet in packets:
        #     if packet:
        #         frame_num += 1
        #         if not render_csv_row(packet[1], packet[0], fh_csv):
        #             ignored_packets += 1
        for packet in RawPcapReader(in_pcap):
            # print("test", _)
            try:
                if packet:
                    frame_num += 1
                    if not render_csv_row(packet[1], packet[0], fh_csv):
                        ignored_packets += 1
                    if frame_num % 10000 == 0:
                        print(frame_num)
                    # if frame_num >= 2000000:
                    #     break
            except StopIteration:
                # Shouldn't happen because the RawPcapReader iterator should also
                # exit before this happens.
                break

    print('{} packets read, {} packets not written to CSV'.
          format(frame_num, ignored_packets))
#--------------------------------------------------

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
#--------------------------------------------------

def open_source_data_process():
    print('main')
    file_list = file_name_walk('../DataSets/Open-Source/Normal')
    save_root = '../DataSets/Open-Source/normal-packet-level-device'
    # file_list = file_name_walk('../DataSets/Open-Source/Anomaly')
    # save_root = '../DataSets/Open-Source/attack-packet-level-device'
    if not os.path.exists(save_root):
        os.makedirs(save_root)
    file_list.sort()
    for i, file_name in enumerate(file_list):
        # if i != 10:
        #     continue
        # try:
        print(file_name)
        if i < 10:  # for file sort, because '.' > {0-9}
            save_path = save_root + '/file-0{}.csv'.format(i)
        else:
            save_path = save_root + '/file-{}.csv'.format(i)
        print('save to', save_path)
        pcap2csv(file_name, save_path)
        # print(file_name)
        # except:
        #     print('fail to open ', file_name)


def main():
    """Program main entry"""
    # normal_list=os.listdir('../DataSets/Attack_iot_filter/Pcap/')
    normal_list = ['philips_camera','360_camera','ezviz_camera','hichip_battery_camera','mercury_wirecamera','skyworth_camera','tplink_camera','xiaomi_camera']
    normal_list.extend(['aqara_gateway', 'gree_gateway', 'ihorn_gateway', 'tcl_gateway', 'xiaomi_gateway'])
    #normal_list=['IoT attack']
    for type_index, type_name in enumerate(normal_list):
        # file_list = file_name_walk('../DataSets/Attack_iot_filter/Pcap/{:}'.format(type_name))
        # save_root = '../DataSets/Anomaly/attack-packet-level-device/{}'.format(type_name)
        # file_list = file_name_walk('../DataSets/Normal/data/{:}'.format(type_name))
        # save_root = '../DataSets/normal-packet-level-device/{}'.format(type_name)
        file_list = file_name_walk('../NewDataSets/Normal/data/{:}'.format(type_name))
        save_root = '../NewDataSets/normal-packet-level-device/{}'.format(type_name)
        if not os.path.exists(save_root):
            os.makedirs(save_root)
        file_list.sort()
        for i, file_name in enumerate(file_list):
            print(file_name)
            if i<10:# for file sort, because '.' > {0-9}
                save_path = save_root + '/{}-0{}.csv'.format(type_name, i)
            else:
                save_path = save_root+'/{}-{}.csv'.format(type_name, i)
            pcap2csv(file_name, save_path)

#--------------------------------------------------

if __name__ == '__main__':
    main()
    # open_source_data_process()
