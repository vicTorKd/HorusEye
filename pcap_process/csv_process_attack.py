import enum
import pandas as pd
from datetime import datetime
import os

PACKET_NUMBER = 5
data_set = "iot_attack"

def file_name_walk(file_dir):
    file_list = []
    for root, dirs, files in os.walk(file_dir):
        for file in files:
            if os.path.splitext(file)[1] == ".csv":
                file_list.append("{}/{}".format(root, file))
    print(file_list)
    return file_list

def new_extract(inputName, saveName):
    # time srcIP srcPort dstIP dstPort protocol length
    col_names = ["time", "srcIP", "srcPort", "dstIP", "dstPort", "protocol", 
    "ip_ihl", "ip_tos", "ip_flags", "ip_ttl", "tcp_dataofs", "tcp_flag", "tcp_window", 
    "udp_len", "length"]
    # df = pd.read_csv(inputName, delimiter="|", names=col_names, nrows=100)
    tcp = pd.read_csv(inputName, delimiter="|", names=col_names)
    # print(df)
    # print(df)

    #tcp = df.drop(["time"], axis=1)

    tcp["srcAddr1"], tcp["srcAddr2"], tcp["srcAddr3"], tcp["srcAddr4"] = tcp["srcIP"].str.split(".", 3).str
    tcp["dstAddr1"], tcp["dstAddr2"], tcp["dstAddr3"], tcp["dstAddr4"] = tcp["dstIP"].str.split(".", 3).str


    tcp = tcp.drop(["srcIP", "dstIP"], axis=1)

    # grouped=tcp.groupby(["srcIP", "srcPort", "dstIP", "dstPort", "protocol"])
    # result = grouped.head(1)
    tcp.to_csv(saveName, index=False)
    #df = pd.read_csv(saveName)
    #print(df)

def open_source_data_process():
    print('main')
    file_list = file_name_walk('../DataSets/open-source/normal-packet-level-device')
    save_root = '../DataSets/open-source/normal-dec-feature-device'
    if not os.path.exists(save_root):
        os.makedirs(save_root)
    file_list.sort()
    for i, file_name in enumerate(file_list):
        # try:
        print(file_name)
        if i < 10:  # for file sort, because '.' > {0-9}
            save_path = save_root + '/file-0{}.csv'.format(i)
        else:
            save_path = save_root + '/file-{}.csv'.format(i)
        new_extract(file_name, save_path)
        # print(file_name)
        # except:
        #     print('fail to open ', file_name)


def main():
    normal_list = ['skyworth_camera','tplink_camera','xiaomi_camera']#'philips_camera','360_camera','ezviz_camera','hichip_battery_camera','mercury_wirecamera','skyworth_camera','tplink_camera','xiaomi_camera'
    for type_index, type_name in enumerate(normal_list):
        #file_list = file_name_walk('../DataSets/attack/attack-packet-level-device/{}'.format(type_name))
        #save_root = '../DataSets/attack/attack-dec-feature-device/{}'.format(type_name)
        file_list = file_name_walk('../DataSets/our/normal-packet-level-device/{:}'.format(type_name))
        save_root = '../DataSets/our/normal-dec-feature-device/{}'.format(type_name)
        if not os.path.exists(save_root):
            os.makedirs(save_root)

        file_list.sort()
        #print(file_list)
        for i, file_name in enumerate(file_list):
            print(file_name)
            if i < 10:  # for file sort, because '.' > {0-9}
                save_path = save_root + '/{}-0{}.csv'.format(type_name, i)
            else:
                save_path = save_root + '/{}-{}.csv'.format(type_name, i)
            new_extract(file_name, save_path)
            print("finish: {}/{}".format(i, len(file_list)))

if __name__ == '__main__':
    a = datetime.now()
    print("start time", a)
    # main()
    open_source_data_process()
    b = datetime.now()
    print("end time", b)
    durn = (b-a).seconds
    print("duration", durn)
