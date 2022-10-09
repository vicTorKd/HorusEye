# Check if cython code has been compiled
import os
import subprocess

use_extrapolation = False  # experimental correlation code
if use_extrapolation:
    print("Importing AfterImage Cython Library")
    if not os.path.isfile("AfterImage.c"):  # has not yet been compiled, so try to do so...
        cmd = "python setup.py build_ext --inplace"
        subprocess.call(cmd, shell=True)
# Import dependencies
import netStat as ns
import csv
import numpy as np

print("Importing Scapy Library")
from scapy.all import *
import os.path
import platform
import subprocess
import hashlib  # fix the hash


# Extracts Kitsune features from given pcap file one packet at a time using "get_next_vector()"
# If wireshark is installed (tshark) it is used to parse (it's faster), otherwise, scapy is used (much slower).
# If wireshark is used then a tsv file (parsed version of the pcap) will be made -which you can use as your input next time
class FE:
    def __init__(self, file_path, limit=np.inf):
        self.path = file_path
        self.limit = limit
        self.parse_type = None  # unknown
        self.curPacketIndx = 0
        self.tsvin = None  # used for parsing TSV file
        self.scapyin = None  # used for parsing pcap with scapy
        ### Prep pcap ##
        self.__prep__()

        ### Prep Feature extractor (AfterImage) ###
        maxHost = 100000000000
        maxSess = 100000000000
        self.nstat = ns.netStat(np.nan, maxHost, maxSess)

    def _get_tshark_path(self):
        if platform.system() == 'Windows':
            return 'C:\Program Files\Wireshark\\tshark.exe'
        else:
            system_path = os.environ['PATH']
            for path in system_path.split(os.pathsep):
                filename = os.path.join(path, 'tshark')
                if os.path.isfile(filename):
                    return filename
        return ''

    def __prep__(self):
        ### Find file: ###
        if not os.path.isfile(self.path):  # file does not exist
            print("File: " + self.path + " does not exist")
            raise Exception()

        ### check file type ###
        type = self.path.split('.')[-1]

        self._tshark = self._get_tshark_path()
        ##If file is pcap
        if type == "pcap":
            self.parse_type = "scapy"
        else:
            print("File: " + self.path + " is not a tsv or pcap file")
            raise Exception()

        ### open readers ##
        if self.parse_type == "tsv":
            maxInt = sys.maxsize
            decrement = True
            while decrement:
                # decrease the maxInt value by factor 10
                # as long as the OverflowError occurs.
                decrement = False
                try:
                    csv.field_size_limit(maxInt)
                except OverflowError:
                    maxInt = int(maxInt / 10)
                    decrement = True

            print("counting lines in file...")
            num_lines = sum(1 for line in open(self.path))
            print("There are " + str(num_lines) + " Packets.")
            self.limit = min(self.limit, num_lines - 1)
            self.tsvinf = open(self.path, 'rt', encoding="utf8")
            self.tsvin = csv.reader(self.tsvinf, delimiter='\t')
            row = self.tsvin.__next__()  # move iterator past header

        else:  # scapy
            print("Reading PCAP file via Scapy...")
            self.scapyin = rdpcap(self.path)
            self.limit = len(self.scapyin)
            print("Loaded " + str(self.limit) + " Packets.")

    def packet_filter(self, p):
        if Ether not in p or bool(1 - (IP in p or IPv6 in p)):
            print('no ether')
            return True
        if TCP not in p and UDP not in p:
            print('no TCP or UDP')
            return True
        if DNS in p or NTP in p or DHCP in p:
            print('DNS or NTP')
            return True
        try:
            if p[TCP].sport == 13511 or p[TCP].dport == 13511 or \
                    p[TCP].sport == 137 or p[TCP].dport == 137 or \
                    p[TCP].sport == 123 or p[TCP].dport == 123:
                return True
        except IndexError:
            pass
        try:
            if p[UDP].dport == 1900:
                return True
        except IndexError:
            pass
        return False

    def get_next_vector(self):
        if self.curPacketIndx == self.limit:
            if self.parse_type == 'tsv':
                self.tsvinf.close()
            return []
        srcport, dstport, proto = 0, 0, 0

        ### Parse next packet ###

        if self.parse_type == "scapy":
            packet = self.scapyin[self.curPacketIndx]
            IPtype = np.nan
            timestamp = packet.time
            framelen = len(packet)
            if packet.haslayer(IP):  # IPv4
                srcIP = packet[IP].src
                dstIP = packet[IP].dst
                proto = packet.proto
                IPtype = 0
            elif packet.haslayer(IPv6):  # ipv6
                srcIP = packet[IPv6].src
                dstIP = packet[IPv6].dst
                IPtype = 1
            else:
                srcIP = ''
                dstIP = ''

            if packet.haslayer(TCP):
                srcproto = str(packet[TCP].sport)
                dstproto = str(packet[TCP].dport)
                srcport, dstport = packet[TCP].sport, packet[TCP].dport


            elif packet.haslayer(UDP):
                srcproto = str(packet[UDP].sport)
                dstproto = str(packet[UDP].dport)
                srcport, dstport = packet[UDP].sport, packet[UDP].dport
            else:
                srcproto = ''
                dstproto = ''

            srcMAC = packet.src
            dstMAC = packet.dst
            if srcproto == '':  # it's a L2/L1 level protocol
                if packet.haslayer(ARP):  # is ARP
                    srcproto = 'arp'
                    dstproto = 'arp'
                    srcIP = packet[ARP].psrc  # src IP (ARP)
                    dstIP = packet[ARP].pdst  # dst IP (ARP)
                    IPtype = 0
                elif packet.haslayer(ICMP):  # is ICMP
                    srcproto = 'icmp'
                    dstproto = 'icmp'
                    IPtype = 0
                elif srcIP + srcproto + dstIP + dstproto == '':  # some other protocol
                    srcIP = packet.src  # src MAC
                    dstIP = packet.dst  # dst MAC
        else:
            return []

        self.curPacketIndx = self.curPacketIndx + 1

        ### Extract Features
        try:
            # print(str([srcIP, srcport, proto]))
            h1 = hashlib.md5(str([srcIP, srcport, proto]).encode('utf-8'))
            h2 = hashlib.md5(str([dstIP, dstport, proto]).encode('utf-8'))
            hash_sum = int.from_bytes(h1.digest(), byteorder='big') + int.from_bytes(h2.digest(), byteorder='big')
            return np.append(np.array(hash_sum),
                             self.nstat.updateGetStats(IPtype, srcMAC, dstMAC, srcIP, srcproto, dstIP, dstproto,
                                                       int(framelen), float(timestamp)))
        except Exception as e:
            print(e)
            return []

    def pcap2tsv_with_tshark(self):
        print('Parsing with tshark...')
        fields = "-e frame.time_epoch -e frame.len -e eth.src -e eth.dst -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e udp.srcport -e udp.dstport -e icmp.type -e icmp.code -e arp.opcode -e arp.src.hw_mac -e arp.src.proto_ipv4 -e arp.dst.hw_mac -e arp.dst.proto_ipv4 -e ipv6.src -e ipv6.dst"
        cmd = '"' + self._tshark + '" -r ' + self.path + ' -T fields ' + fields + ' -E header=y -E occurrence=f > ' + self.path + ".tsv"
        subprocess.call(cmd, shell=True)
        print("tshark parsing complete. File saved as: " + self.path + ".tsv")

    def get_num_features(self):
        return len(self.nstat.getNetStatHeaders())

    def dump_csv(self, save_path):

        csv_file = open(save_path, 'w')
        writer = csv.writer(csv_file)
        i = 0
        print(self.limit)
        while i < self.limit:
            i += 1
            x = self.get_next_vector()
            if x is None:
                continue
            if (len(x) == 0):
                continue
            writer.writerow(x)

        csv_file.close()


def file_name_walk(file_dir):
    file_list = []
    for root, dirs, files in os.walk(file_dir):
        for file in files:
            if os.path.splitext(file)[1] == ".pcap":
                file_list.append("{}/{}".format(root, file))
    print(file_list)
    return file_list


def open_source_data_process():
    packet_limit = np.Inf  # the number of packets to process
    # file_list = file_name_walk('./DataSets/Open-Source/Normal')
    # save_root = './DataSets/Open-Source/normal_kitsune'
    file_list = file_name_walk('./DataSets/Open-Source/Anomaly')
    save_root = './DataSets/Open-Source/attack_kitsune'
    if not os.path.exists(save_root):
        os.makedirs(save_root)
    file_list.sort()
    for i, file_name in enumerate(file_list):
        # try:
        print('processing PCAP: {}...'.format(file_name))
        handler = FE(file_name, packet_limit)
        if i < 10:  # for file sort, because '.' > {0-9}
            save_path = save_root + '/file-0{}.csv'.format(i)
        else:
            save_path = save_root + '/file-{}.csv'.format(i)
        # save_path = save_root + '/normal-{}.csv'.format(i)
        # print(file_name)
        handler.dump_csv(save_path)
        # except:
        #     print('fail to open ', file_name)


if __name__ == '__main__':
    packet_limit = np.Inf  # the number of packets to process

    normal_list = os.listdir('./DataSets/Attack_iot_filter/Pcap/')
    #normal_list = ['ezviz_camera','hichip_battery_camera','mercury_wirecamera','skyworth_camera','tplink_camera','xiaomi_camera']#'philips_camera','360_camera','ezviz_camera','hichip_battery_camera','mercury_wirecamera','skyworth_camera','tplink_camera','xiaomi_camera'
    for type_index, type_name in enumerate(normal_list):
        file_list = file_name_walk('./DataSets/Attack_iot_filter/Pcap/{:}'.format(type_name))
        save_root = './DataSets/Anomaly/attack_kitsune/{}'.format(type_name)
        #file_list = file_name_walk('./DataSets/Normal/data/{:}'.format(type_name))
        #save_root = './DataSets/normal-kitsune_test/{}'.format(type_name)
        if not os.path.exists(save_root):
            os.makedirs(save_root)
        file_list.sort()
        for i, file_name in enumerate(file_list):
            # try:
            handler = FE(file_name, packet_limit)

            print(f'processing PCAP: {file_name}...')
            if i < 10:  # for file sort, because '.' > {0-9}
                save_path = save_root + '/{}-0{}.csv'.format(type_name, i)
            else:
                save_path = save_root + '/{}-{}.csv'.format(type_name, i)

            #print(file_name)

            handler.dump_csv(save_path)
            if(i>10):
                break
            # except:
            #     print('fail to open ', file_name)

    # open_source_data_process()  # for open source data
