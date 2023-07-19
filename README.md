# HorusEye: Realtime IoT Malicious Traffic Detection Framework with Programmable Switches

## Background
The ever growing volume of IoT traffic brings challenges to IoT anomaly detection systems. Existing anomaly detection systems perform all traffic detection on the control plane, which struggles to scale to the growing rates of traffic. In this paper, we propose HorusEye, a high throughput and accurate two-stage anomaly detection framework. In the first stage, preliminary burst-level anomaly detection is implemented on the data plane to exploit its high-throughput capability (e.g., 100Gbps). We design an algorithm that converts a trained iForest model into white list matching rules, and implement the first unsupervised model that can detect unseen attacks on the data plane. The suspicious traffic is then reported to the control plane for further investigation. To reduce the false-positive rate, the control plane carries out the second stage, where more thorough anomaly detection is performed over the reported suspicious traffic using flow-level features and a deep detection model. We implement a prototype of HorusEye and evaluate its performance through a comprehensive set of experiments. The experimental results illustrate that the data plane can detect 99% of the anomalies and offload 76% of the traffic from the control plane. Compared with the state-of-the-art schemes, our framework has superior throughput and detection performance.

## Install
### Environments install
1.  (optional) install TensorRT-8.2.1.8 and relevent packages (graphsurgeon, uff) at <https://developer.nvidia.com/compute/machine-learning/tensorrt/secure/8.2.1/tars/tensorrt-8.2.1.8.linux.x86_64-gnu.cuda-11.4.cudnn8.2.tar.gz>, and install Volksdep (a toolbox for quntization) at <https://github.com/Media-Smart/volksdep>.
2.  conda env create -f iot.yaml

## Project Structure
- control_plane.py is main program, where you can change your hyper-parameter and train and test the framework.  
- iForest_detect.py is Gulliver Tunnel module which achives traffic offloading using isolation forest. Also you can change the hyper-parameter for iForest.  
- load_data.py is called by control_plane.py to load data from file.  
- convert_model.py is model quantization module, which can convert the trained model in pytorch into tensorRT engine. (GPU is required)


## Usage:  

### Feature extraction
The extracted data set (used in the article experiment) can be downloaded at
<https://drive.google.com/u/0/uc?id=1N5F_CuHCmMIes0ox_tnzvr3t9yGtItLS&export=download>
(The compressed file needs to be extracted under the project folder).
Also, we can download the original Pcap file at <https://drive.google.com/u/0/uc?id=191CmJYWszlSmIitfid2J53UMYtiaqhhe&export=download> (The compressed file needs to be extracted under the DataSets folder) and re-do the feature extraction.
1.  For burst level feature extraction, in pcap_process packet, python files should be executed in following order (You need to manually change the datasets path in .py files):
    - python3 pcap2csv_attack.py
    - python3 csv_process_attack.py
    - python3 extract_flow_size.py
2.  For flow level feature extraction, run FE.py.
    - python3 FE.py


For example:
- To perform feature extraction for normal data:
  
      1. diff ./pcap2csv_attack.py ./pcap2csv_attack_copy.py 
            174c174
            <         file_list = file_name_walk('../DataSets/Normal/data/{:}'.format(type_name))
            ---
            >         file_list = file_name_walk('../DataSets/Pcap/Normal/{:}'.format(type_name))
            209c209
            <     # main()
            ---
            >     main()
            211c211
            <     roubust_process()
            ---
            >     # roubust_process()

      2. python3 pcap2csv_attack.py

      3. diff ./csv_process_attack.py ./csv_process_attack_copy.py 
            97c97
            <     # main()
            ---
            >     main()
            99c99
            <     roubust_process()
            ---
            >     # roubust_process()
  
      4. python3 csv_process_attack.py

      5. diff ./extract_flow_size.py ./extract_flow_size_copy.py 
            288,289c288,289
            < # main()
            < roubust_process()
            ---
            > main()
            > # roubust_process()

      6. python3 extract_flow_size.py

      7. diff ./FE.py ./FE_copy.py                              
            349c349
            <         file_list = file_name_walk('./DataSets/Normal/data/{:}'.format(type_name))
            ---
            >         file_list = file_name_walk('./DataSets/Pcap/Normal/{:}'.format(type_name))

      8. python3 FE.py

- To perform feature extraction for anomaly data:
  
      1. diff ./pcap2csv_attack.py ./pcap2csv_attack_copy.py      
            168,170c168,170
            <     # normal_list=os.listdir('../DataSets/Attack_iot_filter/Pcap/')
            <     normal_list = ['philips_camera','360_camera','ezviz_camera','hichip_battery_camera','mercury_wirecamera','skyworth_camera','tplink_camera','xiaomi_camera']
            <     normal_list.extend(['aqara_gateway', 'gree_gateway', 'ihorn_gateway', 'tcl_gateway', 'xiaomi_gateway'])
            ---
            >     normal_list=os.listdir('../DataSets/Pcap/Anomaly/')
            >     # normal_list = ['philips_camera','360_camera','ezviz_camera','hichip_battery_camera','mercury_wirecamera','skyworth_camera','tplink_camera','xiaomi_camera']
            >     # normal_list.extend(['aqara_gateway', 'gree_gateway', 'ihorn_gateway', 'tcl_gateway', 'xiaomi_gateway'])
            172,175c172,175
            <         # file_list = file_name_walk('../DataSets/Attack_iot_filter/Pcap/{:}'.format(type_name))
            <         # save_root = '../DataSets/Anomaly/attack-packet-level-device/{}'.format(type_name)
            <         file_list = file_name_walk('../DataSets/Normal/data/{:}'.format(type_name))
            <         save_root = '../DataSets/normal-packet-level-device/{}'.format(type_name)
            ---
            >         file_list = file_name_walk('../DataSets/Pcap/Anomaly/{:}'.format(type_name))
            >         save_root = '../DataSets/Anomaly/attack-packet-level-device/{}'.format(type_name)
            >         # file_list = file_name_walk('../DataSets/Pcap/Normal/{:}'.format(type_name))
            >         # save_root = '../DataSets/normal-packet-level-device/{}'.format(type_name)
            209c209
            <     # main()
            ---
            >     main()
            211c211
            <     roubust_process()
            ---
            >     # roubust_process()
    
      2. python3 pcap2csv_attack.py
    
      3. diff ./csv_process_attack.py ./csv_process_attack_copy.py
            58,60c58,60
            <     normal_list = ['philips_camera','360_camera','ezviz_camera','hichip_battery_camera','mercury_wirecamera','skyworth_camera','tplink_camera','xiaomi_camera']#'philips_camera','360_camera','ezviz_camera','hichip_battery_camera','mercury_wirecamera','skyworth_camera','tplink_camera','xiaomi_camera'
            <     normal_list.extend(['aqara_gateway', 'gree_gateway', 'ihorn_gateway', 'tcl_gateway', 'xiaomi_gateway'])
            <     # normal_list=os.listdir('../DataSets/Attack_iot_filter/Pcap/')
            ---
            >     # normal_list = ['philips_camera','360_camera','ezviz_camera','hichip_battery_camera','mercury_wirecamera','skyworth_camera','tplink_camera','xiaomi_camera']#'philips_camera','360_camera','ezviz_camera','hichip_battery_camera','mercury_wirecamera','skyworth_camera','tplink_camera','xiaomi_camera'
            >     # normal_list.extend(['aqara_gateway', 'gree_gateway', 'ihorn_gateway', 'tcl_gateway', 'xiaomi_gateway'])
            >     normal_list=os.listdir('../DataSets/Pcap/Anomaly/')
            62,65c62,65
            <         # file_list = file_name_walk('../DataSets/Anomaly/attack-packet-level-device/{}'.format(type_name))
            <         # save_root = '../DataSets/Anomaly/attack-dec-feature-device/{}'.format(type_name)
            <         file_list = file_name_walk('../DataSets/normal-packet-level-device/{:}'.format(type_name))
            <         save_root = '../DataSets/normal-dec-feature-device/{}'.format(type_name)
            ---
            >         file_list = file_name_walk('../DataSets/Anomaly/attack-packet-level-device/{}'.format(type_name))
            >         save_root = '../DataSets/Anomaly/attack-dec-feature-device/{}'.format(type_name)
            >         # file_list = file_name_walk('../DataSets/normal-packet-level-device/{:}'.format(type_name))
            >         # save_root = '../DataSets/normal-dec-feature-device/{}'.format(type_name)
            97c97
            <     # main()
            ---
            >     main()
            99c99
            <     roubust_process()
            ---
            >     # roubust_process()
    
      4. python3 csv_process_attack.py
    
      5. diff ./extract_flow_size.py ./extract_flow_size_copy.py  
            239,241c239,241
            <     normal_list = ['philips_camera','360_camera','ezviz_camera','hichip_battery_camera','mercury_wirecamera','skyworth_camera','tplink_camera','xiaomi_camera']#'philips_camera','360_camera','ezviz_camera','hichip_battery_camera','mercury_wirecamera','skyworth_camera','tplink_camera','xiaomi_camera'
            <     normal_list.extend(['aqara_gateway', 'gree_gateway', 'ihorn_gateway', 'tcl_gateway', 'xiaomi_gateway'])
            <     # normal_list=os.listdir('../DataSets/Attack_iot_filter/Pcap/')
            ---
            >     # normal_list = ['philips_camera','360_camera','ezviz_camera','hichip_battery_camera','mercury_wirecamera','skyworth_camera','tplink_camera','xiaomi_camera']#'philips_camera','360_camera','ezviz_camera','hichip_battery_camera','mercury_wirecamera','skyworth_camera','tplink_camera','xiaomi_camera'
            >     # normal_list.extend(['aqara_gateway', 'gree_gateway', 'ihorn_gateway', 'tcl_gateway', 'xiaomi_gateway'])
            >     normal_list=os.listdir('../DataSets/Pcap/Anomaly/')
            250,253c250,253
            <         # file_list = file_name_walk('../DataSets/Anomaly/attack-dec-feature-device/{}'.format(type_name))
            <         # save_root = '../DataSets/Anomaly/attack-flow-level-device_{}_dou_burst_{}_add_pk/{}'.format(str(thr_time),pk_thr,type_name)
            <         file_list = file_name_walk('../DataSets/normal-dec-feature-device/{}'.format(type_name))
            <         save_root = '../DataSets/normal-flow-level-device_{}_dou_burst_{}_add_pk/{}'.format(str(thr_time),pk_thr,type_name)
            ---
            >         file_list = file_name_walk('../DataSets/Anomaly/attack-dec-feature-device/{}'.format(type_name))
            >         save_root = '../DataSets/Anomaly/attack-flow-level-device_{}_dou_burst_{}_add_pk/{}'.format(str(thr_time),pk_thr,type_name)
            >         # file_list = file_name_walk('../DataSets/normal-dec-feature-device/{}'.format(type_name))
            >         # save_root = '../DataSets/normal-flow-level-device_{}_dou_burst_{}_add_pk/{}'.format(str(thr_time),pk_thr,type_name)
            288,289c288,289
            < # main()
            < roubust_process()
            ---
            > main()
            > # roubust_process()
    
      6. python3 extract_flow_size.py

      7. diff ./FE.py ./FE_copy.py
            342,345c342,345
            <     # normal_list = os.listdir('./DataSets/Attack_iot_filter/Pcap/')
            <     normal_list = ['philips_camera','360_camera','ezviz_camera','hichip_battery_camera','mercury_wirecamera',
            <                    'skyworth_camera','tplink_camera','xiaomi_camera','aqara_gateway','gree_gateway','ihorn_gateway',
            <                    'tcl_gateway','xiaomi_gateway']
            ---
            >     normal_list = os.listdir('./DataSets/Pcap/Anomaly/')
            >     # normal_list = ['philips_camera','360_camera','ezviz_camera','hichip_battery_camera','mercury_wirecamera',
            >     #                'skyworth_camera','tplink_camera','xiaomi_camera','aqara_gateway','gree_gateway','ihorn_gateway',
            >     #                'tcl_gateway','xiaomi_gateway']
            347,350c347,350
            <         # file_list = file_name_walk('./DataSets/Attack_iot_filter/Pcap/{:}'.format(type_name))
            <         # save_root = './DataSets/Anomaly/attack_kitsune/{}'.format(type_name)
            <         file_list = file_name_walk('./DataSets/Normal/data/{:}'.format(type_name))
            <         save_root = './DataSets/normal-kitsune_test/{}'.format(type_name)
            ---
            >         file_list = file_name_walk('./DataSets/Pcap/Anomaly/{:}'.format(type_name))
            >         save_root = './DataSets/Anomaly/attack_kitsune/{}'.format(type_name)
            >         # file_list = file_name_walk('./DataSets/Pcap/Normal/{:}'.format(type_name))
            >         # save_root = './DataSets/normal-kitsune_test/{}'.format(type_name)

      8. python3 FE.py
      

### Training and testing
![image](https://github.com/vicTorKd/HorusEye/assets/81010941/cf9c2e02-ae37-49dd-8fd1-0ec18659fc20)
  
 **In addition, you can do more customization by manually setting the hyperparameters in control_plane.py.**

