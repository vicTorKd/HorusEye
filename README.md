# HorusEye: Realtime IoT Malicious Traffic Detection Framework with Programmable Switches

## Background
The ever growing volume of IoT traffic brings challenges to IoT anomaly detection systems. Existing anomaly detection systems perform all traffic detection on the control plane, which struggles to scale to the growing rates of traffic. In this paper, we propose HorusEye, a high throughput and accurate two-stage anomaly detection framework. In the first stage, preliminary burst-level anomaly detection is implemented on the data plane to exploit its high-throughput capability (e.g., 100Gbps). We design an algorithm that converts a trained iForest model into white list matching rules, and implement the first unsupervised model that can detect unseen attacks on the data plane. The suspicious traffic is then reported to the control plane for further investigation. To reduce the false-positive rate, the control plane carries out the second stage, where more thorough anomaly detection is performed over the reported suspicious traffic using flow-level features and a deep detection model. We implement a prototype of HorusEye and evaluate its performance through a comprehensive set of experiments. The experimental results illustrate that the data plane can detect 99% of the anomalies and offload 76% of the traffic from the control plane. Compared with the state-of-the-art schemes, our framework has superior throughput and detection performance.

## Install
### Environments install
1.  (optional) install TensorRT-8.2.1.8 at <https://developer.nvidia.com/compute/machine-learning/tensorrt/secure/8.2.1/local_repos/nv-tensorrt-repo-ubuntu2004-cuda11.4-trt8.2.1.8-ga-20211117_1-1_amd64.deb>, and install Volksdep at <https://github.com/Media-Smart/volksdep>
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
Also, we can download the original Pcap file at <https://drive.google.com/u/0/uc?id=191CmJYWszlSmIitfid2J53UMYtiaqhhe&export=download> and re-do the feature extraction.
1.  For burst level feature extraction, in pcap_process packet, python files should be executed in following order:
    - pcap2csv_attack.py
    - csv_process_attack.py
    - extract_flow_size.py
2.  For flow level feature extraction, run FE.py.  


### Training and testing
![image](https://github.com/vicTorKd/HorusEye/assets/81010941/cf9c2e02-ae37-49dd-8fd1-0ec18659fc20)
  
 **In addition, you can do more customization by manually setting the hyperparameters in control_plane.py.**

