# HorusEye: Realtime IoT Malicious Traffic Detection Framework with Programmable Switches

## Background
The ever-increasing IoT traffic in smart cities brings high throughput challenges to anomaly detection systems. However, the existing anomaly detection systems put all traffic detection on the control plane, which can not keep up with the trend of traffic growth. Thus, we propose a novel IoT anomaly detection framework named HorusEye, including Gulliver Tunnel deployed on the data plane and Magnifier deployed on the control plane. Gulliver Tunnel realizes traffic offloading based on the low-cost and high-throughput capability of the programmable switch (e.g., 100Gbps). Thus, the server does not need to perform an in-depth detection of all traffic, meeting the challenges of future traffic surges. Magnifier rechecks
the anomalies considered by Gulliver Tunnel to reduce the false-positive rate. In Gulliver Tunnel, we design an algorithm for iForest to convert to rules and implement the first unsupervised model that can detect zero-day attacks on the data plane. We also design a new flow feature extraction scheme (e.g., truncate burst, bi-hash, double hash-table) to reduce the resource occupancy on the switch. In Magnifier, we adopt asymmetric model structure, separable convolution, dilated convolution, and model quantization to achieve a high-throughput, low-false positive deep detection model. 

## Install
### Environments install
conda env create -f iot.yaml
## Usage:  

### Feature extraction
Partial data set(used in the demo code) can be downloaded at    
<https://drive.google.com/uc?export=download&id=1paCO5dzxdVXgq49S5NkGkYQw_UaumE8a>.   
(Due to privacy concerns, our raw pcap files will be processed and uploaded after the article is accepted.)
1.  For burst level feature extraction, in pcap_process packet, python files should be executed in following order:
    - pcap2csv.py
    - csv_process.py
    - extract_flow_size.py
2.  For flow level feature extraction, run FE.py.  


### Training and testing
- control_plane.py is main program, where you can change your hyper-parameter and train and test the framework.  
- iForest_detect.py is Gulliver Tunnel module which achives traffic offloading using isolation forest. Also you can change the hyper-parameter for iForest.  
- load_data.py is called by control_plane.py to load data from file.  
- convert_model.py is model quantization module, which can convert the trained model in pytorch into tensorRT engine. (GPU is required)

