from re import T
import torch
import torch.utils.data as Data
from sklearn import preprocessing
from volksdep.calibrators import EntropyCalibrator2
from volksdep.converters import load
from volksdep.converters import save
from volksdep.converters import torch2trt
from volksdep.datasets import CustomDataset

from load_data import *
from model import CNN_AE

os.environ["CUDA_VISIBLE_DEVICES"] = '0,1,2,3'


def setup_seed(seed):
    torch.manual_seed(seed)
    torch.cuda.manual_seed_all(seed)
    np.random.seed(seed)
    import os
    import random
    random.seed(seed)
    os.environ['PYTHONHASHSEED'] = str(seed)
    torch.manual_seed(seed)
    torch.cuda.manual_seed(seed)
    torch.backends.cudnn.benchmark = False
    torch.backends.cudnn.deterministic = True


setup_seed(20)


def excute_RMSE(input, target):
    mse = (input - target).pow(2).sum(2) / INPUT_SIZE
    rmse = torch.sqrt(mse)
    return rmse.detach().cpu().numpy().reshape(-1)  # 0 :error 1:normal


def calibration_data_processing(data, data_num=100):
    scaler = preprocessing.MinMaxScaler()
    data = data.drop(columns=[0, 'class']).values
    np.random.shuffle(data)
    data = data[:data_num, ]
    data = scaler.fit_transform(data)
    data = data[:, np.newaxis, :]
    data = torch.tensor(data, dtype=torch.float32)
    print(data.dtype)
    return data


def test_data_processing(df):  # for testing
    scaler = preprocessing.MinMaxScaler()
    X, y = df.drop(columns=['class', 0]), df['class']  # 0 is for hash key
    X, y = X.values, y.values

    X = scaler.fit_transform(X)

    X = X[:, np.newaxis, :]
    X = torch.tensor(X, dtype=torch.float32)
    y = torch.tensor(y)
    return X, y


def test_throughput(test_model, BATCH_SIZE, X):
    begin = time.time()
    pk_num = BATCH_SIZE
    print('begin')
    with torch.no_grad():
        test_model.eval()
        total_ = 0
        for i in range(0, X.shape[0], pk_num):
            b_x = X[i:i + pk_num].cuda()
            temp_x = test_model(b_x)
            temp_y = excute_RMSE(temp_x, b_x)
            total_ = i + pk_num
    end = time.time()
    memory = torch.cuda.memory_allocated(device=0)
    print('total exc pk_num', total_)
    print('throughput is {:} pk/s'.format(total_ / (end - begin)))
    print('memory is {:} MB/s'.format((memory / 1024)))
    print('time cost', end - begin)


if __name__ == "__main__":
    model_save_path = './params/CNN_DW_dilation.pkl'
    tensorrt_save_path = './params/tensorrt_int8_CNN_DW_dilation.engine'
    onnx_save_path = './params/onnx_model.onnx'

    # Hyper parameters
    CONVERT = True
    # BATCH_SIZE = 40000  # for fp32/fp16 mode
    BATCH_SIZE = 8600  # for int8 trt mode
    INPUT_SIZE = 100
    CALIBRATION_SIZE = 4000000
    CHANNEL_SIZE = 1
    torch.cuda.set_device(0)
    dummy_input = torch.ones(BATCH_SIZE, CHANNEL_SIZE, INPUT_SIZE).cuda()
    device_list_camera = ['philips_camera', '360_camera', 'ezviz_camera', 'hichip_battery_camera', 'mercury_wirecamera',
                   'skyworth_camera', 'tplink_camera',
                   'xiaomi_camera']  # ,'360_camera','ezviz_camera','hichip_battery_camera','mercury_wirecamera',
                                     # 'skyworth_camera','tplink_camera','xiaomi_camera'
    device_list_gateway = ['aqara_gateway', 'gree_gateway', 'ihorn_gateway', 'tcl_gateway', 'xiaomi_gateway']

    if CONVERT:
        model = CNN_AE(input_size=INPUT_SIZE)
        if torch.cuda.is_available():
            model.cuda()
        print("model loading...")
        model.load_state_dict(torch.load(model_save_path), strict=False)
        print("model loaded successfully")

        # build trt model and provided calibration data using EntropyCalibrator2

        # create calibrator
        df_normal_train = load_iot_data_seq(device_list=device_list_camera, begin=0, end=4)
        df_normal_train = df_normal_train.append(load_iot_data_seq(device_list=device_list_gateway, begin=0, end=4))
        df_data = df_normal_train
        tensor_calibration = calibration_data_processing(df_data, len(df_data))
        int8_calibrator = EntropyCalibrator2(CustomDataset(tensor_calibration), batch_size=int(len(df_data)))

        # build trt model
        print("model converting...")
        trt_model = torch2trt(
            model=model,  # model (torch.nn.Module): PyTorch model.
            dummy_input=dummy_input,  # dummy_input (torch.Tensor, tuple or list): dummy input.
            log_level='INFO',  # log_level (string, default is ERROR): TensorRT logger level,
                                # INTERNAL_ERROR, ERROR, WARNING, INFO, VERBOSE are support.
            max_batch_size=BATCH_SIZE,  # max_batch_size (int, default=1): The maximum batch size which can be
                                        # used at execution time, and also the batch size for which the
                                        # ICudaEngine will be optimized.
            min_input_shapes=None,  # min_input_shapes (list, default is None): Minimum input shapes, should
                                    # be provided when shape is dynamic. For example, [(3, 224, 224)] is
                                    # for only one input.
            max_input_shapes=None,  # max_input_shapes (list, default is None): Maximum input shapes, should
                                    # be provided when shape is dynamic. For example, [(3, 224, 224)] is
                                    # for only one input.
            max_workspace_size=8,  # max_workspace_size (int, default is 1): The maximum GPU temporary
                                   # memory which the ICudaEngine can use at execution time. default is 1GB.
            fp16_mode=False,  # fp16_mode (bool, default is False): Whether or not 16-bit kernels are
                              # permitted. During engine build fp16 kernels will also be tried when
                              # this mode is enabled.
            strict_type_constraints=False,  # strict_type_constraints (bool, default is False): When strict type
                                            # constraints is set, TensorRT will choose the type constraints that
                                            # conforms to type constraints. If the flag is not enabled higher
                                            # precision implementation may be chosen if it results in higher
                                            # performance.
            int8_mode=True,  # int8_mode (bool, default is False): Whether Int8 mode is used.
            int8_calibrator=int8_calibrator,  # int8_calibrator (volksdep.calibrators.base.BaseCalibrator, default is
                                   # None): calibrator for int8 mode, if None, default calibrator will
                                   # be used as calibration data.
            opset_version=9,  # opset_version (int, default is 9): Onnx opset version.
            do_constant_folding=True,  # do_constant_folding (bool, default False): If True, the
                                       # constant-folding optimization is applied to the model during
                                       # export. Constant-folding optimization will replace some ops
                                       # that have all constant inputs, with pre-computed constant nodes.
            verbose=True)  # verbose (bool, default False): if specified, we will print out a debug
                           # description of the trace being exported.
        print("model converted successfully")
        # save tensorrt engine
        save(trt_model, tensorrt_save_path)
    else:
        # load tensorrt engine
        trt_model = load(tensorrt_save_path)

        # execute inference
        with torch.no_grad():
            trt_output = trt_model(dummy_input)
            print(trt_output.shape[0])

        # test throughput
        df_attack = load_iot_attack_seq('all')
        df_normal_test_con = load_iot_data_seq(device_list=device_list_camera, begin=4, end=6)
        df_test_con = df_normal_test_con.append(df_attack)
        test_X, test_y = test_data_processing(df_test_con)
        test_throughput(trt_model, BATCH_SIZE, test_X)
