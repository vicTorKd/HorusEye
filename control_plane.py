from fcntl import F_SETFL
import os
import pickle
from re import T
import time
import numpy as np
import torch
import torch.utils.data as Data
from sklearn import preprocessing
from sklearn.metrics import roc_curve, auc, precision_recall_curve, classification_report
from thop import clever_format
from thop import profile
from torch import nn, optim
import iForest_detect
import Kitsune.KitNET as kit
from load_data import *
from model import Magnifier
import warnings
warnings.filterwarnings("ignore")

import argparse
parser = argparse.ArgumentParser(description='Select which experiment to run and whether to train.')
parser.add_argument('--train', dest='train', type=str, default='False', help='Whether to train the model, \'True\' or \'False\'. Default is \'False\'.')
parser.add_argument('--experiment', dest='experiment', type=str, default='A', help='Select which experiment to run, \'A\' is for experiment on our dataset; \'B\' is for experiment on public dataset; \'C\' is for experiment with INT8 model; \'D\' is for robust experiment, after performing robust experiment, retraining Gulliver Tunnel is required. Default is \'A\'.')
parser.add_argument('--horuseye', dest='horuseye', type=str, default='True', help='Whether to use the full HorusEye framework, \'True\' is to use the full HorusEye framework (Magnifier + Gulliver Tunnel); \'False\' is only to use the Magnifier. Default is \'True\'.')
args = parser.parse_args()

os.environ["CUDA_VISIBLE_DEVICES"] = '0,1,2,3'

if not os.path.exists('./params/'):
    os.makedirs('./params/')
if not os.path.exists('./result/'):
    os.makedirs('./result/HorusEye')
    os.makedirs('./result/rmse')
    os.makedirs('./result/Magnifier')
    os.makedirs('./result/Kitsune')

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


def data_processing(df, TWO_D):  # for testing
    if KITSUNE:
        scaler_path = './params/Open-Source/scaler_kitsune.pkl' if OPEN_SOURCE else './params/scaler_kitsune.pkl'
    else:
        scaler_path = './params/Open-Source/scaler.pkl' if OPEN_SOURCE else './params/scaler.pkl'
    scaler = pickle.load(open(scaler_path, 'rb'))
    X, y = df.drop(columns=['class', 0]), df['class']  # 0 is for hash key
    X, y = X.values, y.values

    X = scaler.transform(X)
    if not KITSUNE:
        if TWO_D:
            X = np.pad(X, ((0,0),(3,0)), 'constant')
            index = np.empty((0,0))
            Port_index = np.arange(4,-1,-1).reshape(5,-1)
            MIstat_index = np.arange(5,20).reshape(5,-1)
            HHstat_index = np.arange(20,55).reshape(5,-1)
            HHstat_jit_index = np.arange(55,70).reshape(5,-1)
            HpHpstat_index = np.arange(70,105).reshape(5,-1)
            for i in range(5):
                index = np.append(index, Port_index[i])
                index = np.append(index, MIstat_index[i])
                index = np.append(index, HHstat_index[i])
                index = np.append(index, HHstat_jit_index[i])
                index = np.append(index, HpHpstat_index[i])
            # X = X[:, index.astype(np.int).tolist()].reshape(-1, 1, 5, 20)
            X = X[:, index.astype(np.int).tolist()].reshape(-1, 5, 21)
        else:
            X = X[:, np.newaxis, :]
        X = torch.tensor(X, dtype=torch.float32)
        y = torch.tensor(y)
    return X, y


def train_data_processing_Kitsune(df_normal_train, df_attack_eval):
    # data preparing / transfer data format
    scaler = preprocessing.MinMaxScaler()

    df_normal_train, df_normal_eval = train_test_split(df_normal_train, test_size=0.2, random_state=20)
    X_train = df_normal_train.drop(columns=[0, 'class'])
    X_train = X_train.values
    X_train = scaler.fit_transform(X_train)

    if OPEN_SOURCE:
        if not os.path.exists('./params/Open-Source/'):
            os.makedirs('./params/Open-Source/')
    else:
        if not os.path.exists('./params/'):
            os.makedirs('./params/')

    scaler_path = './params/Open-Source/scaler_kitsune.pkl' if OPEN_SOURCE else './params/scaler_kitsune.pkl'
    pickle.dump(scaler, open(scaler_path, 'wb'))

    # for record loss of the attack / normal
    X_normal_eval, X_attack_eval = df_normal_eval.drop(columns=[0, 'class']), df_attack_eval.drop(columns=[0, 'class'])
    X_normal_eval, X_attack_eval = X_normal_eval.values, X_attack_eval.values
    X_normal_eval = scaler.transform(X_normal_eval)
    X_attack_eval = scaler.transform(X_attack_eval)

    return X_train, X_normal_eval, X_attack_eval


def train_data_processing(df_normal_train, df_attack_eval, TWO_D):
    # data preparing / transfer data format
    scaler = preprocessing.MinMaxScaler()

    df_normal_train, df_normal_eval = train_test_split(df_normal_train, test_size=0.2, random_state=20)

    df_eval = pd.concat([df_normal_eval,df_attack_eval],axis=0)
    X_train, y_train, X_valid, y_valid = df_normal_train.drop(columns=[0, 'class']), df_normal_train[
        'class'], df_eval.drop(columns=[0, 'class']), df_eval['class']
    X_train, y_train, X_valid, y_valid = X_train.values, y_train.values, X_valid.values, y_valid.values
    print(X_train)

    X_train = scaler.fit_transform(X_train)

    if OPEN_SOURCE:
        if not os.path.exists('./params/Open-Source/'):
            os.makedirs('./params/Open-Source/')
    else:
        if not os.path.exists('./params/'):
            os.makedirs('./params/')

    scaler_path = './params/Open-Source/scaler.pkl' if OPEN_SOURCE else './params/scaler.pkl'
    pickle.dump(scaler, open(scaler_path, 'wb'))

    X_valid = scaler.transform(X_valid)

    # for record loss of the attack / normal
    X_normal_eval, X_attack_eval = df_normal_eval.drop(columns=[0, 'class']), df_attack_eval.drop(columns=[0, 'class'])
    X_normal_eval, X_attack_eval = X_normal_eval.values, X_attack_eval.values

    X_normal_eval = scaler.transform(X_normal_eval)
    X_attack_eval = scaler.transform(X_attack_eval)

    if TWO_D:
        # Padding
        X_train = np.pad(X_train, ((0,0),(3,0)), 'constant')
        X_valid = np.pad(X_valid, ((0,0),(3,0)), 'constant')
        X_normal_eval = np.pad(X_normal_eval, ((0,0),(3,0)), 'constant')
        X_attack_eval = np.pad(X_attack_eval, ((0,0),(3,0)), 'constant')
        # Generate index
        index = np.empty((0,0))
        Port_index = np.arange(4,-1,-1).reshape(5,-1)
        MIstat_index = np.arange(5,20).reshape(5,-1)
        HHstat_index = np.arange(20,55).reshape(5,-1)
        HHstat_jit_index = np.arange(55,70).reshape(5,-1)
        HpHpstat_index = np.arange(70,105).reshape(5,-1)
        for i in range(5):
            index = np.append(index, Port_index[i])
            index = np.append(index, MIstat_index[i])
            index = np.append(index, HHstat_index[i])
            index = np.append(index, HHstat_jit_index[i])
            index = np.append(index, HpHpstat_index[i])
        X_train = X_train[:, index.astype(np.int).tolist()].reshape(-1, 5, 21)
        X_valid = X_valid[:, index.astype(np.int).tolist()].reshape(-1, 5, 21)
        X_normal_eval = X_normal_eval[:, index.astype(np.int).tolist()].reshape(-1, 5, 21)
        X_attack_eval = X_attack_eval[:, index.astype(np.int).tolist()].reshape(-1, 5, 21)
    else:
        X_train = X_train[:, np.newaxis, :]
        X_valid = X_valid[:, np.newaxis, :]
        X_normal_eval = X_normal_eval[:, np.newaxis, :]
        X_attack_eval = X_attack_eval[:, np.newaxis, :]
    X_train = torch.tensor(X_train, dtype=torch.float32)
    X_valid = torch.tensor(X_valid, dtype=torch.float32)

    y_train = torch.tensor(y_train)
    y_valid = torch.tensor(y_valid)

    X_normal_eval = torch.tensor(X_normal_eval, dtype=torch.float32)
    X_attack_eval = torch.tensor(X_attack_eval, dtype=torch.float32)
    return X_train, y_train, X_valid, y_valid, X_normal_eval, X_attack_eval


def train_data_processing_numpy(X_normal, X_attack_eval):
    X_normal_train, X_normal_eval = train_test_split(X_normal, test_size=0.2, random_state=20)

    y_train = np.ones(X_normal_train.shape[0])
    y_eval_normal = np.ones(X_normal_eval.shape[0])
    y_eval_attack = np.zeros(df_attack_eval.shape[0])

    y_eval = np.concatenate((y_eval_normal, y_eval_attack))
    X_eval = np.concatenate((X_normal_eval, X_attack_eval), axis=0)

    y_train = torch.tensor(y_train)
    y_eval = torch.tensor(y_eval)

    X_train = torch.tensor(X_normal_train, dtype=torch.float32)
    X_normal_eval = torch.tensor(X_normal_eval, dtype=torch.float32)
    X_attack_eval = torch.tensor(X_attack_eval, dtype=torch.float32)
    X_eval = torch.tensor(X_eval, dtype=torch.float32)

    return X_train, y_train, X_eval, y_eval, X_normal_eval, X_attack_eval


def pred(model, X):
    with torch.no_grad():
        model.eval()
        y = []
        for i in range(0, X.shape[0], 16):
            b_x = X[i:i + 16].cuda()
            temp_x = model(b_x)
            temp_y = model.pred(temp_x, b_x)
            y.extend(temp_y)
            # loss_normal += torch.sqrt(loss_temp)  # RMSE
        # loss_normal = (loss_normal.detach().cpu().numpy() * 16) / i
        # print('the eval noraml loss ', loss_normal)
    return y


def test_throughput(test_model, BATCH_SIZE, X):
    begin = time.time()
    pk_num = BATCH_SIZE
    print('begin')
    with torch.no_grad():
        model.eval()
        total_ = 0
        for i in range(0, X.shape[0], pk_num):
            b_x = X[i:i + pk_num].cuda()
            temp_x = test_model(b_x)
            temp_y = model.excute_RMSE(temp_x, b_x)
            total_ = i + pk_num
    end = time.time()
    memory = torch.cuda.memory_allocated(device=0)
    print('total exc pk_num', total_)
    print('throughput is {:} pk/s'.format(total_ / (end - begin)))
    print('memory is {:} MB/s'.format((memory / 1024)))
    print('time cost', end - begin)


def test(test_model, test_loader):
    begin = time.time()
    with torch.no_grad():
        model.eval()
        correct = 0.
        df_score = []
        rmse_list = []
        eval_y_label = []
        for batch_idx, (data, target) in enumerate(test_loader):
            data = data.cuda()
            eval_output = test_model(data)
            # pred_y = model.pred(eval_output, data, mean_benign,std_benign)
            rmse_eval = model.excute_RMSE(eval_output, data)
            rmse_list.extend(rmse_eval)
            eval_y_label.extend(target)
    end = time.time()
    total_ = len(test_loader) * BATCH_SIZE
    memory = torch.cuda.memory_allocated(device=0)
    print('test_loader')
    print('total exc pk_num', total_)
    print('throughput is {:} pk/s'.format(total_ / (end - begin)))
    print('memory is {:} MB/s'.format((memory / 1024)))
    print('time cost', end - begin)
    return eval_y_label, rmse_list


def train_autoencoder(model, df_normal_train, df_attack_eval, model_save_path, TWO_D):
    # hyper_parameter
    lr = 1e-2
    weight_decay = 0.01
    # weight_decay = 1e-5
    epoches = 20
    INPUTSIZE = 100

    # init
    phi = 0
    beta = 0.1
    # record
    best_testing_acc = 0
    best_epoch = -1
    loss_record = pd.DataFrame(columns=['anomaly_loss', 'normal_loss', 'auc_eval'])
    best_loss_record = pd.DataFrame(columns=['best_auc', 'params', 'macs'])

    # pruning

    # prepocessing
    if type(df_normal_train) is np.ndarray:
        X_train, y_train, X_valid, y_valid, X_normal_eval, X_attack_eval = train_data_processing_numpy(df_normal_train,
                                                                                                       df_attack_eval)
    else:  # Dataframe
        X_train, y_train, X_valid, y_valid, X_normal_eval, X_attack_eval = train_data_processing(df_normal_train,
                                                                                                 df_attack_eval, TWO_D)
    print(X_train.shape)

    train_datasets = Data.TensorDataset(X_train, y_train)
    train_loader = Data.DataLoader(dataset=train_datasets, batch_size=BATCH_SIZE, shuffle=True, num_workers=4)

    test_datasets = Data.TensorDataset(X_valid, y_valid)
    test_loader = Data.DataLoader(dataset=test_datasets, batch_size=BATCH_SIZE, shuffle=True, num_workers=0)

    print("Total number of Epoch: ", epoches)

    # calculate the flops and macs
    with torch.no_grad():
        model.eval()
        input = torch.randn(1, 1, INPUTSIZE)
        if TWO_D:
            # input = input.reshape(1, 1, 5, -1)
            input = input.reshape(1, 5, -1)
        macs, params = profile(model, inputs=(input,))
        macs, params = clever_format([macs, params], "%.3f")
        print("the Params(M) is {:}  the MACs(G) is {:}".format(params, macs))

    criterion = nn.MSELoss()
    optimizier = optim.Adam(model.parameters(), lr=lr, weight_decay=weight_decay)  #
    if torch.cuda.is_available():
        model.cuda()

    for epoch in range(epoches):
        if epoch in [epoches * 0.5, epoches * 1.0]:  # , epoches * 0.5
            for param_group in optimizier.param_groups:
                param_group['lr'] *= 0.1
        # benign_RMSE = []
        model.train()
        for step, (b_x, b_y) in enumerate(train_loader):
            # forward
            b_x = b_x.cuda()
            output = model(b_x)
            loss = criterion(output, b_x)
            loss = torch.sqrt(loss)  # RMSE
            # benign_RMSE.append(loss.detach().cpu().data)
            if (loss > phi):
                phi = loss
            # backward
            optimizier.zero_grad()
            loss.backward()
            optimizier.step()

        eval_y_label, rmse_list = test(model, test_loader)
        # test_throughput(model,X_valid)

        fpr, tpr, thresholds = roc_curve(eval_y_label, rmse_list)
        auc_eval = auc(fpr, tpr)
        print('the auc_eval is ', auc_eval)
        if (best_testing_acc < auc_eval):
            best_epoch = epoch
            best_testing_acc = auc_eval
            print('the best epoch is:', best_epoch)
            print('the best auc is: ', best_testing_acc)
            # save model
            torch.save(model.state_dict(), model_save_path)

        # record eval loss for anomaly and normal
        with torch.no_grad():
            model.eval()
            loss_normal = 0
            for i in range(0, X_normal_eval.shape[0], 16):
                b_x = X_normal_eval[i:i + 16].cuda()
                temp_x = model(b_x)
                loss_temp = criterion(temp_x, b_x)
                loss_normal += loss_temp
                # loss_normal += torch.sqrt(loss_temp)  # RMSE
            loss_normal = (loss_normal.detach().cpu().numpy() * 16) / i
            print('the eval noraml loss ', loss_normal)

            loss_attack = 0
            for i in range(0, X_attack_eval.shape[0], 16):
                b_x = X_attack_eval[i:i + 16].cuda()
                temp_x = model(b_x)
                loss_temp = criterion(temp_x, b_x)
                loss_attack += loss_temp
                # loss_attack += torch.sqrt(loss_temp)  # RMSE
            loss_attack = (loss_attack.detach().cpu().numpy() * 16) / i

        print('the eval attack loss ', loss_attack)

        # record
        loss_record = loss_record.append(
            pd.DataFrame({'anomaly_loss': loss_attack, 'normal_loss': loss_normal, 'auc_eval': auc_eval}, index=[0]))

        print("epoch=", epoch, loss.data.float())
        # print('epoch| {:} best training acc {:}'.format(best_epoch, best_testing_acc))
        # if (epoch + 1) % 5 == 0:
        #     print("epoch: {}, loss is {}".format((epoch + 1), loss.data))

    loss_record_path = './result/Open-Source/loss_record_CNN_DW_dilation.csv' if OPEN_SOURCE \
        else './result/loss_record_CNN_DW_dilation.csv'
    loss_record.to_csv(loss_record_path)
    return model, phi

def test_Kitsune(test_X, test_y,Kitsune_path):
    # test
    K = pickle.load(open(Kitsune_path, 'rb'))
    rmse_test_list = []
    test_y_label = []
    print('begin test throughput')
    begin = time.time()
    for index in range(test_X.shape[0]):
        rmse_eval = K.process(test_X[index,])
        rmse_test_list.append(rmse_eval)
        test_y_label.append(test_y[index,])
    end = time.time()
    total_ = test_X.shape[0]

    print('total exc pk_num', total_)
    print('throughput is {:} pk/s'.format(total_ / (end - begin)))
    print('time cost', end - begin)

    return test_y_label, rmse_test_list

def train_Kitsune(X_train, X_normal_eval, X_attack_eval, Kitsune_path):
    # normal = np.append(X_train, X_normal_eval, axis=0)
    # attack = X_attack_eval

    # KitNET params:
    maxAE = 20  # maximum size for any autoencoder in the ensemble layer
    FMgrace = 5000  # the number of instances taken to learn the feature mapping (the ensemble's architecture)
    ADgrace = X_train.shape[0] - FMgrace
    epoches = 1

    # Build KitNET
    K = kit.KitNET(X_train.shape[1], maxAE, FMgrace, ADgrace)
    normal_label = np.zeros(X_normal_eval.shape[0])
    attack_label = np.ones(X_attack_eval.shape[0])
    label = np.concatenate([normal_label, attack_label], axis=0)

    print("Running KitNET:")
    # start = time.time()
    # Here we process (train/execute) each individual observation.
    # In this way, X is essentially a stream, and each observation is discarded after performing process() method.
    best_epoch = -1
    best_auc = 0
    loss_record = pd.DataFrame(columns=['anomaly_loss', 'normal_loss', 'auc'])
    # model_record = pd.DataFrame(columns=['params', 'FLOPs'])
    for epoch in range(epoches):
        print("epoch= ", epoch)
        RMSE_normal = np.zeros(X_normal_eval.shape[0])
        RMSE_attack = np.zeros(X_attack_eval.shape[0])

        # print("Train......")
        for i in range(FMgrace + ADgrace):
            # if i % 5000 == 0:
            #     print(i)
            if i == 0:
                K.process(X_train[0,], changeState=True)
            else:
                K.process(X_train[i,],
                          changeState=False)  # will train during the grace periods, then execute on all the rest.

        # print("Evaluate normal traffic......")
        for j in range(X_normal_eval.shape[0]):
            # if j % 5000 == 0:
            #     print(j)
            RMSE_normal[j] = K.process(
                X_normal_eval[j,])
        loss_normal = RMSE_normal.mean()

        # print("Evaluate attack traffic......")
        for k in range(X_attack_eval.shape[0]):
            # if k % 5000 == 0:
            #     print(k)
            RMSE_attack[k] = K.process(
                X_attack_eval[k,])
        loss_attack = RMSE_attack.mean()

        RMSE_list = np.concatenate([RMSE_normal, RMSE_attack], axis=0)
        fpr, tpr, thresholds = roc_curve(label, RMSE_list)
        auc_eval = auc(fpr, tpr)
        if auc_eval > best_auc:
            best_auc = auc_eval
            best_epoch = epoch
            pickle.dump(K,open(Kitsune_path, 'wb'))

        loss_record = loss_record.append(pd.DataFrame({'anomaly_loss': loss_attack, 'normal_loss': loss_normal,
                                                       'auc': auc_eval}, index=[0]))

        print('the eval normal loss is ', loss_normal)
        print('the eval attack loss is ', loss_attack)
        print('the auc_eval is ', auc_eval)
        print('the best epoch is ', best_epoch)
        print('the best auc is ', best_auc)

    loss_record.to_csv('./result/Kitsune_loss_record_test.csv')

    return


if __name__ == "__main__":
    # Hyper parameters
    # network and training
    KITSUNE = False
    OPEN_SOURCE =False
    TRAIN = False
    TEST_ROBUST=False
    TEST = True
    Use_filter = True
    Per_Attack=True
    Test_Throughput=True
    PORT = True
    TWO_D = True
    BATCH_SIZE = 256
    TEST_BATCH_SIZE =60000  # for int8 trt model
    INPUTSIZE = 105
    INT8 = False  # using int8 model after quntization

    if args.train == 'True':
        TRAIN = True
    elif args.train == 'False':
        pass
    else:
        print('The train parameter is illegal, please check. Run without training by default. Use -h for more detailed instructions.')
    if args.horuseye == 'True':
        pass
    elif args.horuseye == 'False':
        Use_filter = False
    else:
        print('The horuseye parameter is illegal, please check. Run full HorueEye framework by default. Use -h for more detailed instructions.')
    if args.experiment == 'A':
        pass
    elif args.experiment == 'B':
        OPEN_SOURCE = True
    elif args.experiment == 'C':
        try:
            from volksdep.converters import load
            INT8 = True
        except:
            print('The volksdep library or TensorRT is misconfigured, please check. Run on non-INT8 mode by default. Use -h for more detailed instructions.')
    elif args.experiment == 'D':
        TEST = False
        TEST_ROBUST = True
    else:
        print('The experiment parameter is illegal, please check. Run experiment A by default. Use -h for more detailed instructions.')

    if TWO_D:
        PORT = True
    if KITSUNE:
        PORT = False
        TWO_D = False
        # if Per_Attack:
        #     Test_Throughput = False

    # Pytorch model path
    if OPEN_SOURCE:
        model_save_path = './params/Open-Source/CNN_DW_dilation_channel_port.pkl'
    else:
        model_save_path = './params/CNN_DW_dilation_channel_port.pkl'



    # TensorRT model path
    tensorrt_save_path = './params/tensorrt_int8_CNN_DW_dilation_channel_port'+ str(TEST_BATCH_SIZE)+'.engine'

    # Kitsune model path
    Kitsune_save_path = './params/Open-Source/Kitsune_model.pkl' if OPEN_SOURCE \
        else './params/Kitsune_model.pkl'

    #attack dataset path
    attack_path = './DataSets/Anomaly/attack_kitsune/'

    torch.cuda.set_device(0)
    device_list_gateway = ['aqara_gateway', 'gree_gateway', 'ihorn_gateway', 'tcl_gateway', 'xiaomi_gateway', 'linksys_router']
    device_list_camera = ['philips_camera', '360_camera', 'ezviz_camera', 'hichip_battery_camera', 'mercury_wirecamera',
                   'skyworth_camera', 'tplink_camera', 'xiaomi_camera']

    # model
    if not KITSUNE:
        model = Magnifier(input_size=INPUTSIZE)

    # feature in data plane
    feature_set = ['pk_num', 'sum_len']
    if TRAIN or not Per_Attack:
        print('loading attack data...')
        df_attack = load_iot_attack_seq('all')
        df_attack_test_data = load_iot_attack(attack_name='all', thr_time=1)
        df_attack_eval_data = load_iot_attack(attack_name='http_ddos', thr_time=1)
        df_attack_test = iForest_detect.filter(df_attack_test_data, df_attack)
        df_attack_eval = iForest_detect.filter(df_attack_eval_data, df_attack)
        print('attack test', df_attack_test_data.shape)
        print('attack eval', df_attack_eval_data.shape)
        # if not PORT:
        #     df_attack_test = df_attack_test.drop(columns=[1, 2])
        #     df_attack_eval = df_attack_eval.drop(columns=[1, 2])

    if TRAIN:
        # train iForest to data plane
        print('loading training data...')
        if OPEN_SOURCE:
            df_normal_train_data = open_source_load_iot_data(thr_time=1, selected_list=[0, 2, 4, 6, 7])
        else:
            df_normal_train_data = load_iot_data(device_list=device_list_camera, thr_time=1, begin=0, end=4)
            df_normal_train_data = df_normal_train_data.append(load_iot_data(device_list=device_list_gateway, thr_time=1, begin=0, end=4))
        print(df_normal_train_data.shape)
        df_normal_train, df_normal_eval = train_test_split(df_normal_train_data, test_size=0.2, random_state=20)
        print(df_normal_train.shape)
        iForest_detect.train('all', feature_set, df_normal_train, df_normal_eval, df_attack_eval_data)

        # threshold eval
        df_eval_data = df_normal_eval.append(df_attack_eval_data)
        df_eval_with_pred = iForest_detect.test(['all'], feature_set, df_eval_data)
        iForest_detect.get_Anomaly_ID_test(df_eval_with_pred, df_eval_data)

        # train AE
        if OPEN_SOURCE:
            df_normal_train = open_source_load_iot_data_seq(selected_list=[0, 2, 4, 6, 7])
        else:
            df_normal_train = load_iot_data_seq(device_list=device_list_camera, begin=0, end=4)
            df_normal_train = df_normal_train.append(load_iot_data_seq(device_list=device_list_gateway, begin=0, end=4))
        if not PORT:
            df_normal_train = df_normal_train.drop(columns=[1, 2])
        if KITSUNE:
            # Kitsune data preprocess
            X_train, X_normal_eval, X_attack_eval = train_data_processing_Kitsune(df_normal_train, df_attack_eval)
            # train and test Kitsune
            train_Kitsune(X_train, X_normal_eval, X_attack_eval, Kitsune_save_path)
        else:
            auto, phi = train_autoencoder(model, df_normal_train, df_attack_eval, model_save_path, TWO_D)

    if TEST:  # for test
        # control plane
        if torch.cuda.is_available() and not KITSUNE and not INT8:
            model.cuda()
        print('loading testing data...')
        if OPEN_SOURCE:
            df_normal_test_con = open_source_load_iot_data_seq(selected_list=[1, 3, 5, 8])
        else:
            df_normal_test_con = load_iot_data_seq(device_list=device_list_camera, begin=4, end=6)
            df_normal_test_con = df_normal_test_con.append(load_iot_data_seq(device_list=device_list_gateway, begin=4, end=6))
        # data plane
        if OPEN_SOURCE:
            df_normal_test_data = open_source_load_iot_data(thr_time=1, selected_list=[1, 3, 5, 8])
        else:
            df_normal_test_data = load_iot_data(device_list=device_list_camera, thr_time=1, begin=4, end=6)  # the feature used in data plane
            df_normal_test_data = df_normal_test_data.append(load_iot_data(device_list=device_list_gateway, thr_time=1, begin=4, end=6))


        if Per_Attack: #test for per attack or not
            attack_list = os.listdir(attack_path)
            # Downsampling 10% for normal traffic, avoiding metric bias.
            drop_data, df_normal_test_con = train_test_split(df_normal_test_con, test_size=0.1)
            drop_data, df_normal_test_data = train_test_split(df_normal_test_data, test_size=0.1)

        else:
            attack_list = ['all']

        #log for per_attack
        record_attack = pd.DataFrame(columns=['attack_type','fpr_1','tpr_1', 'thresholds_1','fpr_2','tpr_2', 'thresholds_2','pr_auc','roc_auc'])

        for attack_idx,attack_type in enumerate(attack_list):
            if '.' in attack_type:
                continue
            print('-------------------------- processing ', attack_type,
              ' type --------------------------')
            if Per_Attack:
                df_attack_test = load_iot_attack_seq(attack_type)
                df_attack_test_data = load_iot_attack(attack_name=attack_type, thr_time=1)
            df_test_con = pd.concat([df_normal_test_con,df_attack_test],axis=0)
            df_test_data = pd.concat([df_normal_test_data,df_attack_test_data],axis=0)


            df_test_data.dropna(axis=0, inplace=True)

            # filter data to the same 5-tuple，filt the broadcast data.
            df_test_con = iForest_detect.filter(df_test_data, df_test_con)

            if Use_filter:
                # data plane filter
                df_test_with_pred = iForest_detect.test(['all'], feature_set, df_test_data)
                before_filter_flow_num = len(pd.unique(df_test_with_pred['key']))
                anomaly_df = iForest_detect.get_Anomaly_ID(df_test_with_pred, 0.95)
                after_filter_flow_num = len(pd.unique(anomaly_df['key']))
                # filt the control plane data
                if after_filter_flow_num != 0:
                    print('Flow Gain Ratio', before_filter_flow_num / after_filter_flow_num)

                after_filer_test = iForest_detect.filter(anomaly_df, df_test_con)
                pass_data = iForest_detect.pass_(anomaly_df, df_test_con)
            else:
                after_filer_test = df_test_con
            if not PORT:
                after_filer_test = after_filer_test.drop(columns=[1, 2])
            test_X, test_y = data_processing(after_filer_test, TWO_D)

            # tranfer to test loader
            if not KITSUNE:
                print('Test X shape',test_X.shape)
                test_datasets = Data.TensorDataset(test_X, test_y)
                test_loader = Data.DataLoader(dataset=test_datasets, batch_size=TEST_BATCH_SIZE, shuffle=True, num_workers=0)

                # load AE checkpoints
                # it will add new key in training profile phase, causing to calculate the FLOPs and MACs.
                # and we drop this key by setting the strict to False
                model.load_state_dict(torch.load(model_save_path,map_location='cuda:0'), strict=False)

                # load TensorRT model
                if INT8:
                    trt_model = load(tensorrt_save_path)
                if Test_Throughput:
                    if INT8:
                        test_throughput(trt_model, TEST_BATCH_SIZE, test_X)
                    else:
                        test_throughput(model, TEST_BATCH_SIZE, test_X)
                if INT8:
                    eval_y_label, rmse_list = test(trt_model, test_loader)
                else:
                    eval_y_label, rmse_list = test(model, test_loader)

            if KITSUNE:
                # Kitsune data preprocess
                eval_y_label, rmse_list = test_Kitsune(test_X, test_y, Kitsune_save_path)

            # test Gulliver only
            # eval_y_label = []
            # rmse_list = []
            # eval_y_label.extend(after_filer_test['class'])
            # rmse_list.extend(list(np.ones(after_filer_test.shape[0])))

            if Use_filter:  # add the pass feature
                eval_y_label.extend(pass_data['class'])
                # we believe that the pass data is normal data. Thus, we set its' rmse 0
                rmse_list.extend(list(np.zeros(pass_data.shape[0])))

            # Calculate the auroc of the overall framework
            fpr, tpr, thresholds = roc_curve(eval_y_label, rmse_list)

            # record raw rmse list of model
            raw_res = [[eval_y_label[i], rmse_list[i]] for i in range(len(rmse_list))]
            df_raw_res = pd.DataFrame(columns=['eval_y_label', 'rmse_list'], data=raw_res)
            df_raw_res.to_csv('./result/rmse/raw_rmse_' + attack_type + '.csv')

            auc_eval = auc(fpr, tpr)
            eps = 1e-6
            temp_fpr = 0
            temp_tpr = 0
            temp_thresholds = 0
            for i in range(len(fpr)):
                if fpr[i] <= 5e-5 + eps:
                    temp_fpr = fpr[i]
                    temp_tpr = tpr[i]
                    temp_thresholds = thresholds[i]
                else:
                    break
            print('False positive rate', temp_fpr)
            print('True positive rate', temp_tpr)
            print('Thresholds is ', temp_thresholds)
            df1=pd.DataFrame({'attack_type':attack_type,'fpr_1':temp_fpr,'tpr_1':temp_tpr,'thresholds_1':temp_thresholds},index=[attack_idx])

            temp_fpr = 0
            temp_tpr = 0
            temp_thresholds = 0
            for i in range(len(fpr)):
                if fpr[i] <= 5e-4 + eps:
                    temp_fpr = fpr[i]
                    temp_tpr = tpr[i]
                    temp_thresholds = thresholds[i]
                else:
                    break
            print('False positive rate', temp_fpr)
            print('True positive rate', temp_tpr)
            print('Thresholds is ', temp_thresholds)
            df2 = pd.DataFrame({'fpr_2':temp_fpr,'tpr_2': temp_tpr, 'thresholds_2': temp_thresholds},index=[attack_idx])

            print('the auc_eval is ', auc_eval)

            # Calculate the pr_auc of the overall framework
            precision, recall, thresholds_pr = precision_recall_curve(eval_y_label, rmse_list)
            pr_auc = auc(recall, precision)
            print('the pr_auc is ', pr_auc)
            df3 = pd.DataFrame({'pr_auc': pr_auc, 'roc_auc': auc_eval},index=[attack_idx])
            df_temp = pd.concat([df1,df2,df3],axis=1)
            record_attack = pd.concat([record_attack,df_temp],axis=0)


            # record the roc data
            roc_record = pd.DataFrame(columns=['thresholds','fpr', 'tpr' ])
            roc_record['fpr'] = fpr
            roc_record['tpr'] = tpr
            roc_record['thresholds'] = thresholds
            if OPEN_SOURCE:
                if Use_filter:
                    roc_record.to_csv('./result/Open-Source/HorusEye/roc_record_split_' + attack_type + 'HorusEye.csv')
                elif KITSUNE:
                    roc_record.to_csv('./result/Open-Source/Kitsune/roc_record_split_' + attack_type + '.csv')
                else:
                    roc_record.to_csv('./result/Open-Source/Magnifier/roc_record_split_' + attack_type + '.csv')

            else:
                if Use_filter:
                    roc_record.to_csv('./result/HorusEye/roc_record_split_'+attack_type+'.csv')
                elif KITSUNE:
                    roc_record.to_csv('./result/Kitsune/roc_record_split_' + attack_type + '.csv')
        if OPEN_SOURCE:
            if Use_filter:
                record_attack.to_csv('./result/Open-Source/HorusEye/record_attack.csv')
            elif KITSUNE:
                record_attack.to_csv('./result/Open-Source/Kitsune/record_attack.csv')
            else:
                record_attack.to_csv('./result/Open-Source/Magnifier/record_attack.csv')
        else:
            if Use_filter:
                record_attack.to_csv('./result/HorusEye/record_attack.csv')
            elif KITSUNE:
                record_attack.to_csv('./result/Kitsune/record_attack.csv')

    if TEST_ROBUST:
        Poisoning_ratio = [0.01, 0.02, 0.1]
        robust_list = ['mix','low_rate','poisoning_0','poisoning_1','poisoning_2']
        print('loading attack data...')
        df_attack_eval_data = load_iot_attack(attack_name='http_ddos', thr_time=1)
        print('loading training data...')
        df_normal_train_data = load_iot_data(device_list=device_list_camera, thr_time=1, begin=0, end=4)
        df_normal_train_data = df_normal_train_data.append(load_iot_data(device_list=device_list_gateway, thr_time=1, begin=0, end=4))
        df_normal_train, df_normal_eval = train_test_split(df_normal_train_data, test_size=0.2, random_state=20)
        print(df_normal_train.shape)
        for robust_type in robust_list:
            print('******************', robust_type, '******************')
            df_robust_result=pd.DataFrame()
            if robust_type.startswith('poisoning'):
                ratio = Poisoning_ratio[robust_type.split('_')[1]]
                df_attack_poisoning_data = load_iot_attack(attack_name='mirai_router_filter', thr_time=1)
                poisoning_size = len(df_attack_poisoning_data)
                target_size = int(len(df_normal_train)*ratio)
                while poisoning_size < target_size:
                    df_attack_poisoning_data = df_attack_poisoning_data.append(df_attack_poisoning_data.iloc[:min((target_size-poisoning_size),len(df_attack_poisoning_data))])
                    poisoning_size = len(df_attack_poisoning_data)
                print(df_attack_poisoning_data.shape)
                df_normal_train = df_normal_train.append(df_attack_poisoning_data)
                iForest_detect.train('all', feature_set, df_normal_train, df_normal_eval, df_attack_eval_data)
                robust_result_path='./result/df_robust_result_' + robust_type + '_' + str(ratio) + '.csv'
                robust_attack_path='./DataSets/Anomaly/attack-flow-level-device_1_dou_burst_14_add_pk/mirai_router_filter'
            else:
                robust_result_path='./result/df_robust_result_' + robust_type + '.csv'
                robust_attack_path='./DataSets/robust/{}/attack-flow-level-device_1_dou_burst_14_add_pk'.format(robust_type)
            attack_list=os.listdir(robust_attack_path)
            for attack_path in attack_list:
                print('------------------', attack_path, '------------------')
                df_attack_robust = pd.read_csv(robust_attack_path+'/'+attack_path)
                df_attack_robust['class'] = -1
                # df_attack.dropna(axis=0, inplace=True)
                df_eval_data = df_normal_eval.append(df_attack_robust)
                # df_eval_data = df_attack_robust
                df_eval_with_pred = iForest_detect.test(['all'], feature_set, df_eval_data)

                udp_test, tcp_test = df_eval_data[df_eval_data['udp_tcp'] == 0], df_eval_data[df_eval_data['udp_tcp'] == 1]
                udp_test_y = udp_test['class']
                tcp_test_y = tcp_test['class']
                test_y = pd.concat([udp_test_y, tcp_test_y], axis=0)

                return_table = classification_report(y_true=test_y, y_pred=df_eval_with_pred['pred'],
                                                    target_names=['abnormal', 'normal'],
                                                    output_dict=True)
                df_robust_result = pd.concat([df_robust_result, pd.DataFrame(
                    {'robust_attack':attack_path, 'abnormal_precision': round(return_table['abnormal']['precision'], 3),
                    'abnormal_recall': round(return_table['abnormal']['recall'], 3),
                    'normal_precision': round(return_table['normal']['precision'], 3),
                    'normal_recall': round(return_table['normal']['recall'], 3),
                    'support': return_table['normal']['support'], },
                    index=[0])], axis=0)
            df_robust_result.to_csv(robust_result_path)

