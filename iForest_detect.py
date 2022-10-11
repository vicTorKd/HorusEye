from load_data import *
# from Unsupervised_detect import *
import numpy as np
import matplotlib.pyplot as plt
from sklearn.ensemble import IsolationForest
from sklearn.metrics import classification_report,accuracy_score
from sklearn.metrics import precision_score
from sklearn.cluster import DBSCAN

def transfer_rule_port(clf, path):

    from collections import defaultdict
    branches = defaultdict(set)
    ports = [15 - i for i in range(16)]
    for f in ports:
        branches[f].add(0)
        branches[f].add(1)

    Feature_domain = pd.DataFrame({'key': 1}, index=[0])

    for f in branches.keys():
        temp = pd.DataFrame({f: tuple(branches[f]), 'key': 1})
        Feature_domain = pd.merge(Feature_domain, temp, on='key')

    Feature_domain.drop(columns=['key'], inplace=True)
    Feature_domain.sort_values(by=list(branches.keys()), ascending=True, inplace=True)
    Feature_domain.sort_index(axis=1, inplace=True)
    #emu num
    print('Emu num',len(Feature_domain))

    Feature_domain_label = clf.predict(Feature_domain)
    Feature_domain['label'] = Feature_domain_label

    merge = Feature_domain[Feature_domain['label'] == 1]
    print('merge num white list',len(merge))
    merge.to_csv(path)

def transfer_rule2(clf, path):
    INF = 100000
    from collections import defaultdict
    branches = defaultdict(set)
    for e in clf.estimators_:
        threshold = e.tree_.threshold.astype(np.int64)
        feature = e.tree_.feature
        n_nodes = e.tree_.node_count
        for i in range(n_nodes):
            if (feature[i] < 0):  # leaf node
                continue
            branches[feature[i]].add(threshold[i])
    for f in branches.keys():
        branches[f].add(INF)

    Feature_domain = pd.DataFrame({'key': 1}, index=[0])

    for f in branches.keys():
        temp = pd.DataFrame({f: tuple(branches[f]), 'key': 1})
        Feature_domain = pd.merge(Feature_domain, temp, on='key')

    Feature_domain.drop(columns=['key'], inplace=True)
    Feature_domain.sort_values(by=list(branches.keys()), ascending=True, inplace=True)
    Feature_domain.sort_index(axis=1, inplace=True)
    #emu num
    print('Emu num',len(Feature_domain))

    Feature_domain_label = clf.predict(Feature_domain)
    Feature_domain['label'] = Feature_domain_label
    #Feature_domain.to_csv('./result/Feature_domain.csv')
    merge = pd.DataFrame()

    for f in branches.keys():
        Feature_domain[str(f) + '_left'] = Feature_domain[f]
    #old_count = defaultdict(int)

    flag = {}
    for f in branches.keys():
        flag[f] = False
    if len(Feature_domain):
        temp = pd.Series(Feature_domain.iloc[0])
        for f in branches.keys():
            temp[str(f) + '_left'] = 0
        merge = merge.append(temp)
    for i in range(0, len(Feature_domain) - 1):
        flag=False
        if (Feature_domain['label'].iloc[i] == Feature_domain['label'].iloc[i + 1]):

            for f in branches.keys():
                if Feature_domain[f].iloc[i+1] == INF:
                    merge[f].iloc[-1] = INF
                elif(Feature_domain[f].iloc[i] == INF):
                    temp = pd.Series(Feature_domain.iloc[i + 1])
                    temp[str(f) + '_left'] = 0
                    flag=True
            if flag:
                merge = merge.append(temp)

        else:

            temp = pd.Series(Feature_domain.iloc[i + 1])
            for f in branches.keys():
                merge[f].iloc[-1] = Feature_domain[f].iloc[i]
                if Feature_domain[f].iloc[i]==INF:
                    temp[str(f) + '_left']=0
                else:
                    temp[str(f) + '_left'] = Feature_domain[f].iloc[i]
            merge = merge.append(temp)


    merge = merge[merge['label'] == 1]
    print('merge num white list',len(merge))

    for i in range(len(merge)):
        for f in branches.keys():
            if merge[f].iloc[i] == merge[str(f) + '_left'].iloc[i]:
                merge[str(f) + '_left'].iloc[i] = merge[f].iloc[i]-1

    merge_ = pd.DataFrame()  # merge for two feature

    if len(merge):
        merge_ = merge_.append(pd.Series(merge.iloc[0]))

    feature_num = len(branches.keys())
    for i in range(0, len(merge) - 1):
        flag1 = 1
        flag2 = False
        f_change = None
        for f in branches.keys():
            if (merge[f].iloc[i] == merge[f].iloc[i + 1] and merge[str(f) + '_left'].iloc[i] ==
                    merge[str(f) + '_left'].iloc[i + 1]):
                flag1 += 1
            elif merge[str(f) + '_left'].iloc[i + 1] <= merge_[f].iloc[-1] and merge[f].iloc[i + 1] == merge_[f].iloc[-1] + 1:
                flag2 = True
                f_change = f


        if (flag1==feature_num) & flag2:
            merge_[f_change].iloc[-1] = merge[f_change].iloc[i + 1]

        else:
            merge_ = merge_.append(pd.Series(merge.iloc[i + 1]))

    merge_.to_csv(path)


def train(device_name, feature_set, df_normal_train, df_normal_eval, df_attack_eval):
    # if 'server_port' in feature_set:
    #     df_normal_train = add_server_port(df_normal_train, open_source=True)
    #     df_attack_eval = add_server_port(df_attack_eval, open_source=False)
    
    feature_set_port = ['port_' + str(15 - i) for i in range(16)]

    udp_train, tcp_train = df_normal_train[df_normal_train['udp_tcp'] == 0], df_normal_train[
        df_normal_train['udp_tcp'] == 1]
    udp_x_train, udp_y_train = udp_train.drop(columns=['class']), udp_train['class']
    tcp_x_train, tcp_y_train = tcp_train.drop(columns=['class']), tcp_train['class']

    df_eval = df_normal_eval.append(df_attack_eval)
    udp_eval, tcp_eval = df_eval[df_eval['udp_tcp'] == 0], df_eval[df_eval['udp_tcp'] == 1]

    udp_x_eval, udp_eval_y = udp_eval.drop(columns=['class']), udp_eval['class']
    tcp_x_eval, tcp_eval_y = tcp_eval.drop(columns=['class']), tcp_eval['class']

    best_str = ""
    best_f1_score = 0
    best_n = 0
    best_m = 0
    best_return = {}
    port_contamination = 0.05

    iforest_record = pd.DataFrame(columns=['contamination', 'm_samples', 'num_estimators', 'anomaly_recall',
                                           'normal_recall'])
    for num_estimators in [200]:  # 100,200,300
        for m_samples in [5000]:  # 300,400
            for contamination in [0.15]:
                clf_udp = IsolationForest(n_estimators=num_estimators, max_samples=m_samples, random_state=114514,
                                          contamination=contamination,n_jobs=8)
                clf_tcp = IsolationForest(n_estimators=num_estimators, max_samples=m_samples, random_state=114514,
                                          contamination=contamination,n_jobs=8)
                clf_tcp_port = IsolationForest(n_estimators=num_estimators, max_samples=m_samples, random_state=114514,
                                          contamination=port_contamination, n_jobs=8)
                clf_udp_port = IsolationForest(n_estimators=num_estimators, max_samples=m_samples, random_state=114514,
                                               contamination=port_contamination, n_jobs=8)

                if len(feature_set) == 1:
                    # print(udp_x_train[feature_set])
                    clf_udp.fit(udp_x_train[feature_set].values.reshape(-1, 1))
                    clf_tcp.fit(tcp_x_train[feature_set].values.reshape(-1, 1))
                    y_pred_eval_udp = clf_udp.predict(udp_x_eval[feature_set].values.reshape(-1, 1))
                    y_pred_eval_tcp = clf_tcp.predict(tcp_x_eval[feature_set].values.reshape(-1, 1))
                else:
                    clf_udp.fit(udp_x_train[feature_set])
                    clf_tcp.fit(tcp_x_train[feature_set])
                    y_pred_eval_udp = clf_udp.predict(udp_x_eval[feature_set])
                    y_pred_eval_tcp = clf_tcp.predict(tcp_x_eval[feature_set])
                    clf_udp_port.fit(udp_x_train[feature_set_port])
                    clf_tcp_port.fit(tcp_x_train[feature_set_port])

                    y_pred_eval_udp_port = clf_udp_port.predict(udp_x_eval[feature_set_port])
                    y_pred_eval_tcp_port = clf_tcp_port.predict(tcp_x_eval[feature_set_port])
                # y_pred_eval = np.concatenate((y_pred_eval_udp , y_pred_eval_tcp ))
                y_pred_eval = np.concatenate((y_pred_eval_udp | y_pred_eval_udp_port, y_pred_eval_tcp | y_pred_eval_tcp_port))
                eval_y = udp_eval_y.append(tcp_eval_y)
                eval_x = udp_x_eval.append(tcp_x_eval)

                print("n_estimators:{:},m_samples:{:},contamination:{:}".format(num_estimators, m_samples,contamination))
                print('Test')
                temp_str = classification_report(y_true=eval_y, y_pred=y_pred_eval, target_names=['abnormal', 'normal'])
                temp_list = temp_str.split()
                iforest_record = iforest_record.append(
                    pd.DataFrame({'contamination': contamination, 'm_samples': m_samples,
                                  'num_estimators': num_estimators, 'anomaly_recall': temp_list[6],
                                  'normal_recall': temp_list[11]}, index=[0]))
                print(temp_str)
                a = classification_report(y_true=eval_y, y_pred=y_pred_eval, target_names=['abnormal', 'normal'],
                                          output_dict=True)
                start_time=time.time()
                
                transfer_rule2(clf_tcp, './result/tcp_rule_' + device_name + '.csv')
                transfer_rule2(clf_udp, './result/udp_rule_' + device_name + '.csv')

                transfer_rule_port(clf_tcp_port, './result/tcp_port_rule_' + device_name + '.csv')
                transfer_rule_port(clf_udp_port, './result/udp_port_rule_' + device_name + '.csv')
                print('transfer_rule time cost:',time.time()-start_time)

                test_x = test(['all'], feature_set, df_eval)

                print('accuracy',accuracy_score(test_x['pred'],y_pred_eval))
                test_x[test_x['pred']!=y_pred_eval].to_csv('./result/wrong.csv')
                temp_f1 = a['abnormal']['recall']
                if (best_f1_score <= temp_f1):
                    best_f1_score = temp_f1
                    best_str = temp_str
                    best_n = num_estimators
                    best_m = m_samples
                    best_return = a
                    eval_x['test_y'] = eval_y
                    eval_x['pred_y'] = y_pred_eval
                    eval_x.to_csv('./result/test_pred_' + device_name + '.csv')

    print("best n_estimators:{:},m_samples:{:}".format(best_n, best_m))
    print(best_str + '\n' + str(temp_f1))
    iforest_record.to_csv('./result/iforest_record.csv')
    return best_return

def test_port(device_list, feature_set,df_test):#
#input device_list: name of device (type: list), feature_set: e.g.['sum_len'], df_test: type: DataFrame
    udp_test, tcp_test = df_test[df_test['udp_tcp'] == 0], df_test[df_test['udp_tcp'] == 1]
    udp_x_test, udp_test_y = udp_test.drop(columns=['class']), udp_test['class']
    tcp_x_test, tcp_test_y = tcp_test.drop(columns=['class']), tcp_test['class']

    udp_clf=pd.DataFrame()
    tcp_clf=pd.DataFrame()
    udp_x_test['pred'] = -1
    tcp_x_test['pred'] = -1
    for device_name in device_list:
        udp_clf = udp_clf.append(pd.read_csv('./result/udp_rule_' + device_name + '.csv'))
        tcp_clf = tcp_clf.append(pd.read_csv('./result/tcp_rule_' + device_name + '.csv'))
    condition_udp=[]
    condition_tcp=[]


    for i in range(len(udp_clf)):
        condition1 = []
        for f in range(len(feature_set)):
            if not len(condition1):
                condition1 = condition1 or (((udp_x_test[feature_set[f]] == udp_clf[str(f)].iloc[i])))
            else:
                # print(len(condition1))
                condition1 = condition1 & (((udp_x_test[feature_set[f]] == udp_clf[str(f)].iloc[i])))

        if not len(condition_udp):
            condition_udp = condition_udp or condition1
        else:
            condition_udp = condition_udp | condition1

    for i in range(len(tcp_clf)):

        condition2 = []
        for f in range(len(feature_set)):

            if not len(condition2):
                condition2 = condition2 or (((tcp_x_test[feature_set[f]] == tcp_clf[str(f)].iloc[i])))
            else:
                condition2 = condition2 & (((tcp_x_test[feature_set[f]] == tcp_clf[str(f)].iloc[i])))

        if not len(condition_tcp):
            condition_tcp = condition_tcp or condition2
        else:
            condition_tcp = condition_tcp | condition2

    udp_x_test.loc[condition_udp, 'pred'] = 1
    tcp_x_test.loc[condition_tcp, 'pred'] = 1

    test_x=udp_x_test.append(tcp_x_test)
    test_y=udp_test_y.append(tcp_test_y)
    temp_str = classification_report(y_true=test_y, y_pred=test_x['pred'], target_names=['abnormal', 'normal'])
    print(temp_str)

    return_table = classification_report(y_true=test_y, y_pred=test_x['pred'], target_names=['abnormal', 'normal'],
                              output_dict=True)
    result_table = pd.DataFrame()
    result_table=result_table.append(pd.DataFrame({'device_name':device_name,'abnormal_precision': round(return_table['abnormal']['precision'],3), 'abnormal_recall': round(return_table['abnormal']['recall'],3),'normal_precision': round(return_table['normal']['precision'],3), 'normal_recall': round(return_table['normal']['recall'],3),'support': return_table['normal']['support'],}, index=[0]))
    result_table.to_csv('./result/result_table.csv')
    return test_x #['5-tuple','sum_len','pred','pk_num']

def test(device_list, feature_set,df_test):#
    # input device_list: name of device (type: list), feature_set: e.g.['sum_len'], df_test: type: DataFrame
    feature_set_port = ['port_' + str(15 - i) for i in range(16)]
    udp_test, tcp_test = df_test[df_test['udp_tcp'] == 0], df_test[df_test['udp_tcp'] == 1]
    udp_x_test, udp_test_y = udp_test.drop(columns=['class']), udp_test['class']
    tcp_x_test, tcp_test_y = tcp_test.drop(columns=['class']), tcp_test['class']

    udp_clf=pd.DataFrame()
    tcp_clf=pd.DataFrame()
    
    tcp_clf_port=pd.DataFrame()
    udp_clf_port=pd.DataFrame()

    udp_x_test['pred'] = -1
    tcp_x_test['pred'] = -1
    for device_name in device_list:
        udp_clf = udp_clf.append(pd.read_csv('./result/udp_rule_' + device_name + '.csv'))
        tcp_clf = tcp_clf.append(pd.read_csv('./result/tcp_rule_' + device_name + '.csv'))
        
        tcp_clf_port = tcp_clf_port.append(pd.read_csv('./result/tcp_port_rule_' + device_name + '.csv'))
        udp_clf_port = udp_clf_port.append(pd.read_csv('./result/udp_port_rule_' + device_name + '.csv'))

    condition_udp=[]
    condition_tcp=[]

    condition_udp_port=[]
    condition_tcp_port=[]


    for i in range(len(udp_clf)):
        condition1 = []
        for f in range(len(feature_set)):
            if not len(condition1):
                condition1 = condition1 or (((udp_x_test[feature_set[f]] <= udp_clf[str(f)].iloc[i]) & (
                        udp_x_test[feature_set[f]] > udp_clf[str(f)+'_left'].iloc[i])))
            else:
                # print(len(condition1))
                condition1 = condition1 & (((udp_x_test[feature_set[f]] <= udp_clf[str(f)].iloc[i]) & (
                        udp_x_test[feature_set[f]] > udp_clf[str(f)+'_left'].iloc[i])))
        if not len(condition_udp):
            condition_udp = condition_udp or condition1

        else:
            condition_udp = condition_udp | condition1

    for i in range(len(udp_clf_port)):
            condition1 = []
            for f in range(len(feature_set_port)):
                if not len(condition1):
                    condition1 = condition1 or ((udp_x_test[feature_set_port[f]] == udp_clf_port[str(f)].iloc[i]))
                else:
                    # print(len(condition1))
                    condition1 = condition1 & ((udp_x_test[feature_set_port[f]] == udp_clf_port[str(f)].iloc[i]))

            if not len(condition_udp_port):
                condition_udp_port = condition_udp_port or condition1

            else:
                condition_udp_port = condition_udp_port | condition1
            
            
    for i in range(len(tcp_clf)):

        condition2 = []
        for f in range(len(feature_set)):

            if not len(condition2):
                condition2 = condition2 or (((tcp_x_test[feature_set[f]] <= tcp_clf[str(f)].iloc[i]) & (tcp_x_test[feature_set[f]] > tcp_clf[str(f)+'_left'].iloc[i])) )
            else:
                condition2 = condition2 & (((tcp_x_test[feature_set[f]] <= tcp_clf[str(f)].iloc[i]) & (tcp_x_test[feature_set[f]] > tcp_clf[str(f)+'_left'].iloc[i])))
        if not len(condition_tcp):
            condition_tcp = condition_tcp or condition2
        else:
            condition_tcp = condition_tcp | condition2

    for i in range(len(tcp_clf_port)):
            condition2 = []
            for f in range(len(feature_set_port)):
                if not len(condition2):
                    condition2 = condition2 or (((tcp_x_test[feature_set_port[f]] == tcp_clf_port[str(f)].iloc[i])))
                else:
                    condition2 = condition2 & (((tcp_x_test[feature_set_port[f]] == tcp_clf_port[str(f)].iloc[i])))

            if not len(condition_tcp_port):
                condition_tcp_port = condition_tcp_port or condition2
            else:
                condition_tcp_port = condition_tcp_port | condition2
            
    udp_x_test.loc[condition_udp & condition_udp_port, 'pred'] = 1
    tcp_x_test.loc[condition_tcp & condition_tcp_port, 'pred'] = 1

    test_x=udp_x_test.append(tcp_x_test)
    test_y=udp_test_y.append(tcp_test_y)
    temp_str = classification_report(y_true=test_y, y_pred=test_x['pred'], target_names=['abnormal', 'normal'])
    print(temp_str)

    return_table = classification_report(y_true=test_y, y_pred=test_x['pred'], target_names=['abnormal', 'normal'],
                              output_dict=True)
    result_table = pd.DataFrame()
    result_table=result_table.append(pd.DataFrame({'device_name':device_name,'abnormal_precision': round(return_table['abnormal']['precision'],3), 'abnormal_recall': round(return_table['abnormal']['recall'],3),'normal_precision': round(return_table['normal']['precision'],3), 'normal_recall': round(return_table['normal']['recall'],3),'support': return_table['normal']['support'],}, index=[0]))
    result_table.to_csv('./result/result_table.csv')
    return test_x #['5-tuple','sum_len','pred','pk_num']

def get_Anomaly_ID_test(df_test_with_pred, df_test_data):  #DateFrame
    best_f1_score = 0
    best_thr = 0
    best_return = {}
    df_test_data = df_test_data.sort_values(by='key', ascending=True)
    threshold_record = pd.DataFrame(columns=['threshold', 'anomaly_recall', 'normal_recall'])
    for thr in np.arange(0.05, 1.05, 0.1):
        print("threshold:{:}".format(thr))
        df_44 = get_Anomaly_ID(df_test_with_pred, threshold=thr)
        df_abnormal = df_test_with_pred[df_test_with_pred['key'].isin(df_44['key'])]
        df_abnormal['pred'] = -1
        df_normal = df_test_with_pred[~df_test_with_pred['key'].isin(df_abnormal['key'])]
        df_normal['pred'] = 1
        df_pred = df_abnormal[['key', 'pred']].append(df_normal[['key', 'pred']])
        df_pred = df_pred.sort_values(by='key', ascending=True)
        return_table = classification_report(y_true=df_test_data['class'], y_pred=df_pred['pred'],
                                             target_names=['abnormal', 'normal'], output_dict=True)
        temp = classification_report(y_true=df_test_data['class'], y_pred=df_pred['pred'],
                                     target_names=['abnormal', 'normal'], output_dict=False)
        print(temp)
        threshold_record = threshold_record.append(
            pd.DataFrame({'threshold': thr, 'anomaly_recall': return_table['abnormal']['recall'],
                          'normal_recall': return_table['normal']['recall']}, index=[0]))
        temp_f1 = return_table['normal']['recall']
        if (best_f1_score < temp_f1):
            best_f1_score = temp_f1
            best_thr = thr
            best_return = return_table
    print("best threshold:{:}".format(best_thr))
    threshold_record.to_csv('./result/threshold_record_test.csv')
    return best_return

def get_Anomaly_ID(df,threshold=0.95):#DateFrame
    #df=df[df['pred'] == -1]
    thr = threshold
    df= df[['key','pred']]
    df.reset_index(inplace=True, drop=True)
    df11 = df[df['pred'] == -1].groupby(df['key']).agg('sum').reset_index()
    df11.columns = ['key', 'pred_y_abnormal']
    df22 = df[df['pred'] == 1].groupby(df['key']).agg('sum').reset_index()
    df22.columns = ['key', 'pred_y_normal']
    df33 = pd.merge(df11, df22)
    df33['abnormal'] = abs(df33['pred_y_abnormal']) / (abs(df33['pred_y_abnormal']) + df33['pred_y_normal'])
    df44 = df33[df33['abnormal'] > thr]
    df44 = df44.append(df11[~df11['key'].isin(df33["key"])])
    return df44

def filter(anomaly_df, control_all_pk_df):# anomaly_df which dedicate the anomaly in the first stage
    filter_ = control_all_pk_df[control_all_pk_df[0].isin(anomaly_df["key"])]
    return filter_
def pass_(anomaly_df, control_all_pk_df):# anomaly_df which dedicate the anomaly in the first stage
    filter_ = control_all_pk_df[~control_all_pk_df[0].isin(anomaly_df["key"])]
    return filter_
def main(attack_name='all',device_list=['philips_camera'],thr_time=10,file_num=5):
    #hyper-parameter
    feature_set=['sum_len']
    #
    df_normal_test=pd.DataFrame()
    df_attack=load_iot_attack(attack_name,thr_time)
    df_attack_test, df_attack_eval = train_test_split(df_attack, test_size=0.2)
    for device_name in device_list: #train every device
        df_normal= load_iot_data( device_list= [device_name] , thr_time=thr_time,begin=0,end=5)
        df_normal_train, df_normal_test_part = train_test_split(df_normal, test_size=0.5)

        df_normal_test=df_normal_test.append(df_normal_test_part) #accumulate for testing
        train(device_name, feature_set, df_normal_train, df_attack_eval)

    # test the rule
    df_test = df_normal_test.append(df_attack_test)
    df_test.dropna(axis=0, inplace=True)

    df_test_with_pred = test(device_list, feature_set, df_test)
    anomaly_df=get_Anomaly_ID(df_test_with_pred)
    anomaly_df.to_csv('./result/pre_anomaly_5-tuple.csv')
    return
