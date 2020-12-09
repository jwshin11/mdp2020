import sys
import numpy as np
import math
import json
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import sklearn.metrics as sklm
from sklearn import svm
from features import *

def plot_time_vs_ip_len(time_dict, ip_len_dict, trace_list, plots_path, save_plots=False):
    for trace in trace_list:
        plt.clf()
        plt.plot(time_dict[trace], ip_len_dict[trace], linestyle='-', marker='.')
        plt.title(trace[0] + ' - ' + trace[1])
        plt.xlabel('Time (sec)')
        plt.ylabel('Length of IP Packet Sent (bytes)')

        if save_plots:
            plt.savefig(plots_path + trace[0] + '-' + trace[1] + '.png')
        
        num_packets = len(time_dict[trace])
        if num_packets > 10:
            time = max(time_dict[trace]) - min(time_dict[trace])
            avg = num_packets / time
            
            print('src: {}\tdst: {}\t# of packets: {}\t Time: {}\tpackets/sec: {}'.format(trace[0], trace[1], num_packets, time, avg))

def plot_burst(burst_dict, trace_list, plots_path, save_plots=False):
    for trace in trace_list:
        plt.clf()
        plt.plot(burst_dict[trace], linestyle='-', marker='.')
        plt.title(trace[0] + ' - ' + trace[1])
        plt.xlabel('Burst')

        if save_plots:
            plt.savefig(plots_path + trace[0] + '-' + trace[1] + '.png')

def main():
    filename = sys.argv[1]
    # file_list = get_files(files_txt)
    file_list = []
    file_list.append(filename)
    num_frames = int(sys.argv[2])
    _, time, _ = filename.split('/')
    print('Extracting features...')
    time_dict, ip_len_dict, burst_dict, trace_list = get_features(file_list, num_frames)

    print('Plotting graphs...')
    # plot_time_vs_ip_len(time_dict, ip_len_dict, trace_list, './plots/' + time + '/ip_len/', save_plots=True)

    plot_burst(burst_dict, trace_list, './plots/' + time + '/burst/', save_plots=True)

    file_list = []
    file_list.append('swat/1030/swat4.pcap')
    time_dict1, ip_len_dict1, burst_dict1, trace_list1 = get_features(file_list, num_frames)

    file_list = []
    file_list.append('swat/1230/swat2.pcap')
    time_dict2, ip_len_dict2, burst_dict2, trace_list2 = get_features(file_list, num_frames)

    list1 = list(set(trace_list) & set(trace_list1))
    list2 = list(set(list1) & set(trace_list2))
    list2.sort()
    N = len(list2)
    ind = np.arange(N)
    width = 0.25
    avg0 = []
    avg1 = []
    avg2 = []

    print(list2)
    rem = []
    for trace in list2:
        num_packets = len(time_dict[trace])
        time = max(time_dict[trace]) - min(time_dict[trace])
        avg = num_packets / time
        if avg > 3000:
            rem.append(trace)
            continue
        avg0.append(avg)

        num_packets = len(time_dict1[trace])
        time = max(time_dict1[trace]) - min(time_dict1[trace])
        avg = num_packets / time
        avg1.append(avg)

        num_packets = len(time_dict2[trace])
        time = max(time_dict2[trace]) - min(time_dict2[trace])
        avg = num_packets / time
        avg2.append(avg)

    for trace in rem:
        list2.remove(trace)

    # print(len(avg0))
    # print(len(avg1))
    # print(len(avg2))
    # plt.bar(ind, avg0, width, label='1005')
    # plt.bar(ind + width, avg1, width, label='1030')
    # plt.bar(ind + width, avg2, width, label='1230')
    # plt.ylabel('IP Length in Bytes')
    # plt.savefig('./bargraph.png')

    for i in range(len(avg0)):
        print('Trace: {}\t1005: {}\t1030: {}\t1230: {}'.format(list2[i], avg0[i], avg1[i], avg2[i]))


def plot_histogram(window_list, plots_path, plot_graph=False):
    i = 0
    for window in window_list:
        plt.clf()
        bin_size = 10
        num_bins = int(math.ceil((650 - 40) / bin_size))
        n, bins, patches = plt.hist(window, num_bins, facecolor='blue')
        plt.savefig(plots_path + str(i) + '.png')
        i += 1

        print('\nMin: {}\tMax: {}'.format(min(window), max(window)))
        print(window)

def window_main():
    filename = sys.argv[1]
    # file_list = get_files(files_txt)
    file_list = []
    file_list.append(filename)
    num_frames = int(sys.argv[2])
    max_window_size = int(sys.argv[3])
    _, time, _ = filename.split('/')

    window_list,_ = get_window_features(file_list, num_frames, max_window_size, 1)
    # plot_histogram(window_list, './plots/histogram/' + time + '/')
    
    y = []
    for i in range(len(window_list)):
        y.append(1)

    file_list = []
    file_list.append('swat/1030/swat3.pcap')
    saved = window_list
    window_list2,_ = get_window_features(file_list, num_frames, max_window_size, 1)
    for i in range(len(window_list2)):
        y.append(0)
    # pred = run_one_class_svm(window_list)
    window_list3 = window_list + window_list2
    clf = svm.SVC()
    clf.fit(window_list3, y)
    pred = clf.predict(window_list3)
    print(pred)

    file_list = []
    file_list.append('swat/1005/swat15.pcap')
    window_list,_ = get_window_features(file_list, 1000, max_window_size,1)


    pred = clf.predict(window_list)
    print(pred)

def run_svm(X_train, y_train, X_test, y_test):
    # # Train
    # clf = svm.SVC(gamma='auto')
    # clf.fit(X_train, y_train)

    # # Test
    # pred = clf.predict(X_test)
    # accuracy_score = sklm.accuracy_score(y_test, pred)
    # print(accuracy_score)
    for i in range(25):
        c = 10 ** np.random.uniform(-3, 3)
        r = 10 ** np.random.uniform(-3, 3)
        clf = svm.SVC(kernel='poly', degree=2, C=c, coef0=r, class_weight='balanced', gamma='auto')
        clf.fit(X_train, y_train)
        pred = clf.predict(X_test)
        accuracy_score = sklm.accuracy_score(y_test, pred)
        print(accuracy_score)


def run_one_class_svm(X_train, X_test, y_test):
    # Train
    clf = svm.OneClassSVM(gamma='auto')
    clf.fit(X_train)

    # Test
    pred = clf.predict(X_test)
    accuracy_score = sklm.accuracy_score(y_test, pred)
    print(y_test)
    print(pred)
    print(accuracy_score)

def actual_main():
    with open('config.json') as f:
        config = json.load(f)
    
    # Get params from config file
    normal_train_file_list = config['normal_train']
    abnormal_train_file_list = config['abnormal_train']
    normal_test_file_list = config['normal_test']
    abnormal_test_file_list = config['abnormal_test']
    train_num_frames_per_file = config['train_num_frames_per_file']
    test_num_frames_per_file = config['test_num_frames_per_file']
    window_size = config['window_size']

    # Get windows from train set
    normal_X_train, normal_y_train = get_window_features(normal_train_file_list, train_num_frames_per_file, window_size, 1)
    abnormal_X_train, abnormal_y_train = get_window_features(abnormal_train_file_list, train_num_frames_per_file, window_size, -1)
    X_train = normal_X_train + abnormal_X_train
    y_train = normal_y_train + abnormal_y_train

    # Get windows from test set
    normal_X_test, normal_y_test = get_window_features(normal_test_file_list, test_num_frames_per_file, window_size, 1)
    abnormal_X_test, abnormal_y_test = get_window_features(abnormal_test_file_list, test_num_frames_per_file, window_size, -1)
    X_test = normal_X_test + abnormal_X_test
    y_test = normal_y_test + abnormal_y_test

    # Train and test different models
    # SVM
    run_svm(X_train, y_train, X_test, y_test)

    # One-Class SVM
    # run_one_class_svm(X_train, X_test, y_test)

    print(X_train)

if __name__ == '__main__':
    actual_main()