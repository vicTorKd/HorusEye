#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2021/11/30 下午5:01
# @Author  : Yutao Dong
# @Site    : 
# @File    : AE.py
# @Software: PyCharm
import torch
import torch.nn as nn
import torch.nn.functional as F


class hswish(nn.Module):
    def forward(self, x):
        out = x * F.relu6(x + 3, inplace=True) / 6
        return out


class Kitsune(nn.Module):  # Kitsune model when m=1, used for complexity test
    def __init__(self, input_size=100, hidden_rate=0.75):
        super(Kitsune, self).__init__()
        self.input_size = input_size
        self.hidden_rate = hidden_rate
        self.thr = 1
        self.EnsembleLayer = nn.Sequential(
            # encoder
            nn.Conv1d(in_channels=self.input_size, out_channels=self.input_size, kernel_size=1,  # 100
                      stride=1, bias=False, groups=self.input_size),
            nn.Sigmoid(),
            # decoder
            nn.Conv1d(in_channels=self.input_size, out_channels=self.input_size, kernel_size=1,  # 100
                      stride=1, bias=False, groups=self.input_size),
            nn.Sigmoid()
        )
        self.OutputLayer = nn.Sequential(
            nn.Linear(self.input_size, int(self.input_size * self.hidden_rate)),
            nn.Sigmoid(),
            nn.Linear(int(self.input_size * self.hidden_rate), self.input_size),
            nn.Sigmoid()
        )

    def forward(self, x):
        # reshape input to 100 channels for conv1d
        x = torch.reshape(x, (-1, self.input_size, 1))
        out = self.EnsembleLayer(x)
        # reshape output to 1 channel for ae
        out = torch.reshape(out, (-1, 1, self.input_size))
        out = self.OutputLayer(out)
        return out

    def excute_RMSE(self, input, target):
        mse = (input - target).pow(2).sum(2) / self.input_size
        rmse = torch.sqrt(mse)
        return rmse.detach().cpu().numpy().reshape(-1)  # 0 :error 1:normal

    def pred(self, input, target):
        rmse = self.excute_RMSE(input, target)
        return rmse > self.thr

    def set_thr(self, thr):
        self.thr = thr


class CNN_AE(nn.Module):
    def __init__(self, input_size=16):
        super(CNN_AE, self).__init__()

        self.input_size = input_size
        self.thr = 1
        d_dim = 16
        self._stage_out_channels = 32
        self.conv = nn.Sequential(
            nn.Conv1d(in_channels=1, out_channels=d_dim, kernel_size=3,  # 100
                      stride=1, dilation=1, bias=False, groups=1),
            nn.BatchNorm1d(d_dim),
            hswish()
        )
        output_channels = self._stage_out_channels
        self.conv1 = nn.Sequential(
            nn.Conv1d(in_channels=d_dim, out_channels=d_dim, kernel_size=3,  # 100
                      stride=1, dilation=2, padding=2, bias=False, groups=d_dim),
            nn.BatchNorm1d(d_dim),
            nn.Conv1d(in_channels=d_dim, out_channels=output_channels, kernel_size=1,  # 100
                      stride=1, padding=0, bias=False),
            nn.BatchNorm1d(output_channels),
            hswish()
        )
        self.maxpool1 = nn.MaxPool1d(kernel_size=3, stride=3, padding=1)  # 33
        input_channels = output_channels
        self.conv2 = nn.Sequential(
            nn.Conv1d(in_channels=input_channels, out_channels=output_channels, kernel_size=3,
                      stride=1, dilation=5, padding=2, bias=False, groups=1),  # 33
            nn.BatchNorm1d(output_channels),
            hswish(),
        )
        self.decoder = nn.Sequential(
            nn.Linear(864, input_size),
            nn.BatchNorm1d(1),
            hswish(),
        )
        self.flatten = nn.Sequential(
            nn.Flatten()
        )

    def forward(self, x):
        out = self.conv(x)
        out = self.conv1(out)
        out = self.maxpool1(out)
        out = self.conv2(out)
        out = self.flatten(out)
        out = torch.unsqueeze(out, dim=1)
        out = self.decoder(out)
        return out

    def excute_RMSE(self, input, target):
        mse = (input - target).pow(2).sum(2) / self.input_size
        rmse = torch.sqrt(mse)
        return rmse.detach().cpu().numpy().reshape(-1)  # 0 :error 1:normal

    def pred(self, input, target):
        rmse = self.excute_RMSE(input, target)
        return rmse > self.thr

    def set_thr(self, thr):
        self.thr = thr

