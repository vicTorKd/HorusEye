import torch
import torch.nn as nn
import torch.nn.functional as F
import math


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


class CNN_AE_channel(nn.Module):
    def __init__(self, input_size=16):
        super(CNN_AE_channel, self).__init__()

        self.input_size = input_size
        self.thr = 1
        d_dim = 20
        self._stage_out_channels = 80
        self.flatten_size = int(math.ceil(self.input_size/(3*5))*self._stage_out_channels)
        self.conv = nn.Sequential(
            nn.Conv1d(in_channels=5, out_channels=d_dim, kernel_size=3,  # 20
                      stride=1, dilation=1, padding=1, bias=False, groups=1),
            nn.BatchNorm1d(d_dim),
            hswish()
        )
        output_channels = 2*d_dim
        self.conv1 = nn.Sequential(
            nn.Conv1d(in_channels=d_dim, out_channels=d_dim, kernel_size=3,  # 20
                      stride=1, dilation=2, padding=2, bias=False, groups=d_dim),
            nn.BatchNorm1d(d_dim),
            nn.Conv1d(in_channels=d_dim, out_channels=output_channels, kernel_size=1,  # 20
                      stride=1, padding=0, bias=False),
            nn.BatchNorm1d(output_channels),
            hswish()
        )
        input_channels = output_channels
        output_channels = self._stage_out_channels
        self.conv2 = nn.Sequential(
            nn.Conv1d(in_channels=input_channels, out_channels=input_channels, kernel_size=3,  # 20
                      stride=1, dilation=3, padding=3, bias=False, groups=input_channels),
            nn.BatchNorm1d(input_channels),
            nn.Conv1d(in_channels=input_channels, out_channels=output_channels, kernel_size=1,  # 20
                      stride=1, padding=0, bias=False),
            nn.BatchNorm1d(output_channels),
            hswish()
        )
        self.maxpool1 = nn.MaxPool1d(kernel_size=3, stride=3, padding=1)  # upper(20/3)=7
        input_channels = output_channels
        self.conv3 = nn.Sequential(
            nn.Conv1d(in_channels=input_channels, out_channels=output_channels, kernel_size=3,
                      stride=1, dilation=1, padding=1, bias=False, groups=1),  # 7
            nn.BatchNorm1d(output_channels),
            hswish(),
        )
        self.decoder = nn.Sequential(
            nn.Linear(self.flatten_size, self.input_size), # 7*80=560
            nn.BatchNorm1d(1),
            hswish()
        )
        self.flatten = nn.Sequential(
            nn.Flatten()
        )

    def forward(self, x):
        out = self.conv(x)
        out = self.conv1(out)
        out = self.conv2(out)
        out = self.maxpool1(out)
        out = self.conv3(out)
        out = self.flatten(out)
        out = torch.unsqueeze(out, dim=1)
        out = self.decoder(out)
        out = torch.reshape(out, (-1,5,int(self.input_size/5)))
        return out

    def excute_RMSE(self, input, target):
        input = torch.reshape(input, (-1,1,self.input_size))
        target = torch.reshape(target, (-1,1,self.input_size))
        mse = (input - target).pow(2).sum(2) / self.input_size
        rmse = torch.sqrt(mse)
        return rmse.detach().cpu().numpy().reshape(-1)  # 0 :error 1:normal

    def pred(self, input, target):
        rmse = self.excute_RMSE(input, target)
        return rmse > self.thr

    def set_thr(self, thr):
        self.thr = thr
