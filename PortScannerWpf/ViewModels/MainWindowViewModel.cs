using PortScannerWpf.Models;
using Prism.Commands;
using Prism.Mvvm;
using SharpPcap;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Net;
using System.Threading.Tasks;

namespace PortScannerWpf.ViewModels
{
    public class MainWindowViewModel : BindableBase
    {
        #region コマンド・プロパティ
        private string _title = "PortScannerWpf";
        /// <summary>
        /// タイトル
        /// </summary>
        public string Title
        {
            get { return _title; }
            set { SetProperty(ref _title, value); }
        }

        private CaptureDeviceList _deviceList;
        /// <summary>
        /// デバイス一覧
        /// </summary>
        public CaptureDeviceList DeviceList
        {
            get { return _deviceList; }
            set { SetProperty(ref _deviceList, value); }
        }

        private ICaptureDevice _selectedCaptureDevice;
        /// <summary>
        /// 選択されたデバイス
        /// </summary>
        public ICaptureDevice SelectedCaptureDevice
        {
            get { return _selectedCaptureDevice; }
            set { SetProperty(ref _selectedCaptureDevice, value); }
        }

        private bool _isBusy = false;
        /// <summary>
        /// 処理中フラグ
        /// </summary>
        public bool IsBusy
        {
            get { return _isBusy; }
            set { SetProperty(ref _isBusy, value); }
        }

        private string _targets;
        public string Targets
        {
            get { return _targets; }
            set { SetProperty(ref _targets, value); }
        }

        public ObservableCollection<ScanResponse> ScanResponses { get; set; } = new ObservableCollection<ScanResponse>();

        /// <summary>
        /// スキャン開始コマンド
        /// </summary>
        public DelegateCommand StartScanCommand { get; private set; }
        #endregion

        /// <summary>
        /// コンストラクタ
        /// </summary>
        public MainWindowViewModel()
        {
            // コマンドを定義
            StartScanCommand = new DelegateCommand(ExecuteStartScanCommand, CanExecuteStartScanCommand);
            StartScanCommand.ObservesProperty(() => SelectedCaptureDevice);
            StartScanCommand.ObservesProperty(() => IsBusy);

            // デバイス一覧取得
            DeviceList = CaptureDeviceList.Instance;
        }

        private async void ExecuteStartScanCommand()
        {
            var responses = await GetResponseAsync();
            ScanResponses.Clear();
            foreach (var res in responses)
            {
                ScanResponses.Add(res);
            }
        }

        private async Task<List<ScanResponse>> GetResponseAsync()
        {
            var ret = new List<ScanResponse>();
            await Task.Run(() =>
            {
                IsBusy = true;
                var requests = CreateScanRequest(Targets);
                var model = new PortScanModel(SelectedCaptureDevice, requests);
                ret = model.Execute();
                IsBusy = false;
            }).ConfigureAwait(false);
            return ret;
        }

        private bool CanExecuteStartScanCommand()
        {
            return SelectedCaptureDevice != null && !IsBusy;
        }

        private List<ScanRequest> CreateScanRequest(string source)
        {
            var ret = new List<ScanRequest>();

            string[] lines = source.Split(new[] { Environment.NewLine }, StringSplitOptions.RemoveEmptyEntries);
            foreach (string line in lines)
            {
                int colonIndex = line.IndexOf(':');
                if (colonIndex == -1)
                {
                    continue;
                }
                string host = line.Substring(0, colonIndex);
                string port = line.Substring(colonIndex + 1);
                try
                {
                    var tryAddress = IPAddress.Parse(host);
                    ushort tryPort = ushort.Parse(port);
                    ret.Add(new ScanRequest()
                    {
                        IPAddress = tryAddress,
                        Port = tryPort
                    });
                }
                catch (Exception ex)
                {
                    continue;
                }
            }
            return ret;
        }
    }
}
