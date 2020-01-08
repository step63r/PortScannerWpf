using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;
using SharpPcap.Npcap;
using SharpPcap.WinPcap;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace PortScannerWpf.Models
{
    /// <summary>
    /// ポートスキャンのビジネスロジッククラス
    /// </summary>
    public class PortScanModel
    {
        /// <summary>
        /// ネットワークデバイス
        /// </summary>
        private readonly ICaptureDevice _captureDevice;
        /// <summary>
        /// スキャン要求
        /// </summary>
        private readonly List<ScanRequest> _scanRequests;
        /// <summary>
        /// 最大リトライ回数
        /// </summary>
        private readonly int _maxRetryCount;

        /// <summary>
        /// コンストラクタ
        /// </summary>
        /// <param name="captureDevice">ネットワークデバイス</param>
        /// <param name="scanRequests">スキャン要求</param>
        /// <param name="maxRetryCount">最大リトライ回数</param>
        public PortScanModel(ICaptureDevice captureDevice, List<ScanRequest> scanRequests, int maxRetryCount = 3)
        {
            _captureDevice = captureDevice;
            _scanRequests = scanRequests;
            _maxRetryCount = maxRetryCount;
        }

        /// <summary>
        /// 実行する
        /// </summary>
        public List<ScanResponse> Execute()
        {
            var ret = new List<ScanResponse>();
            // デバイス変換
            var device = _captureDevice as NpcapDevice;

            if (device == null)
            {
                throw new InvalidCastException(string.Format("デバイス {0} を NpcapDevice に変換できません", device.Description));
            }

            // 送信元IPアドレス
            var srcIPAddress = GetIPv4(device);

            // SYNスキャン
            foreach (var request in _scanRequests)
            {
                // 送信先MACアドレス
                var arp = new ARP(device);
                var targetMacAddress = arp.Resolve(request.IPAddress);

                if (targetMacAddress == null)
                {
                    ret.Add(new ScanResponse()
                    {
                        IPAddress = request.IPAddress,
                        Port = request.Port,
                        Status = PortStatus.UnResolved
                    });
                    continue;
                    //throw new InvalidOperationException(string.Format("アドレス {0} を ARP 解決できません", request.IPAddress.ToString()));
                }

                // TCPヘッダ生成
                var tcpPacket = new TcpPacket(1024, request.Port);
                tcpPacket.Synchronize = !tcpPacket.Synchronize;
                tcpPacket.WindowSize = 4096;

                // IPヘッダ生成
                var ipPacket = new IPv4Packet(srcIPAddress, request.IPAddress);

                // Ehternetヘッダ生成
                var ethernetPacket = new EthernetPacket(device.Interface.MacAddress, targetMacAddress, EthernetType.None);

                // TCPパケット生成
                ipPacket.PayloadPacket = tcpPacket;
                tcpPacket.UpdateTcpChecksum();
                ethernetPacket.PayloadPacket = ipPacket;
                ipPacket.UpdateIPChecksum();

                for (int retryCount = 0; retryCount < _maxRetryCount; retryCount++)
                {
                    // オープン
                    device.Open(DeviceMode.Normal, 1000);
                    // フィルタセット
                    device.Filter = "src host " + request.IPAddress + " and src port " + request.Port + " and (tcp[13] & 18 != 0) or (tcp[13] & 4 != 0)";

                    try
                    {
                        // TCPパケット送信
                        device.SendPacket(ethernetPacket);

                        // 受信パケット取得
                        var rawpacket = device.GetNextPacket();

                        if (rawpacket == null)
                        {
                            if ((retryCount + 1) >= _maxRetryCount)
                            {
                                ret.Add(new ScanResponse()
                                {
                                    IPAddress = request.IPAddress,
                                    Port = request.Port,
                                    Status = PortStatus.Timeout
                                });
                                break;
                            }
                            continue;
                        }
                        else
                        {
                            // SYN/ACKフラグが立っていたら、open判定
                            // RSTフラグが立っていたらclosed判定
                            var response = Packet.ParsePacket(rawpacket.LinkLayerType, rawpacket.Data);
                            if (response is EthernetPacket eth)
                            {
                                var ip = response.Extract<IPPacket>();
                                if (ip != null)
                                {
                                    var tcp = response.Extract<TcpPacket>();
                                    if (tcp != null)
                                    {
                                        if (tcp.Acknowledgment && tcp.Synchronize)
                                        {
                                            ret.Add(new ScanResponse()
                                            {
                                                IPAddress = request.IPAddress,
                                                Port = request.Port,
                                                Status = PortStatus.Open
                                            });
                                        }
                                        else if (tcp.Reset)
                                        {
                                            ret.Add(new ScanResponse()
                                            {
                                                IPAddress = request.IPAddress,
                                                Port = request.Port,
                                                Status = PortStatus.Closed
                                            });
                                        }
                                        else
                                        {
                                            ret.Add(new ScanResponse()
                                            {
                                                IPAddress = request.IPAddress,
                                                Port = request.Port,
                                                Status = PortStatus.UnKnown
                                            });
                                        }
                                    }
                                }
                            }
                            break;
                        }
                    }
                    catch (Exception ex)
                    {
                        throw new Exception(ex.Message);
                    }
                    finally
                    {
                        if (device.Opened)
                        {
                            device.Close();
                        }
                    }
                }
            }
            return ret;
        }

        /// <summary>
        /// 指定デバイスからIPv4アドレスを取得する
        /// </summary>
        /// <param name="captureDevice"></param>
        /// <returns></returns>
        private IPAddress GetIPv4(NpcapDevice device)
        {
            foreach (var addr in device.Addresses)
            {
                if (addr.Netmask.ToString() != "")
                {
                    return IPAddress.Parse(addr.Addr.ToString());
                }
            }
            throw new InvalidOperationException(string.Format("デバイス {0} に有効な IPv4 アドレスが見つかりませんでした", device.Description));
        }
    }
}
