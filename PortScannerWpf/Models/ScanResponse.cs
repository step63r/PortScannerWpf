using System.Net;

namespace PortScannerWpf.Models
{
    /// <summary>
    /// スキャン応答
    /// </summary>
    public class ScanResponse
    {
        /// <summary>
        /// IPアドレス
        /// </summary>
        public IPAddress IPAddress { get; set; }
        /// <summary>
        /// ポート番号
        /// </summary>
        public ushort Port { get; set; }
        /// <summary>
        /// 状態
        /// </summary>
        public PortStatus Status { get; set; }
    }
}
