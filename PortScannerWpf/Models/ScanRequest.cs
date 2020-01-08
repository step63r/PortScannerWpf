using System.Net;

namespace PortScannerWpf.Models
{
    /// <summary>
    /// スキャン要求
    /// </summary>
    public class ScanRequest
    {
        /// <summary>
        /// 
        /// </summary>
        public IPAddress IPAddress { get; set; }
        /// <summary>
        /// 
        /// </summary>
        public ushort Port { get; set; }
    }
}
