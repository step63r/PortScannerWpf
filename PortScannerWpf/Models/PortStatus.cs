namespace PortScannerWpf.Models
{
    /// <summary>
    /// ポート状態
    /// </summary>
    public enum PortStatus
    {
        Open,
        Closed,
        UnKnown,
        Timeout,
        UnResolved
    }
}
