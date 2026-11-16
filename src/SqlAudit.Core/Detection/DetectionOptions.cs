namespace SqlAudit.Core.Detection;

/// <summary>检测阈值配置。可从 appsettings.json 覆盖，便于按业务调整误报率。</summary>
public sealed class DetectionOptions
{
    /// <summary>返回行数的绝对告警阈值。</summary>
    public long RowsAbsoluteThreshold { get; set; } = 100_000;

    /// <summary>返回行数的绝对严重阈值。</summary>
    public long RowsExtremeThreshold { get; set; } = 1_000_000;

    /// <summary>相对基线倍数：超过该账号同库历史 P99 的 N 倍视为异常。</summary>
    public double BaselineMultiplier { get; set; } = 8.0;

    /// <summary>建立基线所需的最少样本数；样本不足时只做绝对阈值判定。</summary>
    public int BaselineMinSamples { get; set; } = 20;

    /// <summary>时间盲注中视为“可疑延时”的最小秒数。</summary>
    public double SuspiciousDelaySeconds { get; set; } = 1.0;

    /// <summary>单条语句命中的 finding 上限，避免畸形输入拖垮评分。</summary>
    public int MaxFindingsPerStatement { get; set; } = 20;

    /// <summary>是否对 AND 侧永真条件（如 AND 1=1）也输出 finding。</summary>
    public bool ReportAndTautology { get; set; } = true;
}
