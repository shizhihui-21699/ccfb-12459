namespace SqlAudit.Core.Model;

/// <summary>严重级别，数值可用于排序与阈值过滤。</summary>
public enum Severity
{
    None = 0,
    Info = 1,
    Low = 2,
    Medium = 3,
    High = 4,
    Critical = 5,
}

public static class SeverityExtensions
{
    public static string ToLabel(this Severity severity) => severity switch
    {
        Severity.Critical => "严重",
        Severity.High => "高危",
        Severity.Medium => "中危",
        Severity.Low => "低危",
        Severity.Info => "提示",
        _ => "无",
    };

    /// <summary>告警风险分权重（单条 finding 的贡献）。</summary>
    public static int ToWeight(this Severity severity) => severity switch
    {
        Severity.Critical => 70,
        Severity.High => 45,
        Severity.Medium => 20,
        Severity.Low => 8,
        Severity.Info => 2,
        _ => 0,
    };
}
