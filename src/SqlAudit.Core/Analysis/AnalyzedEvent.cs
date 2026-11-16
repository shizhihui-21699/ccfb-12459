using SqlAudit.Core.Model;

namespace SqlAudit.Core.Analysis;

/// <summary>
/// 单条审计事件的分析结论。把原始事件与命中规则合并成一个可展示、可筛选的单元。
/// </summary>
public sealed class AnalyzedEvent
{
    public required AuditEvent Event { get; init; }

    public required IReadOnlyList<Finding> Findings { get; init; }

    /// <summary>风险分（0-100）。由 findings 权重累加并按规则类别去重衰减。</summary>
    public int RiskScore { get; init; }

    public Severity MaxSeverity { get; init; }

    /// <summary>命中的规则类别（去重）：SQL 注入 / 数据外泄 / 权限变更 …</summary>
    public IReadOnlyList<string> Categories { get; init; } = [];

    /// <summary>规则 ID 列表（去重，按严重度排序）。</summary>
    public IReadOnlyList<string> RuleIds { get; init; } = [];

    public bool HasFindings => Findings.Count > 0;

    public string ShortSummary =>
        Findings.Count == 0 ? "" : Findings.OrderByDescending(f => f.Severity).First().Message;

    public string StatementHash => Event.StatementHash;
}
