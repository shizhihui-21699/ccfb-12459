namespace SqlAudit.Core.Model;

/// <summary>规则命中结果。</summary>
public sealed class Finding
{
    public required string RuleId { get; init; }

    public required string RuleName { get; init; }

    public required Severity Severity { get; init; }

    /// <summary>面向分析人员的结论描述。</summary>
    public required string Message { get; init; }

    /// <summary>命中的 SQL 片段（截断）。</summary>
    public string Evidence { get; init; } = "";

    /// <summary>证据在 SQL 原文中的起始偏移，便于前端高亮。</summary>
    public int? Offset { get; init; }

    public int? Length { get; init; }
}

/// <summary>规则元数据，供规则说明页与前端展示。</summary>
public sealed record RuleDefinition(
    string Id,
    string Name,
    string NameZh,
    string Category,
    string Description,
    Severity DefaultSeverity);
