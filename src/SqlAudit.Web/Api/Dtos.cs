using SqlAudit.Core.Analysis;
using SqlAudit.Core.Model;
using SqlAudit.Web.Storage;

namespace SqlAudit.Web.Api;

// 对外 DTO。刻意与领域模型分离：领域模型会随规则演进，
// 而前端契约应保持稳定，且不应把内部字段（如 rawRecord）无条件暴露。

public sealed record FindingDto(
    string RuleId,
    string RuleName,
    string RuleNameZh,
    string Severity,
    string SeverityLabel,
    string Category,
    string Message,
    string Evidence,
    int? Offset,
    int? Length);

public sealed record EventDto(
    long Id,
    string Source,
    string SourceLabel,
    string Timestamp,
    string Account,
    string Database,
    string? ClientHost,
    string? ServerHost,
    string? CommandTag,
    string? SessionId,
    string Statement,
    long? RowsReturned,
    long? RowsAffected,
    double? DurationMs,
    bool Succeeded,
    string? ErrorCode,
    string? SourceFile,
    int SourceLine,
    int RiskScore,
    string MaxSeverity,
    string MaxSeverityLabel,
    string[] RuleIds,
    string[] Categories,
    // findings 只在详情接口返回，列表接口用摘要降低载荷
    IReadOnlyList<FindingDto>? Findings = null,
    string? RawRecord = null);

public sealed record BatchDto(
    long Id,
    string FileName,
    long FileSize,
    string Source,
    string SourceLabel,
    bool AutoDetected,
    string ImportedAt,
    int EventCount,
    int AlertCount,
    int CriticalCount,
    int DiagnosticCount,
    string? Note);

public sealed record ChainEventDto(
    long Id,
    string Timestamp,
    string Statement,
    int RiskScore,
    string[] RuleIds);

public sealed record ChainDto(
    string SessionKey,
    string Account,
    string Database,
    string? ClientHost,
    string FirstSeen,
    string LastSeen,
    int EventCount,
    int MaxRiskScore,
    string MaxSeverity,
    string MaxSeverityLabel,
    string[] RuleIds,
    string[] Stages,
    IReadOnlyList<ChainEventDto> Events);

public sealed record RuleDto(
    string Id,
    string Name,
    string NameZh,
    string Category,
    string Description,
    string DefaultSeverity,
    string DefaultSeverityLabel,
    int HitCount);

public sealed record OverviewDto(
    int TotalEvents,
    int AlertedEvents,
    int CriticalEvents,
    int BatchCount,
    IReadOnlyList<FacetDto> Accounts,
    IReadOnlyList<FacetDto> Databases,
    IReadOnlyList<FacetDto> Sources,
    IReadOnlyList<RuleHitDto> RuleHits,
    IReadOnlyList<DayDto> Timeline,
    IReadOnlyList<AccountDatabaseDto> AccountDatabases,
    string? Earliest,
    string? Latest);

public sealed record FacetDto(string Value, int Count);

public sealed record RuleHitDto(string RuleId, string Name, int Count);

public sealed record DayDto(string Day, int Total, int Alerts);

public sealed record AccountDatabaseDto(string Account, string Database, int Count);

public sealed record PagedDto<T>(IReadOnlyList<T> Items, int Total, int Limit, int Offset);

public static class DtoMapper
{
    public static EventDto ToDto(AnalyzedEvent item, bool includeDetail = false)
    {
        var ev = item.Event;
        return new EventDto(
            ev.Id,
            ev.Source.ToCode(),
            ev.Source.ToLabel(),
            ev.Timestamp.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'"),
            ev.Account,
            ev.Database,
            ev.ClientHost,
            ev.ServerHost,
            ev.CommandTag,
            ev.SessionId,
            ev.Statement,
            ev.RowsReturned,
            ev.RowsAffected,
            ev.DurationMs is { } d ? Math.Round(d, 3) : null,
            ev.Succeeded,
            ev.ErrorCode,
            ev.SourceFile,
            ev.SourceLine,
            item.RiskScore,
            item.MaxSeverity.ToString().ToLowerInvariant(),
            item.MaxSeverity.ToLabel(),
            item.RuleIds.ToArray(),
            item.Categories.ToArray(),
            includeDetail ? item.Findings.Select(ToDto).ToList() : null,
            includeDetail ? ev.RawRecord : null);
    }

    public static FindingDto ToDto(Finding finding)
    {
        var def = RuleCatalog.Get(finding.RuleId);
        return new FindingDto(
            finding.RuleId,
            def?.Name ?? finding.RuleName,
            def?.NameZh ?? RuleCatalog.NameOf(finding.RuleId),
            finding.Severity.ToString().ToLowerInvariant(),
            finding.Severity.ToLabel(),
            def?.Category ?? "其他",
            finding.Message,
            finding.Evidence,
            finding.Offset,
            finding.Length);
    }

    public static ChainDto ToDto(SessionChain chain) => new(
        chain.SessionKey,
        chain.Account,
        chain.Database,
        chain.ClientHost,
        chain.FirstSeen.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'"),
        chain.LastSeen.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'"),
        chain.EventCount,
        chain.MaxRiskScore,
        chain.MaxSeverity.ToString().ToLowerInvariant(),
        chain.MaxSeverity.ToLabel(),
        chain.RuleIds.ToArray(),
        chain.Stages.ToArray(),
        chain.Events.Select(e => new ChainEventDto(
            e.Event.Id,
            e.Event.Timestamp.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'"),
            e.Event.Statement,
            e.RiskScore,
            e.RuleIds.ToArray())).ToList());

    public static RuleDto ToDto(RuleDefinition rule, int hitCount) => new(
        rule.Id,
        rule.Name,
        rule.NameZh,
        rule.Category,
        rule.Description,
        rule.DefaultSeverity.ToString().ToLowerInvariant(),
        rule.DefaultSeverity.ToLabel(),
        hitCount);
}
