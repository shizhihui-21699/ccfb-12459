using SqlAudit.Core.Analysis;
using SqlAudit.Core.Model;

namespace SqlAudit.Web.Storage;

/// <summary>一次导入的元信息。</summary>
public sealed class ImportBatch
{
    public long Id { get; set; }

    public required string FileName { get; init; }

    public long FileSize { get; init; }

    public AuditSource Source { get; init; }

    public bool SourceWasAutoDetected { get; init; }

    public DateTimeOffset ImportedAt { get; init; }

    public int EventCount { get; init; }

    public int AlertCount { get; init; }

    public int DiagnosticCount { get; init; }

    public string? Note { get; init; }
}

/// <summary>筛选条件。所有字段可组合，null 表示不限。</summary>
public sealed class EventQuery
{
    public string? Account { get; init; }

    public string? Database { get; init; }

    public DateTimeOffset? From { get; init; }

    public DateTimeOffset? To { get; init; }

    /// <summary>仅返回存在告警的事件。</summary>
    public bool AlertsOnly { get; init; }

    /// <summary>最低严重度。</summary>
    public Severity? MinSeverity { get; init; }

    /// <summary>按规则 ID 过滤（任一命中即可）。</summary>
    public IReadOnlyList<string>? RuleIds { get; init; }

    /// <summary>按来源过滤。</summary>
    public AuditSource? Source { get; init; }

    /// <summary>自由文本：匹配 SQL、账号、客户端地址。</summary>
    public string? Text { get; init; }

    /// <summary>仅某个导入批次。</summary>
    public long? BatchId { get; init; }

    public int Limit { get; init; } = 50;

    public int Offset { get; init; }
}

public sealed record PageResult<T>(IReadOnlyList<T> Items, int Total, int Limit, int Offset);

/// <summary>审计数据仓储。</summary>
public interface IAuditRepository
{
    Task InitializeAsync(CancellationToken ct = default);

    Task<long> AddBatchAsync(ImportBatch batch, IReadOnlyList<AnalyzedEvent> events, CancellationToken ct = default);

    Task<IReadOnlyList<ImportBatch>> ListBatchesAsync(CancellationToken ct = default);

    Task<bool> DeleteBatchAsync(long batchId, CancellationToken ct = default);

    Task<PageResult<AnalyzedEvent>> QueryEventsAsync(EventQuery query, CancellationToken ct = default);

    Task<AnalyzedEvent?> GetEventAsync(long id, CancellationToken ct = default);

    /// <summary>按当前筛选条件统计账号/库/时间分布，用于前端筛选下拉与概览。</summary>
    Task<OverviewStats> GetOverviewAsync(CancellationToken ct = default);

    Task<IReadOnlyList<SessionChain>> GetChainsAsync(CancellationToken ct = default);

    IReadOnlyList<RuleDefinition> Rules { get; }
}

public sealed class OverviewStats
{
    public int TotalEvents { get; init; }

    public int AlertedEvents { get; init; }

    public int CriticalEvents { get; init; }

    public IReadOnlyList<FacetCount> Accounts { get; init; } = [];

    public IReadOnlyList<FacetCount> Databases { get; init; } = [];

    public IReadOnlyList<FacetCount> Sources { get; init; } = [];

    public IReadOnlyList<RuleCount> RuleHits { get; init; } = [];

    public IReadOnlyList<DayCount> Timeline { get; init; } = [];

    public IReadOnlyList<AccountDatabase> AccountDatabases { get; init; } = [];

    public DateTimeOffset? Earliest { get; init; }

    public DateTimeOffset? Latest { get; init; }
}

public sealed record FacetCount(string Value, int Count);

public sealed record RuleCount(string RuleId, string Name, int Count);

public sealed record DayCount(string Day, int Total, int Alerts);

public sealed record AccountDatabase(string Account, string Database, int Count);
