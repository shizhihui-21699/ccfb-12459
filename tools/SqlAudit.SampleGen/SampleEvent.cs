namespace SqlAudit.SampleGen;

/// <summary>单条待输出的事件（与具体日志格式解耦）。</summary>
public sealed class SampleEvent
{
    public required DateTimeOffset Timestamp { get; init; }

    public required string Account { get; init; }

    public required string Database { get; init; }

    public string ClientHost { get; init; } = "";

    public string SessionId { get; init; } = "";

    public string Command { get; init; } = "Query";

    public required string Statement { get; init; }

    public long? RowsReturned { get; init; }

    public long? RowsAffected { get; init; }

    /// <summary>毫秒。</summary>
    public double? DurationMs { get; init; }

    public bool Succeeded { get; init; } = true;

    public string? ErrorCode { get; init; }

    /// <summary>生成器内部标记：用于自检“埋点是否都被检测到”。</summary>
    public string? Label { get; init; }
}

public sealed class SampleDataset
{
    public required string Name { get; init; }

    public required IReadOnlyList<SampleEvent> Events { get; init; }

    /// <summary>应当被检出的事件标签及期望命中的规则。</summary>
    public required IReadOnlyDictionary<string, string[]> ExpectedFindings { get; init; }
}
