using SqlAudit.Core.Model;

namespace SqlAudit.Core.Analysis;

/// <summary>同一会话内的可疑行为聚合结果。</summary>
public sealed class SessionChain
{
    public required string SessionKey { get; init; }

    public string Account { get; init; } = "";

    public string Database { get; init; } = "";

    public string? ClientHost { get; init; }

    public DateTimeOffset FirstSeen { get; init; }

    public DateTimeOffset LastSeen { get; init; }

    /// <summary>参与聚合的高风险事件（按时间排序）。</summary>
    public required IReadOnlyList<AnalyzedEvent> Events { get; init; }

    public int MaxRiskScore { get; init; }

    public Severity MaxSeverity { get; init; }

    /// <summary>会话中出现的规则（去重）。</summary>
    public required IReadOnlyList<string> RuleIds { get; init; }

    /// <summary>攻击阶段推断，如“探测 → 盲注 → 外泄”。</summary>
    public required IReadOnlyList<string> Stages { get; init; }

    public int EventCount => Events.Count;
}

/// <summary>
/// 会话级关联。单条注入探测语句可能看起来零散，但同一连接里
/// 依次出现「列数探测 → UNION 读取字典 → 大结果集导出」就是一条清晰的攻击链。
/// 判定：同一 (SessionId 或 account+client) 且时间窗口内（默认 30 分钟）命中 ≥ 2 条不同注入规则，
/// 或命中任意 critical 事件即形成链路。
/// </summary>
public static class SessionCorrelator
{
    private static readonly HashSet<string> InjectionRules = new(StringComparer.OrdinalIgnoreCase)
    {
        RuleCatalog.Tautology, RuleCatalog.StackedQuery, RuleCatalog.UnionInjection,
        RuleCatalog.TimeBasedBlind, RuleCatalog.ExecutableComment, RuleCatalog.CredentialStoreAccess,
    };

    private static readonly HashSet<string> ExfiltrationRules = new(StringComparer.OrdinalIgnoreCase)
    {
        RuleCatalog.LargeResultSet, RuleCatalog.BulkExport,
    };

    public static IReadOnlyList<SessionChain> Correlate(
        IEnumerable<AnalyzedEvent> analyzed, TimeSpan? window = null, int minEvents = 2)
    {
        var span = window ?? TimeSpan.FromMinutes(30);
        var groups = new Dictionary<string, List<AnalyzedEvent>>(StringComparer.Ordinal);

        foreach (var item in analyzed)
        {
            if (!item.HasFindings) continue;
            // 只有注入类、外泄类、权限变更事件参与会话链
            var relevant = item.RuleIds.Any(id =>
                InjectionRules.Contains(id) || ExfiltrationRules.Contains(id)
                || string.Equals(id, RuleCatalog.PrivilegeChange, StringComparison.OrdinalIgnoreCase));
            if (!relevant) continue;

            var key = SessionKeyOf(item.Event);
            if (!groups.TryGetValue(key, out var list))
            {
                list = new List<AnalyzedEvent>();
                groups[key] = list;
            }
            list.Add(item);
        }

        var chains = new List<SessionChain>();

        foreach (var (key, items) in groups)
        {
            items.Sort((a, b) => a.Event.Timestamp.CompareTo(b.Event.Timestamp));

            // 按时间窗口切分成若干段
            var segment = new List<AnalyzedEvent>();
            foreach (var item in items)
            {
                if (segment.Count > 0 && item.Event.Timestamp - segment[^1].Event.Timestamp > span)
                {
                    EmitChain(key, segment, chains, minEvents);
                    segment = new List<AnalyzedEvent>();
                }
                segment.Add(item);
            }
            EmitChain(key, segment, chains, minEvents);
        }

        return chains.OrderByDescending(c => c.MaxRiskScore).ThenBy(c => c.FirstSeen).ToList();
    }

    private static void EmitChain(string key, List<AnalyzedEvent> segment, List<SessionChain> output, int minEvents)
    {
        if (segment.Count < minEvents) return;

        var distinctInjectionRules = segment
            .SelectMany(e => e.RuleIds)
            .Where(id => InjectionRules.Contains(id))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Count();

        var hasCritical = segment.Any(e => e.MaxSeverity == Severity.Critical);

        // 至少两条不同注入规则，或存在严重事件，才构成可上报的攻击链
        if (distinctInjectionRules < 2 && !hasCritical) return;

        var first = segment[0].Event;
        var ruleIds = segment.SelectMany(e => e.RuleIds).Distinct(StringComparer.OrdinalIgnoreCase).ToList();

        output.Add(new SessionChain
        {
            SessionKey = key,
            Account = first.Account,
            Database = first.Database,
            ClientHost = segment.Select(e => e.Event.ClientHost).FirstOrDefault(h => !string.IsNullOrEmpty(h)),
            FirstSeen = first.Timestamp,
            LastSeen = segment[^1].Event.Timestamp,
            Events = segment,
            MaxRiskScore = segment.Max(e => e.RiskScore),
            MaxSeverity = segment.Max(e => e.MaxSeverity),
            RuleIds = ruleIds,
            Stages = InferStages(segment),
        });
    }

    /// <summary>
    /// 按事件发生顺序推断阶段，同一阶段只保留首次出现的位置。
    /// 用固定表顺序会让「先提权再导出」显示成「先导出再提权」，与会话时间线矛盾。
    /// </summary>
    private static List<string> InferStages(IReadOnlyList<AnalyzedEvent> orderedEvents)
    {
        var stages = new List<string>();
        foreach (var item in orderedEvents)
        {
            var stage = StageOf(item.RuleIds);
            if (stage is not null && !stages.Contains(stage)) stages.Add(stage);
        }
        return stages;
    }

    private static string? StageOf(IReadOnlyList<string> ruleIds)
    {
        if (ruleIds.Any(id => id is RuleCatalog.Tautology or RuleCatalog.StackedQuery
                or RuleCatalog.ExecutableComment))
            return "注入探测";
        if (ruleIds.Any(id => id is RuleCatalog.UnionInjection or RuleCatalog.CredentialStoreAccess))
            return "信息收集";
        if (ruleIds.Any(id => id is RuleCatalog.TimeBasedBlind))
            return "盲注拖延";
        if (ruleIds.Any(id => id is RuleCatalog.PrivilegeChange))
            return "权限变更";
        if (ruleIds.Any(id => id is RuleCatalog.LargeResultSet or RuleCatalog.BulkExport))
            return "数据外泄";
        return null;
    }

    private static string SessionKeyOf(AuditEvent ev)
    {
        if (!string.IsNullOrWhiteSpace(ev.SessionId))
            return $"session:{ev.Source}:{ev.SessionId}";
        return $"client:{ev.Account}@{ev.ClientHost}";
    }
}
