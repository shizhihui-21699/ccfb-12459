using SqlAudit.Core.Model;

namespace SqlAudit.Core.Detection;

/// <summary>
/// 账号×数据库维度的返回行数基线。
///
/// 目的：生产库里报表账号每天都会跑几十万行的导出，用固定阈值会天天误报；
/// 而某个平时只取几十行的账号突然取 40 万行才是异常。
/// 因此对每个 (account, database) 维护返回行数的分布，用 P50 / P95 / P99 做自适应判定。
/// 样本不足（&lt; BaselineMinSamples）时仅使用绝对阈值。
/// </summary>
public sealed class BaselineIndex
{
    public sealed record Stats(
        int Count,
        long P50,
        long P95,
        long P99,
        long Max,
        double Mean);

    private readonly Dictionary<(string Account, string Database), Stats> _stats = new();
    private readonly Dictionary<string, Stats> _accountStats = new();

    public int TotalSamples { get; private set; }

    public static BaselineIndex Build(IEnumerable<AuditEvent> events)
    {
        var index = new BaselineIndex();
        var byKey = new Dictionary<(string, string), List<long>>();
        var byAccount = new Dictionary<string, List<long>>();

        foreach (var ev in events)
        {
            if (ev.RowsReturned is not { } rows) continue;
            if (!ev.HasStatement) continue;
            // 只统计读取类语句
            if (!LooksLikeRead(ev.Statement)) continue;

            var key = (ev.Account, ev.Database);
            if (!byKey.TryGetValue(key, out var list))
            {
                list = new List<long>();
                byKey[key] = list;
            }
            list.Add(rows);

            if (!byAccount.TryGetValue(ev.Account, out var alist))
            {
                alist = new List<long>();
                byAccount[ev.Account] = alist;
            }
            alist.Add(rows);
            index.TotalSamples++;
        }

        foreach (var (key, values) in byKey) index._stats[key] = Compute(values);
        foreach (var (account, values) in byAccount) index._accountStats[account] = Compute(values);
        return index;
    }

    /// <summary>取该账号在该库的基线；不足样本时返回 null（由调用方退回绝对阈值）。</summary>
    public Stats? For(string account, string database, int minSamples)
    {
        if (_stats.TryGetValue((account, database), out var s) && s.Count >= minSamples) return s;
        return null;
    }

    /// <summary>该账号的跨库基线（库维度样本不足时的备选）。</summary>
    public Stats? ForAccount(string account, int minSamples)
    {
        if (_accountStats.TryGetValue(account, out var s) && s.Count >= minSamples) return s;
        return null;
    }

    private static Stats Compute(List<long> values)
    {
        values.Sort();
        var n = values.Count;
        if (n == 0) return new Stats(0, 0, 0, 0, 0, 0);
        return new Stats(
            n,
            Percentile(values, 0.50),
            Percentile(values, 0.95),
            Percentile(values, 0.99),
            values[^1],
            values.Average());
    }

    /// <summary>最近秩法求分位数。</summary>
    private static long Percentile(List<long> sorted, double p)
    {
        if (sorted.Count == 0) return 0;
        var rank = (int)Math.Ceiling(p * sorted.Count) - 1;
        return sorted[Math.Clamp(rank, 0, sorted.Count - 1)];
    }

    private static bool LooksLikeRead(string statement)
    {
        var span = statement.AsSpan().TrimStart();
        return span.StartsWith("SELECT", StringComparison.OrdinalIgnoreCase)
               || span.StartsWith("WITH", StringComparison.OrdinalIgnoreCase)
               || span.StartsWith("TABLE", StringComparison.OrdinalIgnoreCase)
               || span.StartsWith("SHOW", StringComparison.OrdinalIgnoreCase);
    }
}
