using SqlAudit.Core.Model;

namespace SqlAudit.Core.Analysis;

/// <summary>
/// 风险评分。设计意图：
///  1. 同一规则重复命中只计一次（避免一条语句里 5 个 OR 1=1 把分数堆满）；
///  2. 不同规则叠加时做边际衰减（第二条同类别 70%，异类别 100%），
///     因为“同一条语句同时命中 UNION + 可执行注释”确实比单个信号更可疑；
///  3. 结果为 0-100 的整数，可直接用于前端排序与阈值告警。
/// </summary>
public static class RiskScorer
{
    public static (int Score, Severity MaxSeverity) Score(IEnumerable<Finding> findings, IReadOnlyDictionary<string, string> ruleCategories)
    {
        var byRule = new Dictionary<string, Finding>(StringComparer.OrdinalIgnoreCase);
        var maxSeverity = Severity.None;

        foreach (var f in findings)
        {
            if (f.Severity > maxSeverity) maxSeverity = f.Severity;
            if (f.Severity == Severity.None) continue;

            // 同规则保留最高严重度
            if (!byRule.TryGetValue(f.RuleId, out var existing) || f.Severity > existing.Severity)
                byRule[f.RuleId] = f;
        }

        if (byRule.Count == 0) return (0, maxSeverity);

        // 先按严重度降序，保证最强信号拿到全额权重
        var ordered = byRule.Values.OrderByDescending(f => f.Severity).ToList();
        var seenCategories = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        double total = 0;

        foreach (var f in ordered)
        {
            var category = ruleCategories.TryGetValue(f.RuleId, out var c) ? c : f.RuleId;
            var weight = f.Severity.ToWeight();
            var factor = seenCategories.Add(category) ? 1.0 : 0.7;
            total += weight * factor;
        }

        var score = (int)Math.Round(Math.Min(100.0, total));
        return (score, maxSeverity);
    }
}
