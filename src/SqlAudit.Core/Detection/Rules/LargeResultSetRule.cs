using SqlAudit.Core.Model;
using SqlAudit.Core.Sql;

namespace SqlAudit.Core.Detection.Rules;

/// <summary>
/// R-005 返回行数异常（数据外泄）。
///
/// 双通道判定：
///  A. 绝对阈值：rows_sent ≥ 100,000 → 高危；≥ 1,000,000 → 严重。
///  B. 自适应基线：rows_sent ≥ max(绝对下限, 该账号同库历史 P99 × 倍数) 且超过 P99 时才告警。
///     样本不足时只用 A。这样报表账号的例行大批量导出不会被天天误报，
///     而“平时取几十行、这次取 40 万行”的账号会立刻凸显。
///
/// 额外加分项（提升严重度）：
///   * 语句为 SELECT *（无列裁剪）
///   * 无 WHERE 子句或 WHERE 恒真
///   * 命中敏感表（users / orders / payments / customers 等）
/// </summary>
public sealed class LargeResultSetRule : IStatementRule
{
    public RuleDefinition Definition { get; } = RuleCatalog.Get(RuleCatalog.LargeResultSet)!;

    private readonly BaselineIndex _baseline;

    public LargeResultSetRule(BaselineIndex baseline) => _baseline = baseline;

    private static readonly string[] SensitiveTables =
    [
        "users", "user", "accounts", "customers", "orders", "payments", "transactions",
        "credentials", "sessions", "tokens", "pii", "employees", "salaries",
    ];

    public IEnumerable<Finding> Evaluate(StatementContext ctx)
    {
        var ev = ctx.Event;
        if (ev.RowsReturned is not { } rows) yield break;
        if (rows <= 0) yield break;

        var opts = ctx.Options;
        var absoluteHit = rows >= opts.RowsAbsoluteThreshold;
        var baseline = _baseline.For(ev.Account, ev.Database, opts.BaselineMinSamples)
                       ?? _baseline.ForAccount(ev.Account, opts.BaselineMinSamples);

        long? baselineP99 = baseline?.P99;
        var relativeHit = false;
        if (baseline is not null && baselineP99 is > 0)
        {
            var threshold = Math.Max(opts.RowsAbsoluteThreshold, (long)(baselineP99.Value * opts.BaselineMultiplier));
            // 只有明显偏离自身历史分布才算异常
            relativeHit = rows >= threshold && rows >= baselineP99.Value * 2;
        }

        if (!absoluteHit && !relativeHit) yield break;

        var severity = rows >= opts.RowsExtremeThreshold
            ? Severity.Critical
            : absoluteHit ? Severity.High : Severity.High;

        var reasons = new List<string>();
        if (absoluteHit)
            reasons.Add($"返回 {SqlFingerprint.FormatNumber(rows)} 行，超过绝对阈值 {SqlFingerprint.FormatNumber(opts.RowsAbsoluteThreshold)}");
        if (relativeHit && baselineP99 is not null)
            reasons.Add($"该账号在同库历史 P99 为 {SqlFingerprint.FormatNumber(baselineP99.Value)} 行，本次为其 {rows / (double)Math.Max(1, baselineP99.Value):0.#} 倍");

        var hasWhere = ctx.ContainsKeyword("WHERE");
        var selectStar = IsSelectStar(ctx.CodeTokens);
        if (!hasWhere) reasons.Add("语句无 WHERE 过滤条件（全表扫描）");
        if (selectStar) reasons.Add("使用 SELECT * 未做列裁剪");
        if (ReferencesSensitiveTable(ctx)) reasons.Add("涉及敏感业务表");

        // 无过滤条件的全表导出，或触及极端阈值，升级为严重
        if (rows >= opts.RowsExtremeThreshold || (!hasWhere && rows >= opts.RowsAbsoluteThreshold))
            severity = Severity.Critical;

        var token = ctx.CodeTokens.Count > 0 ? ctx.CodeTokens[0] : default;
        var offset = token.Offset;
        var length = Math.Min(ctx.Sql.Length - offset, 240);

        yield return new Finding
        {
            RuleId = RuleCatalog.LargeResultSet,
            RuleName = RuleCatalog.LargeResultSet,
            Severity = severity,
            Message = $"大批量查询：" + string.Join("；", reasons) + "。",
            Evidence = ctx.EvidenceRange(offset, Math.Max(1, length)),
            Offset = offset,
            Length = Math.Max(1, length),
        };
    }

    private static bool IsSelectStar(IReadOnlyList<SqlToken> tokens)
    {
        for (var i = 0; i < tokens.Count - 1; i++)
        {
            if (tokens[i].IsKeyword("SELECT") && tokens[i + 1].IsOperator("*")) return true;
        }
        return false;
    }

    private static bool ReferencesSensitiveTable(StatementContext ctx)
    {
        foreach (var table in SensitiveTables)
        {
            if (ctx.ReferencesObject(table)) return true;
        }
        return false;
    }
}
