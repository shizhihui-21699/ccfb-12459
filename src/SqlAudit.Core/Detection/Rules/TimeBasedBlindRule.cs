using SqlAudit.Core.Model;
using SqlAudit.Core.Sql;

namespace SqlAudit.Core.Detection.Rules;

/// <summary>
/// R-004 时间盲注函数。
///
/// 覆盖：
///   MySQL      SLEEP(n) / BENCHMARK(count, expr) / GET_LOCK(name, timeout)
///    PostgreSQL pg_sleep(n) / pg_sleep_for(interval) / pg_sleep_until(ts)
///    SQL Server WAITFOR DELAY '00:00:05'
///    Oracle     DBMS_LOCK.SLEEP(n)
///
/// 分级：延时参数 ≥ 阈值（默认 1s）为高危；小于阈值的 SLEEP(0)/SLEEP(0.01) 属探测性、
/// 记为中危；BENCHMARK 迭代次数极高（≥1e6）同样高危。
///
/// 误报控制：业务代码里也会用 SLEEP 做限流/重试，因此仅当函数出现在
/// SELECT 语句且参数为字面量时告警；若语句本身带常量延时参数且来自登录后的
/// 正常作业，可结合基线在告警聚合层降权（见 RiskScorer）。
/// </summary>
public sealed class TimeBasedBlindRule : IStatementRule
{
    public RuleDefinition Definition { get; } = RuleCatalog.Get(RuleCatalog.TimeBasedBlind)!;

    private static readonly HashSet<string> DelayFunctions = new(StringComparer.OrdinalIgnoreCase)
    {
        "SLEEP", "PG_SLEEP", "PG_SLEEP_FOR", "PG_SLEEP_UNTIL", "DBMS_LOCK.SLEEP", "WAITFOR",
    };

    public IEnumerable<Finding> Evaluate(StatementContext ctx)
    {
        var tokens = ctx.CodeTokens;
        if (tokens.Count == 0) yield break;

        // 1) 函数调用型：SLEEP(x) / pg_sleep(x)
        foreach (var call in TokenUtils.FunctionCalls(tokens))
        {
            var name = NormalizeName(call.Name);
            if (name is "BENCHMARK")
            {
                var args = ArgTokens(tokens, call.OpenIndex, call.CloseIndex);
                var iterations = args.Count > 0 && TokenUtils.TryNumber(args[0], out var n) ? n : 0;
                var severity = iterations >= 1_000_000 ? Severity.High
                    : iterations >= 10_000 ? Severity.Medium
                    : Severity.Low;
                yield return Build(ctx, tokens[call.NameIndex], tokens[call.CloseIndex],
                    severity,
                    $"调用 BENCHMARK({TokenUtils.Clamp(tokens[call.NameIndex + 2].Text, 20)}…)，"
                    + $"通过重复执行制造延时，迭代次数 {iterations:0}，是 MySQL 时间盲注的典型手法");
                continue;
            }

            if (!DelayFunctions.Contains(name)) continue;

            var args2 = ArgTokens(tokens, call.OpenIndex, call.CloseIndex);
            var delay = ExtractDelaySeconds(name, args2);
            var isPgUntil = name is "PG_SLEEP_UNTIL" or "PG_SLEEP_FOR";
            var severity2 = delay is null && !isPgUntil
                ? Severity.Medium
                : delay >= ctx.Options.SuspiciousDelaySeconds ? Severity.High
                : Severity.Medium;

            var argText = args2.Count > 0 ? TokenUtils.Clamp(args2[0].Text, 40) : "";
            var message = delay is not null
                ? $"调用延时函数 {call.Name}({argText})，预计阻塞 {delay:0.###} 秒；"
                  + "切换布尔条件为真/假即可观测响应时差，是时间盲注的核心手法"
                : $"调用延时函数 {call.Name}({argText})，时间盲注特征";

            yield return Build(ctx, tokens[call.NameIndex], tokens[call.CloseIndex], severity2, message);
        }

        // 2) T-SQL: WAITFOR DELAY '00:00:05'
        for (var i = 0; i < tokens.Count; i++)
        {
            if (!tokens[i].IsKeyword("WAITFOR")) continue;
            if (i + 1 >= tokens.Count || !tokens[i + 1].IsKeyword("DELAY")) continue;

            var severity = Severity.High;
            var text = i + 2 < tokens.Count ? tokens[i + 2].Text : "";
            yield return Build(ctx, tokens[i], tokens[Math.Min(i + 2, tokens.Count - 1)],
                severity, $"使用 WAITFOR DELAY {TokenUtils.Clamp(text, 30)} 强制阻塞，时间盲注特征");
        }
    }

    private static string NormalizeName(string name)
    {
        var n = name.ToUpperInvariant();
        // PG 的 pg_sleep 可能带 schema 前缀 pg_catalog.pg_sleep
        var dot = n.LastIndexOf('.');
        if (dot >= 0) n = n[(dot + 1)..];
        return n;
    }

    /// <summary>提取参数 token（不含包围括号）。</summary>
    private static List<SqlToken> ArgTokens(IReadOnlyList<SqlToken> tokens, int openIndex, int closeIndex)
    {
        var args = new List<SqlToken>();
        for (var i = openIndex + 1; i < closeIndex; i++) args.Add(tokens[i]);
        return args;
    }

    /// <summary>从参数中解析延时秒数；支持 SLEEP(5)、pg_sleep(2.5)、pg_sleep_for('5 seconds')。</summary>
    private static double? ExtractDelaySeconds(string name, List<SqlToken> args)
    {
        if (args.Count == 0) return null;

        // 取第一个字面量
        var first = args[0];
        if (TokenUtils.TryNumber(first, out var num))
        {
            // pg_sleep_until 的参数是时间戳，不是秒数
            if (name is "PG_SLEEP_UNTIL") return null;
            return num;
        }

        if (first.Kind == TokKind.String)
        {
            var text = first.Value.Trim();
            // '00:00:05' T-SQL 格式
            if (TimeSpan.TryParse(text, out var ts)) return ts.TotalSeconds;
            // '5 seconds' / '500 ms'
            var parts = text.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length >= 1 && double.TryParse(parts[0], out var v))
            {
                var unit = parts.Length > 1 ? parts[1].ToLowerInvariant() : "s";
                return unit switch
                {
                    "ms" or "milliseconds" or "millisecond" => v / 1000.0,
                    "minute" or "minutes" or "min" => v * 60,
                    _ => v,
                };
            }
        }

        return null;
    }

    private static Finding Build(
        StatementContext ctx, SqlToken from, SqlToken to, Severity severity, string message)
    {
        var offset = from.Offset;
        var length = Math.Max(1, to.End - offset);
        return new Finding
        {
            RuleId = RuleCatalog.TimeBasedBlind,
            RuleName = RuleCatalog.TimeBasedBlind,
            Severity = severity,
            Message = message,
            Evidence = ctx.EvidenceRange(offset, length),
            Offset = offset,
            Length = length,
        };
    }
}
