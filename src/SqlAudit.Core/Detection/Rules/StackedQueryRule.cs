using SqlAudit.Core.Model;
using SqlAudit.Core.Sql;

namespace SqlAudit.Core.Detection.Rules;

/// <summary>
/// R-002 堆叠查询。
///
/// 判定要点：
///  1. 用词法切分（而非正则 split）得到语句片段，字符串字面量、注释、$$ 引用体内的分号不会误切。
///  2. 仅当后续语句为“有影响的写操作/权限操作”时告警：
///     INSERT/UPDATE/DELETE/DDL/GRANT/CALL/EXEC/SET 等。`SELECT 1; SELECT 2` 这种批处理
///     在报表工具中偶见，只作提示；`... ; DROP TABLE` 才是真正危险的堆叠注入。
///  3. 存储过程/函数/触发器定义体内的分号会被识别并排除（见 SqlStatementSplitter）。
///  4. 后续语句为 SELECT（如 MySQL 驱动 multi-statement 批量查询）时，仅当首语句含
///     可疑注入特征（注释、永真）才升级。
/// </summary>
public sealed class StackedQueryRule : IStatementRule
{
    public RuleDefinition Definition { get; } = RuleCatalog.Get(RuleCatalog.StackedQuery)!;

    private static readonly HashSet<string> DangerousFollowUp = new(StringComparer.OrdinalIgnoreCase)
    {
        "INSERT", "UPDATE", "DELETE", "DROP", "CREATE", "ALTER", "TRUNCATE", "GRANT", "REVOKE",
        "CALL", "EXEC", "EXECUTE", "SET", "RENAME", "REPLACE", "MERGE", "COPY", "LOAD",
        "DECLARE", "UNLOCK", "LOCK", "FLUSH", "SHUTDOWN", "KILL", "DO", "HANDLER", "PURGE",
    };

    public IEnumerable<Finding> Evaluate(StatementContext ctx)
    {
        var segments = SqlStatementSplitter.Split(ctx.Sql, ctx.Dialect);
        if (segments.Count < 2) yield break;

        // 首个片段即为当前审计的语句，后续片段视为堆叠的附加语句。
        var followUps = segments.Skip(1)
            .Select(s => (Segment: s, Keyword: LeadingKeyword(s.Sql, ctx.Dialect)))
            .Where(x => x.Keyword.Length > 0)
            .ToList();

        if (followUps.Count == 0) yield break;

        var dangerous = followUps.Where(x => DangerousFollowUp.Contains(x.Keyword)).ToList();
        var suspicious = followUps.Where(x => x.Keyword is "SELECT" or "SHOW" or "DESCRIBE" or "EXPLAIN").ToList();

        if (dangerous.Count > 0)
        {
            var kw = string.Join(" / ", dangerous.Select(x => x.Keyword).Distinct());
            var first = dangerous[0].Segment;
            var severity = IsPrivilegedFollowUp(dangerous.Select(x => x.Keyword)) ? Severity.Critical : Severity.Critical;
            yield return new Finding
            {
                RuleId = RuleCatalog.StackedQuery,
                RuleName = RuleCatalog.StackedQuery,
                Severity = severity,
                Message = $"单条记录中包含 {segments.Count} 条语句，分号后跟随写操作（{kw}）。"
                          + "正常业务通常只提交单语句，堆叠写操作是 SQL 注入的高置信信号。",
                Evidence = TokenUtils.Clamp(first.Sql, 200),
                Offset = first.Offset,
                Length = Math.Min(first.Sql.Length, 200),
            };
            yield break;
        }

        if (suspicious.Count > 0)
        {
            // 多条 SELECT 的批处理：若首语句含注入特征再升级，否则只提示
            var firstSql = segments[0].Sql;
            var hasInjectionHint = firstSql.Contains("/*", StringComparison.Ordinal)
                                   || firstSql.Contains("--", StringComparison.Ordinal)
                                   || firstSql.Contains("#", StringComparison.Ordinal)
                                   || firstSql.Contains(" OR ", StringComparison.OrdinalIgnoreCase);

            if (hasInjectionHint)
            {
                yield return new Finding
                {
                    RuleId = RuleCatalog.StackedQuery,
                    RuleName = RuleCatalog.StackedQuery,
                    Severity = Severity.Medium,
                    Message = $"单条记录包含 {segments.Count} 条 SELECT 语句，且首语句含注释或 OR 片段，"
                              + "疑似利用 multi-statement 进行联合探测。",
                    Evidence = TokenUtils.Clamp(suspicious[0].Segment.Sql, 200),
                    Offset = suspicious[0].Segment.Offset,
                    Length = Math.Min(suspicious[0].Segment.Sql.Length, 200),
                };
            }
            else
            {
                yield return new Finding
                {
                    RuleId = RuleCatalog.StackedQuery,
                    RuleName = RuleCatalog.StackedQuery,
                    Severity = Severity.Info,
                    Message = $"单条记录包含 {segments.Count} 条语句（{string.Join(" / ", suspicious.Select(x => x.Keyword).Distinct())}），"
                              + "可能是批处理查询；如非预期请核对应用侧 multi-statement 配置。",
                    Evidence = TokenUtils.Clamp(suspicious[0].Segment.Sql, 200),
                    Offset = suspicious[0].Segment.Offset,
                    Length = Math.Min(suspicious[0].Segment.Sql.Length, 200),
                };
            }
        }
    }

    private static bool IsPrivilegedFollowUp(IEnumerable<string> keywords) =>
        keywords.Any(k => k is "GRANT" or "REVOKE" or "DROP" or "ALTER" or "CREATE");

    /// <summary>取片段的首关键字（跳过注释与括号）。</summary>
    private static string LeadingKeyword(string segment, SqlDialect dialect)
    {
        var tokens = SqlLexer.Tokenize(segment, dialect);
        var idx = TokenUtils.FirstSignificant(tokens);
        if (idx < 0) return "";
        var t = tokens[idx];
        if (t.IsPunct('(')) return "SELECT"; // (SELECT ...) UNION ...
        return t.Kind is TokKind.Identifier or TokKind.QuotedIdentifier ? t.Value.ToUpperInvariant() : "";
    }
}
