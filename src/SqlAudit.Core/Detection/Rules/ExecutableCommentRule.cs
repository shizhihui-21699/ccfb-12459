using SqlAudit.Core.Model;
using SqlAudit.Core.Sql;

namespace SqlAudit.Core.Detection.Rules;

/// <summary>
/// R-008 可执行注释混淆。
/// MySQL 的 /*! ... */ 与 /*!50000 ... */ 会被服务端当作真实语法执行，
/// 常被用来把 DROP/UNION/SLEEP 等关键词藏进注释里绕过 WAF 与关键字审计。
/// MariaDB 还支持 /*M! ... */。PG 无此特性，只在 MySQL 方言下检测。
/// </summary>
public sealed class ExecutableCommentRule : IStatementRule
{
    public RuleDefinition Definition { get; } = RuleCatalog.Get(RuleCatalog.ExecutableComment)!;

    /// <summary>
    /// 注释体内出现以下任一内容即判定为「藏有可执行逻辑」。
    /// 注意词法分析器会把 0x 字面量、@@变量单独切分，因此这里同时覆盖这两种写法的前缀。
    /// </summary>
    private static readonly string[] SuspiciousKeywords =
    [
        "UNION", "SELECT", "FROM", "WHERE", "SLEEP", "BENCHMARK", "DROP", "GRANT",
        "INTO", "OUTFILE", "DUMPFILE", "@@", "INFORMATION_SCHEMA", "PG_CATALOG",
        "MYSQL.", "LOAD_FILE", "UPDATE", "DELETE", "INSERT", "0x",
    ];

    public IEnumerable<Finding> Evaluate(StatementContext ctx)
    {
        if (ctx.Dialect != SqlDialect.MySql) yield break;

        foreach (var token in ctx.Tokens)
        {
            if (token.Kind != TokKind.ExecutableComment) continue;

            var body = token.Value;
            var hit = SuspiciousKeywords
                .Where(k => body.Contains(k, StringComparison.OrdinalIgnoreCase))
                .ToList();

            // MariaDB /*M! ... */ 也按可执行处理（词法器统一归为 ExecutableComment）
            var severity = hit.Count > 0 ? Severity.High : Severity.Medium;
            var detail = hit.Count > 0
                ? $"注释体内含关键字 {string.Join("、", hit.Distinct(StringComparer.OrdinalIgnoreCase))}"
                : "注释体内含将被执行的 SQL 片段";

            yield return new Finding
            {
                RuleId = RuleCatalog.ExecutableComment,
                RuleName = RuleCatalog.ExecutableComment,
                Severity = severity,
                Message = $"使用 MySQL 版本化可执行注释 {TokenUtils.Clamp(token.Text, 40)}…，{detail}。"
                          + "该注释会被服务端执行，是常用的 WAF 绕过手法。",
                Evidence = ctx.EvidenceRange(token.Offset, token.Length),
                Offset = token.Offset,
                Length = token.Length,
            };
        }
    }
}