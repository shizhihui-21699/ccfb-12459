using SqlAudit.Core.Model;
using SqlAudit.Core.Sql;

namespace SqlAudit.Core.Detection.Rules;

/// <summary>
/// R-006 授权变更。
///
/// 覆盖 MySQL 与 PG 的权限/账号管理语句：
///   GRANT / REVOKE
///   CREATE USER / ALTER USER / DROP USER（MySQL 8 起 CREATE USER ... IDENTIFIED BY）
///   CREATE ROLE / ALTER ROLE / DROP ROLE（PG）
///   SET ROLE / SET SESSION AUTHORIZATION
///   ALTER USER ... IDENTIFIED BY（改密码）
///   MySQL 的 SET PASSWORD
///
/// 分级：
///   GRANT ALL PRIVILEGES ON *.* / WITH GRANT OPTION / SUPERUSER / CREATEROLE / REPLICATION
///   / ALTER USER ... IDENTIFIED BY  → 严重（提权或凭据变更）
///   普通 GRANT SELECT ON db.table → 高危（仍是敏感变更，需人工确认）
/// </summary>
public sealed class PrivilegeChangeRule : IStatementRule
{
    public RuleDefinition Definition { get; } = RuleCatalog.Get(RuleCatalog.PrivilegeChange)!;

    private static readonly HashSet<string> PrivilegedTokens = new(StringComparer.OrdinalIgnoreCase)
    {
        "ALL", "ALL PRIVILEGES", "SUPER", "SUPERUSER", "CREATEROLE", "CREATEDB", "REPLICATION",
        "SHUTDOWN", "PROCESS", "FILE", "GRANT", "USAGE", "BYPASSRLS",
    };

    public IEnumerable<Finding> Evaluate(StatementContext ctx)
    {
        var tokens = ctx.CodeTokens;
        if (tokens.Count == 0) yield break;

        var first = ctx.FirstKeyword;

        // GRANT / REVOKE
        if (first is "GRANT" or "REVOKE")
        {
            var isGrant = first == "GRANT";
            var allPrivileges = tokens.Any(t => t.IsKeyword("ALL"));
            var onAllObjects = IsOnAllObjects(tokens);
            var withGrantOption = ContainsSequence(tokens, "WITH", "GRANT", "OPTION");
            var privilegedRole = ContainsAnyKeyword(tokens, "SUPERUSER", "CREATEROLE", "CREATEDB", "REPLICATION", "SYSADMIN");

            var critical = allPrivileges && onAllObjects
                           || withGrantOption
                           || privilegedRole;

            yield return new Finding
            {
                RuleId = RuleCatalog.PrivilegeChange,
                RuleName = RuleCatalog.PrivilegeChange,
                Severity = critical ? Severity.Critical : Severity.High,
                Message = critical
                    ? BuildCriticalGrantMessage(isGrant, allPrivileges, onAllObjects, withGrantOption, privilegedRole)
                    : $"{first} 语句变更了账号权限，需确认是否为受控的变更窗口操作。",
                Evidence = ctx.EvidenceRange(tokens[0].Offset, Math.Min(tokens[^1].End - tokens[0].Offset, 240)),
                Offset = tokens[0].Offset,
                Length = Math.Min(tokens[^1].End - tokens[0].Offset, 240),
            };
            yield break;
        }

        // CREATE USER / ALTER USER / DROP USER / CREATE ROLE / ALTER ROLE / DROP ROLE
        if (first is "CREATE" or "ALTER" or "DROP")
        {
            var idx = -1;
            for (var i = 0; i < tokens.Count; i++)
            {
                if (tokens[i].IsKeyword("USER") || tokens[i].IsKeyword("ROLE")) { idx = i; break; }
            }
            if (idx < 0) yield break;

            var objectKind = tokens[idx].Value.ToUpperInvariant();
            var isAlter = first == "ALTER";
            var setsPassword = ContainsAnyKeyword(tokens, "IDENTIFIED", "PASSWORD");
            var isSuperuserGrant = ContainsSequence(tokens, "WITH", "SUPERUSER")
                                   || ContainsSequence(tokens, "WITH", "CREATEROLE");

            var severity = setsPassword || isSuperuserGrant ? Severity.Critical : Severity.Medium;
            var detail = setsPassword ? "并设置/修改了口令，可能是账号接管或后门账号"
                : isSuperuserGrant ? "并授予 SUPERUSER/CREATEROLE 等高权限属性"
                : "";

            yield return new Finding
            {
                RuleId = RuleCatalog.PrivilegeChange,
                RuleName = RuleCatalog.PrivilegeChange,
                Severity = severity,
                Message = $"{first} {objectKind} 变更了数据库账号定义{detail}。",
                Evidence = ctx.EvidenceRange(tokens[0].Offset, Math.Min(tokens[^1].End - tokens[0].Offset, 240)),
                Offset = tokens[0].Offset,
                Length = Math.Min(tokens[^1].End - tokens[0].Offset, 240),
            };
            yield break;
        }

        // SET ROLE / SET SESSION AUTHORIZATION / SET PASSWORD
        if (first == "SET")
        {
            if (ContainsSequence(tokens, "SESSION", "AUTHORIZATION") || ContainsKeywordAt(tokens, "ROLE", 1))
            {
                yield return new Finding
                {
                    RuleId = RuleCatalog.PrivilegeChange,
                    RuleName = RuleCatalog.PrivilegeChange,
                    Severity = Severity.High,
                    Message = "切换会话角色/授权标识，可能用于以更高权限身份执行后续操作。",
                    Evidence = ctx.EvidenceRange(tokens[0].Offset, Math.Min(120, ctx.Sql.Length - tokens[0].Offset)),
                    Offset = tokens[0].Offset,
                    Length = Math.Min(120, ctx.Sql.Length - tokens[0].Offset),
                };
            }
            else if (ContainsKeywordAt(tokens, "PASSWORD", 1))
            {
                yield return new Finding
                {
                    RuleId = RuleCatalog.PrivilegeChange,
                    RuleName = RuleCatalog.PrivilegeChange,
                    Severity = Severity.Critical,
                    Message = "SET PASSWORD 修改账号口令，属凭据变更，需立即核对操作人。",
                    Evidence = ctx.EvidenceRange(tokens[0].Offset, Math.Min(160, ctx.Sql.Length - tokens[0].Offset)),
                    Offset = tokens[0].Offset,
                    Length = Math.Min(160, ctx.Sql.Length - tokens[0].Offset),
                };
            }
        }
    }

    private static string BuildCriticalGrantMessage(
        bool isGrant, bool all, bool onAll, bool withGrantOption, bool privilegedRole)
    {
        var parts = new List<string>();
        if (all && onAll) parts.Add("授予 ALL PRIVILEGES ON *.*（全局全权限）");
        else if (all) parts.Add("授予 ALL PRIVILEGES");
        if (withGrantOption) parts.Add("带 WITH GRANT OPTION（可将权限继续转授）");
        if (privilegedRole) parts.Add("涉及 SUPERUSER/CREATEROLE/REPLICATION 等实例级高权限");
        return $"高风险提权：{(isGrant ? "GRANT" : "REVOKE")} " + string.Join("；", parts) + "。";
    }

    /// <summary>ON *.* / ON ALL TABLES IN SCHEMA / ON DATABASE 判定为全局对象。</summary>
    private static bool IsOnAllObjects(IReadOnlyList<SqlToken> tokens)
    {
        for (var i = 0; i < tokens.Count; i++)
        {
            if (!tokens[i].IsKeyword("ON")) continue;
            // *.* → 连续两个 '*' 运算符
            if (i + 3 < tokens.Count && tokens[i + 1].IsOperator("*") && tokens[i + 2].IsPunct('.')
                && tokens[i + 3].IsOperator("*"))
                return true;
            if (i + 1 < tokens.Count && (tokens[i + 1].IsKeyword("DATABASE") || tokens[i + 1].IsKeyword("SCHEMA")))
                return true;
        }
        return false;
    }

    private static bool ContainsSequence(IReadOnlyList<SqlToken> tokens, params string[] keywords)
    {
        for (var i = 0; i + keywords.Length <= tokens.Count; i++)
        {
            var ok = true;
            for (var k = 0; k < keywords.Length; k++)
            {
                if (!tokens[i + k].IsKeyword(keywords[k])) { ok = false; break; }
            }
            if (ok) return true;
        }
        return false;
    }

    private static bool ContainsAnyKeyword(IReadOnlyList<SqlToken> tokens, params string[] keywords) =>
        tokens.Any(t => keywords.Any(k => t.IsKeyword(k)));

    private static bool ContainsKeywordAt(IReadOnlyList<SqlToken> tokens, string keyword, int index) =>
        index < tokens.Count && tokens[index].IsKeyword(keyword);
}
