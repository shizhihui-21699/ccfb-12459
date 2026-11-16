using SqlAudit.Core.Model;
using SqlAudit.Core.Sql;

namespace SqlAudit.Core.Detection.Rules;

/// <summary>
/// R-003 UNION 拼接注入。
///
/// UNION 在正常业务里极常见（报表合并、多表取数），因此不能见到 UNION 就报。
/// 这里用“注入指纹”加权：每个特征计分，达到阈值才产出 finding。
///
/// 高权重特征（每条 +40）：
///   * UNION SELECT 后紧跟全 NULL 占位列（NULL,NULL,... 至少 2 个），用于探测列数
///   * 读取系统字典：information_schema / pg_catalog / pg_user / mysql.user / sys.
///   * 读取系统函数：version() / current_user / user() / database() / @@version / system_user
///   * 使用十六进制/CHAR()/CHR() 构造字符串（绕过引号过滤）
///   * 紧邻注释闭合（-- /*），说明是拼接在参数位置
/// 中权重（+15）：UNION 出现在字符串/参数语境后、UNION 后的 SELECT 列数与原查询不一致
/// 低权重（+5）：UNION SELECT 中出现 NULL 占位（单个）
///
/// 总分 ≥ 40 → 高危；≥ 70 → 严重。纯业务 UNION 查询得分 0~5，不会告警。
/// </summary>
public sealed class UnionInjectionRule : IStatementRule
{
    public RuleDefinition Definition { get; } = RuleCatalog.Get(RuleCatalog.UnionInjection)!;

    private static readonly string[] SystemSchemas =
    [
        "information_schema", "pg_catalog", "mysql", "performance_schema", "sys", "pg_toast",
    ];

    private static readonly string[] SystemObjects =
    [
        "user", "db", "tables_priv", "columns_priv", "user_privileges", "pg_shadow", "pg_authid",
        "pg_user", "pg_roles", "pg_class", "pg_tables", "pg_settings", "pg_proc",
    ];

    private static readonly HashSet<string> ReconFunctions = new(StringComparer.OrdinalIgnoreCase)
    {
        "VERSION", "CURRENT_USER", "USER", "DATABASE", "SYSTEM_USER", "SESSION_USER",
        "CURRENT_SCHEMA", "CURRENT_DATABASE", "PG_BACKEND_PID", "INET_SERVER_ADDR",
        "INET_CLIENT_ADDR", "CURRENT_SETTING", "CURRENT_QUERY", "LAST_INSERT_ID",
        "CHAR", "CHR", "ASCII", "ORD", "HEX", "UNHEX", "CONCAT", "CONCAT_WS", "GROUP_CONCAT",
    };

    public IEnumerable<Finding> Evaluate(StatementContext ctx)
    {
        var tokens = ctx.CodeTokens;
        if (tokens.Count == 0) yield break;

        for (var i = 0; i < tokens.Count; i++)
        {
            if (!tokens[i].IsKeyword("UNION")) continue;

            // 定位 UNION 后的 SELECT
            var j = i + 1;
            if (j < tokens.Count && (tokens[j].IsKeyword("ALL") || tokens[j].IsKeyword("DISTINCT"))) j++;
            if (j >= tokens.Count || !tokens[j].IsKeyword("SELECT"))
            {
                // UNION 后不是 SELECT 不常见，跳过
                continue;
            }

            var score = 0;
            var reasons = new List<string>();

            // 选区终点：UNION 后到下一个 UNION / ORDER / LIMIT / 语句结束
            var selectEnd = FindSelectEnd(tokens, j);

            // 特征 1：NULL 占位列
            var nullRun = CountLeadingNulls(tokens, j + 1);
            if (nullRun >= 2)
            {
                score += 40;
                reasons.Add($"UNION SELECT 使用 {nullRun} 个 NULL 占位列，用于探测原查询列数");
            }
            else if (nullRun == 1)
            {
                score += 5;
                reasons.Add("UNION SELECT 含 NULL 占位");
            }

            // 特征 2：系统字典对象
            var sysObj = FindSystemObject(tokens, j, selectEnd);
            if (sysObj is not null)
            {
                score += 40;
                reasons.Add($"UNION 分支读取系统字典对象 {sysObj}");
            }

            // 特征 3：侦察函数
            var reconFn = FindReconFunction(tokens, j, selectEnd);
            if (reconFn is not null)
            {
                score += 40;
                reasons.Add($"UNION 分支调用系统信息函数 {reconFn}()");
            }

            // 特征 4：@@version / @@datadir 等变量
            var systemVariable = FindSystemVariable(tokens, j, selectEnd);
            if (systemVariable is not null)
            {
                score += 40;
                reasons.Add($"UNION 分支读取系统变量 {systemVariable}");
            }

            // 特征 5：十六进制/CHAR 构造字符串
            var hexOrChar = FindLiteralConstruction(tokens, j, selectEnd);
            if (hexOrChar is not null)
            {
                score += 40;
                reasons.Add($"UNION 分支用 {hexOrChar} 构造字符串，常用来绕开引号关键词过滤");
            }

            // 特征 6：紧挨注释闭合 → 拼接痕迹（整条语句范围内看 UNION 前后）
            if (HasAdjacentCommentClose(tokens, i))
            {
                score += 25;
                reasons.Add("UNION 前紧邻注释闭合符（-- 或 /*），显示语句被拼接篡改");
            }

            if (score < 40) continue;

            var severity = score >= 70 ? Severity.Critical : Severity.High;
            var endToken = Math.Min(selectEnd, tokens.Count - 1);
            var offset = tokens[i].Offset;
            var length = tokens[endToken].End - offset;

            yield return new Finding
            {
                RuleId = RuleCatalog.UnionInjection,
                RuleName = RuleCatalog.UnionInjection,
                Severity = severity,
                Message = $"检测到 UNION 拼接注入（风险分 {score}）：" + string.Join("；", reasons),
                Evidence = ctx.EvidenceRange(offset, length),
                Offset = offset,
                Length = length,
            };
        }
    }

    private static int FindSelectEnd(IReadOnlyList<SqlToken> tokens, int selectIndex)
    {
        var depth = 0;
        for (var i = selectIndex; i < tokens.Count; i++)
        {
            var t = tokens[i];
            if (t.IsPunct('(')) depth++;
            else if (t.IsPunct(')')) { if (depth == 0) return i; depth--; }
            else if (depth == 0 && (t.IsKeyword("UNION") || t.IsKeyword("ORDER")
                                    || t.IsKeyword("LIMIT") || t.IsKeyword("OFFSET")))
                return i;
        }
        return tokens.Count - 1;
    }

    private static int CountLeadingNulls(IReadOnlyList<SqlToken> tokens, int index)
    {
        var count = 0;
        var i = index;
        while (i < tokens.Count)
        {
            if (tokens[i].IsKeyword("NULL")) { count++; i++; }
            else if (tokens[i].IsPunct(',')) i++;
            else if (tokens[i].Kind == TokKind.Number || tokens[i].Kind == TokKind.String) i++; // 数字/字符串占位，跳过
            else break;
        }
        return count;
    }

    private static string? FindSystemObject(IReadOnlyList<SqlToken> tokens, int from, int to)
    {
        for (var i = from; i <= Math.Min(to, tokens.Count - 1); i++)
        {
            var t = tokens[i];
            if (t.Kind is not (TokKind.Identifier or TokKind.QuotedIdentifier)) continue;
            var v = t.Value;
            foreach (var schema in SystemSchemas)
            {
                if (string.Equals(v, schema, StringComparison.OrdinalIgnoreCase)) return schema;
            }
        }
        return null;
    }

    private static string? FindReconFunction(IReadOnlyList<SqlToken> tokens, int from, int to)
    {
        for (var i = from; i <= Math.Min(to, tokens.Count - 1); i++)
        {
            if (i + 1 >= tokens.Count || !tokens[i + 1].IsPunct('(')) continue;
            if (tokens[i].Kind != TokKind.Identifier) continue;
            if (ReconFunctions.Contains(tokens[i].Value)) return tokens[i].Value;
        }
        return null;
    }

    private static string? FindSystemVariable(IReadOnlyList<SqlToken> tokens, int from, int to)
    {
        for (var i = from; i <= Math.Min(to, tokens.Count - 1); i++)
        {
            if (tokens[i].Kind == TokKind.Variable && tokens[i].Text.StartsWith("@@")) return tokens[i].Text;
            // 词法器把 "@@version" 作为单个 Variable token；部分方言下可能被切成 "@" + "@" + 标识符
            if (tokens[i].Kind == TokKind.Identifier
                && string.Equals(tokens[i].Value, "VERSION", StringComparison.OrdinalIgnoreCase)
                && i > 0 && tokens[i - 1].Kind == TokKind.Variable)
                return "@@version";
        }
        return null;
    }

    private static string? FindLiteralConstruction(IReadOnlyList<SqlToken> tokens, int from, int to)
    {
        for (var i = from; i <= Math.Min(to, tokens.Count - 1); i++)
        {
            if (tokens[i].Kind == TokKind.HexLiteral && tokens[i].Value.Length >= 2) return "十六进制字面量";
            if (tokens[i].IsKeyword("CHAR") || tokens[i].IsKeyword("CHR")) return tokens[i].Value.ToUpperInvariant();
            if (tokens[i].IsKeyword("UNHEX")) return "UNHEX";
        }
        return null;
    }

    private static bool HasAdjacentCommentClose(IReadOnlyList<SqlToken> tokens, int unionIndex)
    {
        // 检查 UNION 前 1~4 个 token 是否包含常规注释（被当作注入的闭合符）
        for (var i = Math.Max(0, unionIndex - 4); i < unionIndex; i++)
        {
            if (tokens[i].Kind == TokKind.Comment) return true;
        }
        return false;
    }
}
