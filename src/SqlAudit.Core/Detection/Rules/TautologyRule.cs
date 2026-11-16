using SqlAudit.Core.Model;
using SqlAudit.Core.Sql;

namespace SqlAudit.Core.Detection.Rules;

/// <summary>
/// R-001 永真条件。
///
/// 判定要点（控制误报）：
///  1. 只认字面量之间的恒等比较：两侧都是字面量且等价（'a'='a'、1=1、0x41='A'），
///     或 OR TRUE / OR 1 / OR 'x' 这类常量真值。
///  2. 必须处于布尔上下文：位于 WHERE / HAVING / ON 之后，或紧跟在 OR / AND / NOT / '('/')' 之后。
///     因此 `SELECT 1`、`WHERE id = 1` 不会被误判。
///  3. 以 OR 连接（典型注入 `' OR 1=1`）为严重；以 AND 连接（`AND 1=1`）为低危，
///     因为部分 ORM / 报表工具会生成 AND 1=1 作为占位条件，可由 ReportAndTautology 关闭。
///  4. WHERE 1=1 作为首个条件且后续确有 AND 子句，视为常见 SQL 拼接写法，仅提示。
/// </summary>
public sealed class TautologyRule : IStatementRule
{
    public RuleDefinition Definition { get; } = RuleCatalog.Get(RuleCatalog.Tautology)!;

    public IEnumerable<Finding> Evaluate(StatementContext ctx)
    {
        var tokens = ctx.CodeTokens;
        if (tokens.Count == 0) yield break;

        // 布尔上下文总闸门：永真条件只有在语句具备 WHERE/HAVING/ON 时才有意义。
        // 这排除了 `SELECT 1 OR 1`（MySQL 位运算）、`SELECT 1=1`（投影常量）等非过滤场景。
        var hasBooleanClause = tokens.Any(t =>
            t.IsKeyword("WHERE") || t.IsKeyword("HAVING") || t.IsKeyword("ON"));
        if (!hasBooleanClause) yield break;

        var emitted = 0;
        var max = ctx.Options.MaxFindingsPerStatement;

        for (var i = 0; i < tokens.Count && emitted < max; i++)
        {
            var token = tokens[i];

            // ---- 形态 1：OR <常量真值> -------------------------------------
            if (token.IsKeyword("OR") && i + 1 < tokens.Count)
            {
                var next = tokens[i + 1];

                // OR 1=1 / OR 'a'='a' 等恒等比较
                if (TryMatchTautology(tokens, i + 1, out var end, out var kind))
                {
                    emitted++;
                    yield return Build(ctx, tokens, i + 1, end,
                        Severity.Critical,
                        $"OR 后接恒等比较（{Summarize(tokens, i + 1, end)}），整个 WHERE 条件恒真，是典型的注入闭包写法");
                    i = end;
                    continue;
                }

                // OR 1 / OR TRUE / OR 'x'
                if (IsTruthyConstant(next) && !IsFollowedByComparison(tokens, i + 1))
                {
                    emitted++;
                    yield return Build(ctx, tokens, i, i + 1,
                        Severity.Critical,
                        $"OR 后接非零常量（{Summarize(tokens, i, i + 1)}），使 WHERE 条件恒真");
                    i += 1;
                    continue;
                }
            }

            // ---- 形态 2：AND <恒等比较>（占位/注入探测）---------------------
            if (token.IsKeyword("AND") && i + 1 < tokens.Count
                && TryMatchTautology(tokens, i + 1, out var andEnd, out _))
            {
                if (ctx.Options.ReportAndTautology)
                {
                    emitted++;
                    yield return Build(ctx, tokens, i + 1, andEnd,
                        Severity.Low,
                        $"AND 后接恒等比较（{Summarize(tokens, i + 1, andEnd)}），对结果集无实质影响，常见于自动化注入探测或工具占位条件");
                }
                i = andEnd;
                continue;
            }

            // ---- 形态 3：WHERE / HAVING 之后直接恒真 -----------------------
            if (token.IsKeyword("WHERE") || token.IsKeyword("HAVING"))
            {
                var start = i + 1;
                var limit = FindClauseEnd(tokens, start);

                if (start < tokens.Count && TryMatchTautology(tokens, start, out var wEnd, out _) && wEnd <= limit)
                {
                    // WHERE 1=1 AND ... 是最常见的 SQL 动态拼接写法（几乎所有 ORM/手写拼接都有），
                    // 不构成绕过过滤的风险，直接忽略以免淹没真正的告警。
                    var leadingPlaceholder = wEnd + 1 < tokens.Count && tokens[wEnd + 1].IsKeyword("AND");
                    if (leadingPlaceholder)
                    {
                        i = wEnd;
                        continue;
                    }

                    emitted++;
                    yield return Build(ctx, tokens, start, wEnd,
                        Severity.High,
                        $"WHERE 条件直接为恒真比较（{Summarize(tokens, start, wEnd)}），查询绕过全部过滤条件");
                    i = wEnd;
                    continue;
                }

                // WHERE (1=1) 形式
                if (start < tokens.Count && tokens[start].IsPunct('('))
                {
                    var close = TokenUtils.MatchParen(tokens, start);
                    if (close > start + 2 && TryMatchTautology(tokens, start + 1, out var pEnd, out _)
                        && pEnd == close - 1)
                    {
                        emitted++;
                        yield return Build(ctx, tokens, start, close,
                            Severity.High,
                            $"WHERE 条件为括号包裹的恒真式（{Summarize(tokens, start + 1, pEnd)}），查询绕过全部过滤条件");
                        i = close;
                        continue;
                    }
                }
            }
        }
    }

    /// <summary>在 tokens[index] 处匹配一个恒等比较表达式，返回结束下标。</summary>
    private static bool TryMatchTautology(IReadOnlyList<SqlToken> tokens, int index, out int end, out string kind)
    {
        end = index;
        kind = "";

        // 允许前缀 NOT
        var i = index;
        if (i < tokens.Count && tokens[i].IsKeyword("NOT")) i++;

        // 允许被括号包裹：((1=1))
        var wrapperClose = -1;
        while (i < tokens.Count && tokens[i].IsPunct('('))
        {
            var close = TokenUtils.MatchParen(tokens, i);
            if (close < 0) return false;
            wrapperClose = close;
            i++;
        }

        if (i + 2 >= tokens.Count) return false;
        var left = tokens[i];
        var op = tokens[i + 1];
        var right = tokens[i + 2];

        // 仅接受字面量对字面量的比较，避免列引用误判
        if (!IsLiteral(left) || !IsLiteral(right)) return false;

        var isTautology = false;

        if (op.IsOperator("=") || op.IsOperator("<=>"))
        {
            if (Equivalent(left, right)) { isTautology = true; kind = "equality"; }
        }
        else if (op.IsOperator("!=") || op.IsOperator("<>"))
        {
            if (!Equivalent(left, right)) { isTautology = true; kind = "inequality"; }
        }
        else if (op.IsOperator(">") || op.IsOperator("<") || op.IsOperator(">=") || op.IsOperator("<="))
        {
            // 1<2 恒真、1>2 恒假；恒假在注入中不常用，这里只认恒真
            if (TryNumericCompare(left, right, op.Text, out var result) && result)
            {
                isTautology = true;
                kind = "comparison";
            }
        }
        else if (op.IsKeyword("LIKE") && right.Kind == TokKind.String)
        {
            if (IsMatchAllPattern(right.Value)) { isTautology = true; kind = "like"; }
        }
        else if (op.IsKeyword("IS") && right.IsKeyword("NOT"))
        {
            if (i + 3 < tokens.Count && tokens[i + 3].IsKeyword("NULL")) { isTautology = true; kind = "is-not-null"; }
        }
        else if (op.IsKeyword("BETWEEN") && left.Kind == TokKind.Number)
        {
            // 1 BETWEEN 0 AND 2
            if (i + 4 < tokens.Count && TokenUtils.TryNumber(tokens[i + 3], out var lo)
                && tokens[i + 4].IsKeyword("AND") && i + 5 < tokens.Count
                && TokenUtils.TryNumber(tokens[i + 5], out var hi)
                && TokenUtils.TryNumber(left, out var v) && v >= lo && v <= hi)
            {
                isTautology = true;
                kind = "between";
                i += 5;
            }
        }

        if (!isTautology) return false;

        end = i + 2;
        if (kind == "is-not-null") end = i + 4;

        // 若被括号包裹，结束位置取外层右括号
        if (wrapperClose > 0) end = wrapperClose;
        return true;
    }

    private static bool IsFollowedByComparison(IReadOnlyList<SqlToken> tokens, int index) =>
        index + 2 < tokens.Count && TokenUtils.IsComparisonOperator(tokens[index + 1]);

    private static bool IsTruthyConstant(SqlToken token)
    {
        if (token.IsKeyword("TRUE")) return true;
        if (token.Kind == TokKind.Number && double.TryParse(token.Value, out var d)) return d != 0;
        if (token.Kind == TokKind.String) return token.Value.Length > 0;
        if (token.Kind == TokKind.HexLiteral) return token.Value.Length > 0;
        return false;
    }

    private static bool IsLiteral(SqlToken t) =>
        t.Kind is TokKind.Number or TokKind.String or TokKind.HexLiteral or TokKind.BitLiteral;

    private static bool Equivalent(SqlToken a, SqlToken b)
    {
        if (a.Kind == TokKind.Number && b.Kind == TokKind.Number)
        {
            return double.TryParse(a.Value, System.Globalization.NumberStyles.Float,
                       System.Globalization.CultureInfo.InvariantCulture, out var x)
                   && double.TryParse(b.Value, System.Globalization.NumberStyles.Float,
                       System.Globalization.CultureInfo.InvariantCulture, out var y)
                   && Math.Abs(x - y) < 1e-12;
        }

        // 十六进制字面量需与同值字符/数值比较：0x41 = 'A'、0x31 = '1'、0x01 = 1
        var aHex = a.Kind is TokKind.HexLiteral or TokKind.BitLiteral;
        var bHex = b.Kind is TokKind.HexLiteral or TokKind.BitLiteral;
        if (aHex || bHex)
        {
            // 两侧都是十六进制：直接比字节序列
            if (aHex && bHex)
                return string.Equals(a.Value, b.Value, StringComparison.OrdinalIgnoreCase);

            var hexToken = aHex ? a : b;
            var other = aHex ? b : a;
            if (other.Kind == TokKind.String && TryHexToBytes(hexToken.Value, out var bytes)
                && bytes.Length == System.Text.Encoding.UTF8.GetByteCount(other.Value))
            {
                return System.Text.Encoding.UTF8.GetString(bytes) == other.Value;
            }
            if (other.Kind == TokKind.Number && TryHexToBytes(hexToken.Value, out var numericBytes))
            {
                // 0x01 与 1：把十六进制按整数解释后比较
                if (long.TryParse(hexToken.Value, System.Globalization.NumberStyles.HexNumber,
                        System.Globalization.CultureInfo.InvariantCulture, out var hv)
                    && double.TryParse(other.Value, System.Globalization.NumberStyles.Float,
                        System.Globalization.CultureInfo.InvariantCulture, out var nv))
                {
                    return Math.Abs(hv - nv) < 1e-12;
                }
            }
            return false;
        }

        return string.Equals(a.Value, b.Value, StringComparison.Ordinal);
    }

    private static bool TryHexToBytes(string hex, out byte[] bytes)
    {
        bytes = [];
        // 去掉 MySQL 的 0x 前缀
        var digits = hex.StartsWith("0x", StringComparison.OrdinalIgnoreCase) ? hex[2..] : hex;
        if (digits.Length == 0 || digits.Length % 2 != 0) return false;
        try
        {
            bytes = Convert.FromHexString(digits);
            return true;
        }
        catch (FormatException)
        {
            return false;
        }
    }

    private static bool TryNumericCompare(SqlToken left, SqlToken right, string op, out bool result)
    {
        result = false;
        if (!TokenUtils.TryNumber(left, out var a) || !TokenUtils.TryNumber(right, out var b)) return false;
        result = op switch
        {
            ">" => a > b,
            "<" => a < b,
            ">=" => a >= b,
            "<=" => a <= b,
            _ => false,
        };
        return true;
    }

    private static bool IsMatchAllPattern(string pattern)
    {
        var p = pattern.Trim();
        if (p.Length == 0) return false;
        return p.Replace("%", "").Replace("_", "").Length == 0;
    }

    /// <summary>找到 WHERE 子句的结束位置（GROUP/ORDER/LIMIT/UNION/; 或括号外）。</summary>
    private static int FindClauseEnd(IReadOnlyList<SqlToken> tokens, int start)
    {
        var depth = 0;
        for (var i = start; i < tokens.Count; i++)
        {
            var t = tokens[i];
            if (t.IsPunct('(')) depth++;
            else if (t.IsPunct(')')) { if (depth == 0) return i; depth--; }
            else if (depth == 0 && (t.IsKeyword("GROUP") || t.IsKeyword("ORDER")
                                    || t.IsKeyword("LIMIT") || t.IsKeyword("UNION")
                                    || t.IsKeyword("HAVING") || t.IsKeyword("RETURNING")))
                return i;
        }
        return tokens.Count - 1;
    }

    private static Finding Build(
        StatementContext ctx, IReadOnlyList<SqlToken> tokens, int from, int to, Severity severity, string message)
    {
        from = Math.Max(0, Math.Min(from, tokens.Count - 1));
        to = Math.Max(from, Math.Min(to, tokens.Count - 1));
        var offset = tokens[from].Offset;
        var length = tokens[to].End - offset;

        return new Finding
        {
            RuleId = RuleCatalog.Tautology,
            RuleName = RuleCatalog.Tautology,
            Severity = severity,
            Message = message,
            Evidence = ctx.EvidenceRange(offset, length),
            Offset = offset,
            Length = length,
        };
    }

    private static string Summarize(IReadOnlyList<SqlToken> tokens, int from, int to)
    {
        var sb = new System.Text.StringBuilder();
        for (var i = from; i <= Math.Min(to, tokens.Count - 1); i++)
        {
            if (i > from) sb.Append(' ');
            sb.Append(tokens[i].Text);
        }
        return TokenUtils.Clamp(sb.ToString(), 90);
    }
}
