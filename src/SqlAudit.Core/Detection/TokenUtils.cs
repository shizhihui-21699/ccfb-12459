using SqlAudit.Core.Sql;

namespace SqlAudit.Core.Detection;

/// <summary>在 token 流上做结构匹配的辅助方法。</summary>
internal static class TokenUtils
{
    public static bool IsOpenParen(SqlToken t) => t.IsPunct('(');
    public static bool IsCloseParen(SqlToken t) => t.IsPunct(')');

    /// <summary>从 openIndex（必须指向 '('）找到匹配的 ')' 下标；找不到返回 -1。</summary>
    public static int MatchParen(IReadOnlyList<SqlToken> tokens, int openIndex)
    {
        var depth = 0;
        for (var i = openIndex; i < tokens.Count; i++)
        {
            if (IsOpenParen(tokens[i])) depth++;
            else if (IsCloseParen(tokens[i]))
            {
                depth--;
                if (depth == 0) return i;
            }
        }
        return -1;
    }

    /// <summary>判断 tokens[index] 是否为函数调用起点（identifier 后紧跟 '('），返回右括号下标。</summary>
    public static bool TryFunctionCall(IReadOnlyList<SqlToken> tokens, int index, out string name, out int closeIndex)
    {
        name = "";
        closeIndex = -1;
        if (index < 0 || index >= tokens.Count) return false;
        var t = tokens[index];
        if (t.Kind != TokKind.Identifier && t.Kind != TokKind.QuotedIdentifier) return false;
        if (index + 1 >= tokens.Count || !IsOpenParen(tokens[index + 1])) return false;
        var close = MatchParen(tokens, index + 1);
        if (close < 0) return false;
        name = t.Value;
        closeIndex = close;
        return true;
    }

    /// <summary>列出所有函数调用的 (名称, 起点, 参数左括号, 参数右括号)。</summary>
    public static IEnumerable<(string Name, int NameIndex, int OpenIndex, int CloseIndex)> FunctionCalls(
        IReadOnlyList<SqlToken> tokens)
    {
        for (var i = 0; i < tokens.Count; i++)
        {
            if (!IsOpenParen(tokens[i]) && !(tokens[i].Kind is TokKind.Identifier or TokKind.QuotedIdentifier))
                continue;
            if (i + 1 >= tokens.Count || !IsOpenParen(tokens[i + 1])) continue;
            // 关键字后接括号（IN / VALUES / SELECT 子查询）不是函数调用，排除常见关键字
            if (tokens[i].Kind == TokKind.Identifier && NonFunctionKeywords.Contains(tokens[i].Value))
                continue;
            var close = MatchParen(tokens, i + 1);
            if (close < 0) continue;
            yield return (tokens[i].Value, i, i + 1, close);
        }
    }

    private static readonly HashSet<string> NonFunctionKeywords = new(StringComparer.OrdinalIgnoreCase)
    {
        "IN", "VALUES", "SELECT", "FROM", "WHERE", "AND", "OR", "NOT", "AS", "ON", "USING",
        "EXISTS", "CASE", "WHEN", "THEN", "ELSE", "END", "UNION", "ALL", "ANY", "SOME",
        "INSERT", "UPDATE", "DELETE", "SET", "GROUP", "ORDER", "BY", "HAVING", "LIMIT",
        "JOIN", "LEFT", "RIGHT", "INNER", "OUTER", "CROSS", "FULL", "OVER", "PARTITION",
        "WITH", "RETURNING", "INTO", "TABLE", "INDEX", "KEY", "PRIMARY", "FOREIGN",
    };

    public static string Slice(string sql, SqlToken token) =>
        token.Offset >= 0 && token.End <= sql.Length ? sql[token.Offset..token.End] : token.Text;

    /// <summary>拼接一段 token 的原文（用于证据片段），并截断。</summary>
    public static string JoinTokens(IReadOnlyList<SqlToken> tokens, int from, int to, int max = 200)
    {
        if (tokens.Count == 0) return "";
        from = Math.Max(0, from);
        to = Math.Min(tokens.Count - 1, to);
        var startOff = tokens[from].Offset;
        var endOff = tokens[to].End;
        var len = endOff - startOff;
        // 调用方持有原始 sql，这里用 token.Text 近似（空白可能丢失），准确性由调用方提供 sql 保证
        var sb = new System.Text.StringBuilder();
        for (var i = from; i <= to; i++)
        {
            if (i > from) sb.Append(' ');
            sb.Append(tokens[i].Text);
        }
        var text = sb.ToString();
        return text.Length <= max ? text : text[..max] + "…";
    }

    public static string Clamp(string text, int max) =>
        text.Length <= max ? text : text[..max] + "…";

    /// <summary>把数字 token 转为 double。</summary>
    public static bool TryNumber(SqlToken token, out double value)
    {
        value = 0;
        if (token.Kind != TokKind.Number) return false;
        return double.TryParse(token.Value, System.Globalization.NumberStyles.Float,
            System.Globalization.CultureInfo.InvariantCulture, out value);
    }

    public static bool IsComparisonOperator(SqlToken t) =>
        (t.Kind == TokKind.Operator && t.Text is "=" or "<>" or "!=" or "<" or ">" or "<=" or ">=" or "<=>")
        || t.IsKeyword("LIKE") || t.IsKeyword("IS") || t.IsKeyword("RLIKE") || t.IsKeyword("REGEXP");

    /// <summary>取语句的第一个非注释 token。</summary>
    public static int FirstSignificant(IReadOnlyList<SqlToken> tokens)
    {
        for (var i = 0; i < tokens.Count; i++)
        {
            if (tokens[i].Kind is not (TokKind.Comment or TokKind.ExecutableComment)) return i;
        }
        return -1;
    }

    /// <summary>语句首关键字（大写），如 SELECT / GRANT / CREATE。</summary>
    public static string FirstKeyword(IReadOnlyList<SqlToken> tokens)
    {
        var i = FirstSignificant(tokens);
        if (i < 0) return "";
        var t = tokens[i];
        return t.Kind is TokKind.Identifier or TokKind.QuotedIdentifier
            ? t.Value.ToUpperInvariant()
            : "";
    }

    /// <summary>语句中是否出现关键字（任意位置）。</summary>
    public static bool ContainsKeyword(IReadOnlyList<SqlToken> tokens, string keyword) =>
        tokens.Any(t => t.IsKeyword(keyword));

    /// <summary>在下标区间 [from,to] 内是否出现操作符（如 ';' 之外的 '--' 注释）。</summary>
    public static bool ContainsOperator(IReadOnlyList<SqlToken> tokens, int from, int to, string op)
    {
        for (var i = Math.Max(0, from); i <= Math.Min(to, tokens.Count - 1); i++)
        {
            if (tokens[i].IsOperator(op)) return true;
        }
        return false;
    }
}
