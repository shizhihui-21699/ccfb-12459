using System.Text;

namespace SqlAudit.Core.Sql;

/// <summary>SQL 方言。</summary>
public enum SqlDialect
{
    MySql,
    PostgreSql,
}

/// <summary>
/// 容错 SQL 词法分析器。不追求完整语法树，只需要把字符串、标识符、注释正确切开，
/// 以便后续规则在“去字符串化”的 token 流上做结构匹配。
/// 支持：
///   MySQL  —— 反引号标识符、# 注释、/*! 可执行注释、反斜杠转义、0x/0b 字面量、@@变量
///   PG     —— $tag$ 美元引用、E'' 转义串、嵌套块注释、"" 标识符、:: 转换、$1 占位符
/// </summary>
public static class SqlLexer
{
    public static IReadOnlyList<SqlToken> Tokenize(string sql, SqlDialect dialect)
    {
        var tokens = new List<SqlToken>();
        if (string.IsNullOrEmpty(sql)) return tokens;

        var i = 0;
        var n = sql.Length;

        while (i < n)
        {
            var c = sql[i];

            // 空白
            if (char.IsWhiteSpace(c))
            {
                i++;
                continue;
            }

            // 行注释 --（MySQL 要求 -- 后跟空白或行尾；宽松处理，但避免把 5--3 当作注释）
            if (c == '-' && i + 1 < n && sql[i + 1] == '-')
            {
                if (dialect == SqlDialect.PostgreSql || i + 2 >= n || char.IsWhiteSpace(sql[i + 2]))
                {
                    var start = i;
                    while (i < n && sql[i] != '\n') i++;
                    tokens.Add(new SqlToken(TokKind.Comment, sql[start..i], sql[start..i], start, i - start));
                    continue;
                }
            }

            // # 行注释（仅 MySQL）
            if (c == '#' && dialect == SqlDialect.MySql)
            {
                var start = i;
                while (i < n && sql[i] != '\n') i++;
                tokens.Add(new SqlToken(TokKind.Comment, sql[start..i], sql[start..i], start, i - start));
                continue;
            }

            // 块注释 /* ... */，MySQL 的 /*! ... */ 为可执行注释；PG 支持嵌套
            if (c == '/' && i + 1 < n && sql[i + 1] == '*')
            {
                var start = i;
                var executable = i + 2 < n && sql[i + 2] == '!';
                i += executable ? 3 : 2;

                // 可执行注释可带版本号，如 /*!50000 ... */，跳过前导数字
                if (executable)
                {
                    var vstart = i;
                    while (i < n && char.IsDigit(sql[i])) i++;
                    if (i == vstart) { /* 无版本号 */ }
                }

                var depth = 1;
                var bodyStart = i;
                while (i < n && depth > 0)
                {
                    if (i + 1 < n && sql[i] == '*' && sql[i + 1] == '/')
                    {
                        depth--;
                        if (depth == 0) break;
                        i += 2;
                    }
                    else if (dialect == SqlDialect.PostgreSql && i + 1 < n && sql[i] == '/' && sql[i + 1] == '*')
                    {
                        depth++;
                        i += 2;
                    }
                    else i++;
                }

                var body = bodyStart <= i ? sql[bodyStart..Math.Min(i, n)] : "";
                if (i + 1 < n && sql[i] == '*' && sql[i + 1] == '/') i += 2;
                var length = i - start;
                tokens.Add(new SqlToken(
                    executable ? TokKind.ExecutableComment : TokKind.Comment,
                    sql.Substring(start, length),
                    executable ? body : sql.Substring(start, length),
                    start,
                    length));
                continue;
            }

            // 单引号字符串（两种方言都支持 '' 转义；MySQL 额外支持反斜杠转义）
            if (c == '\'')
            {
                tokens.Add(ReadQuotedString(sql, ref i, dialect, prefixLen: 0));
                continue;
            }

            // E'...' / e'...' 前缀字符串（PG）
            if ((c == 'E' || c == 'e') && i + 1 < n && sql[i + 1] == '\''
                && (i == 0 || !IsIdentifierChar(sql[i - 1])))
            {
                var start = i;
                i++;
                var token = ReadQuotedString(sql, ref i, dialect, prefixLen: 0);
                tokens.Add(token with { Offset = start, Length = i - start, Text = sql[start..i] });
                continue;
            }

            // 双引号：PG 为标识符引用，MySQL 默认也是字符串
            if (c == '"')
            {
                var start = i;
                var value = ReadDelimited(sql, ref i, '"', allowBackslash: dialect == SqlDialect.MySql);
                var kind = dialect == SqlDialect.PostgreSql ? TokKind.QuotedIdentifier : TokKind.String;
                tokens.Add(new SqlToken(kind, sql[start..i], value, start, i - start));
                continue;
            }

            // 反引号标识符（MySQL）
            if (c == '`')
            {
                var start = i;
                var value = ReadDelimited(sql, ref i, '`', allowBackslash: false);
                tokens.Add(new SqlToken(TokKind.QuotedIdentifier, sql[start..i], value, start, i - start));
                continue;
            }

            // 美元引用 $tag$ ... $tag$（PG）
            if (c == '$' && dialect == SqlDialect.PostgreSql)
            {
                if (TryReadDollarQuoted(sql, ref i, out var token))
                {
                    tokens.Add(token);
                    continue;
                }
            }

            // 数字 / 十六进制 / 位串
            if (char.IsDigit(c) || (c == '.' && i + 1 < n && char.IsDigit(sql[i + 1])))
            {
                tokens.Add(ReadNumber(sql, ref i));
                continue;
            }

            // 0x.. 十六进制（MySQL）
            if ((c == 'x' || c == 'X') && i + 1 < n && sql[i + 1] == '\'')
            {
                var start = i;
                i += 2;
                var sb = new StringBuilder();
                while (i < n && sql[i] != '\'')
                {
                    sb.Append(sql[i]);
                    i++;
                }
                if (i < n) i++;
                tokens.Add(new SqlToken(TokKind.HexLiteral, sql[start..i], sb.ToString(), start, i - start));
                continue;
            }

            // 变量：@@global.x、@x、:name、$1
            if (c == '@')
            {
                var start = i;
                i++;
                if (i < n && sql[i] == '@') i++;
                while (i < n && (IsIdentifierChar(sql[i]) || sql[i] == '.')) i++;
                tokens.Add(new SqlToken(TokKind.Variable, sql[start..i], sql[start..i], start, i - start));
                continue;
            }

            // PG 位置参数 $1
            if (c == '$' && i + 1 < n && char.IsDigit(sql[i + 1]))
            {
                var start = i;
                i++;
                while (i < n && char.IsDigit(sql[i])) i++;
                tokens.Add(new SqlToken(TokKind.Placeholder, sql[start..i], sql[start..i], start, i - start));
                continue;
            }

            // 标识符 / 关键字
            if (IsIdentifierStart(c))
            {
                var start = i;
                while (i < n && IsIdentifierChar(sql[i])) i++;
                var text = sql[start..i];
                tokens.Add(new SqlToken(TokKind.Identifier, text, text, start, i - start));
                continue;
            }

            // 语句分隔符
            if (c == ';')
            {
                tokens.Add(new SqlToken(TokKind.Semicolon, ";", ";", i, 1));
                i++;
                continue;
            }

            // 标点
            if (c is '(' or ')' or ',' or '.' or '[' or ']' or '{' or '}')
            {
                tokens.Add(new SqlToken(TokKind.Punctuation, c.ToString(), c.ToString(), i, 1));
                i++;
                continue;
            }

            // 运算符（最长匹配）
            var opLen = MatchOperator(sql, i);
            if (opLen > 0)
            {
                tokens.Add(new SqlToken(TokKind.Operator, sql.Substring(i, opLen), sql.Substring(i, opLen), i, opLen));
                i += opLen;
                continue;
            }

            // 未知字符，吞掉一个字符以保证前进
            tokens.Add(new SqlToken(TokKind.Punctuation, c.ToString(), c.ToString(), i, 1));
            i++;
        }

        return tokens;
    }

    private static SqlToken ReadQuotedString(string sql, ref int i, SqlDialect dialect, int prefixLen)
    {
        var start = i;
        var value = ReadDelimited(sql, ref i, '\'', allowBackslash: dialect == SqlDialect.MySql);
        return new SqlToken(TokKind.String, sql[start..i], value, start, i - start);
    }

    /// <summary>读取以 quote 包裹的片段，处理重复引号与（可选）反斜杠转义，返回去掉引号的内部值。</summary>
    private static string ReadDelimited(string sql, ref int i, char quote, bool allowBackslash)
    {
        var n = sql.Length;
        i++; // 跳过起始引号
        var sb = new StringBuilder();
        while (i < n)
        {
            var c = sql[i];
            if (c == quote)
            {
                if (i + 1 < n && sql[i + 1] == quote)
                {
                    sb.Append(quote);
                    i += 2;
                    continue;
                }
                i++;
                return sb.ToString();
            }
            if (allowBackslash && c == '\\' && i + 1 < n)
            {
                sb.Append(sql[i + 1]);
                i += 2;
                continue;
            }
            sb.Append(c);
            i++;
        }
        return sb.ToString(); // 未闭合，容错返回已读内容
    }

    private static bool TryReadDollarQuoted(string sql, ref int i, out SqlToken token)
    {
        token = default;
        var n = sql.Length;
        var start = i;
        var j = i + 1;
        // $tag$ 中 tag 可为空或标识符
        while (j < n && (char.IsLetterOrDigit(sql[j]) || sql[j] == '_')) j++;
        if (j >= n || sql[j] != '$') return false;

        var tag = sql[start..(j + 1)]; // 含两端 $
        var bodyStart = j + 1;
        var close = sql.IndexOf(tag, bodyStart, StringComparison.Ordinal);
        int end;
        string body;
        if (close < 0)
        {
            body = sql[bodyStart..];
            end = n;
        }
        else
        {
            body = sql[bodyStart..close];
            end = close + tag.Length;
        }

        token = new SqlToken(TokKind.String, sql[start..end], body, start, end - start);
        i = end;
        return true;
    }

    private static SqlToken ReadNumber(string sql, ref int i)
    {
        var n = sql.Length;
        var start = i;

        // 十六进制 / 位串字面量
        if (sql[i] == '0' && i + 1 < n && (sql[i + 1] == 'x' || sql[i + 1] == 'X' || sql[i + 1] == 'b' || sql[i + 1] == 'B'))
        {
            var kind = char.ToLowerInvariant(sql[i + 1]) == 'x' ? TokKind.HexLiteral : TokKind.BitLiteral;
            i += 2;
            while (i < n && Uri.IsHexDigit(sql[i])) i++;
            return new SqlToken(kind, sql[start..i], sql[start..i], start, i - start);
        }

        while (i < n && char.IsDigit(sql[i])) i++;
        if (i < n && sql[i] == '.' && (i + 1 >= n || sql[i + 1] != '.'))
        {
            i++;
            while (i < n && char.IsDigit(sql[i])) i++;
        }
        if (i < n && (sql[i] == 'e' || sql[i] == 'E'))
        {
            var save = i;
            i++;
            if (i < n && (sql[i] == '+' || sql[i] == '-')) i++;
            if (i < n && char.IsDigit(sql[i]))
            {
                while (i < n && char.IsDigit(sql[i])) i++;
            }
            else i = save;
        }
        return new SqlToken(TokKind.Number, sql[start..i], sql[start..i], start, i - start);
    }

    private static int MatchOperator(string sql, int i)
    {
        ReadOnlySpan<string> multi = ["->>", "<=>", "<=", ">=", "<>", "!=", "||", "&&", ":=", "::", "->", "#>", "@>", "<@", "!~*", "!~", "~*"];
        foreach (var op in multi)
        {
            if (string.CompareOrdinal(sql, i, op, 0, op.Length) == 0) return op.Length;
        }
        return i < sql.Length && "+-*/%=<>!~^&|?:".IndexOf(sql[i]) >= 0 ? 1 : 0;
    }

    private static bool IsIdentifierStart(char c) => char.IsLetter(c) || c == '_' || c > 127;

    private static bool IsIdentifierChar(char c) => char.IsLetterOrDigit(c) || c == '_' || c == '$' || c > 127;
}
