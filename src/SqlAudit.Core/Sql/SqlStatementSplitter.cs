namespace SqlAudit.Core.Sql;

/// <summary>SQL 语句切片结果。</summary>
public sealed record SqlStatementSegment(string Sql, int Offset, int Terminated);

/// <summary>
/// 以 token 流为基础做语句切分：字符串、注释、$$ 引用体内的分号天然不会是 Semicolon token，
/// 因此比正则按 ';' split 可靠。
/// 对 CREATE PROCEDURE/FUNCTION/TRIGGER/EVENT 这类含 BEGIN...END 体的定义，不做内部分割
/// （MySQL 客户端用 DELIMITER 改分隔符，服务端日志里通常仍以 ';' 出现，内部切分会把过程体拆碎）。
/// </summary>
public static class SqlStatementSplitter
{
    public static IReadOnlyList<SqlStatementSegment> Split(string sql, SqlDialect dialect)
    {
        var tokens = SqlLexer.Tokenize(sql, dialect);
        var result = new List<SqlStatementSegment>();
        if (tokens.Count == 0) return result;

        var buffer = new List<SqlToken>();
        var routineBody = IsRoutineDefinition(tokens);

        foreach (var token in tokens)
        {
            if (token.Kind == TokKind.Semicolon && !routineBody)
            {
                Flush(buffer, result, sql, terminated: true);
                buffer = new List<SqlToken>();
                continue;
            }
            buffer.Add(token);
        }
        Flush(buffer, result, sql, terminated: false);
        return result;
    }

    /// <summary>返回语句个数（不含空语句）。</summary>
    public static int CountStatements(string sql, SqlDialect dialect) => Split(sql, dialect).Count;

    private static void Flush(List<SqlToken> buffer, List<SqlStatementSegment> result, string sql, bool terminated)
    {
        if (buffer.Count == 0) return;
        var start = buffer[0].Offset;
        var end = buffer[^1].End;
        var text = sql[start..end];
        if (string.IsNullOrWhiteSpace(text)) return;
        result.Add(new SqlStatementSegment(text, start, terminated ? 1 : 0));
    }

    private static bool IsRoutineDefinition(IReadOnlyList<SqlToken> tokens)
    {
        // 仅检查前若干 token，匹配 CREATE [OR REPLACE] [DEFINER=..] PROCEDURE|FUNCTION|TRIGGER|EVENT
        var limit = Math.Min(tokens.Count, 12);
        var seenCreate = false;
        for (var i = 0; i < limit; i++)
        {
            var t = tokens[i];
            if (t.Kind is TokKind.Comment or TokKind.ExecutableComment) continue;
            if (!seenCreate)
            {
                if (t.IsKeyword("CREATE")) seenCreate = true;
                else break;
                continue;
            }
            if (t.Kind is TokKind.Identifier or TokKind.QuotedIdentifier)
            {
                var v = t.Value.ToUpperInvariant();
                if (v is "PROCEDURE" or "FUNCTION" or "TRIGGER" or "EVENT") return true;
            }
        }
        return false;
    }
}
