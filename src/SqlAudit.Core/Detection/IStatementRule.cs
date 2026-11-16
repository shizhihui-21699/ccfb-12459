using SqlAudit.Core.Model;
using SqlAudit.Core.Sql;

namespace SqlAudit.Core.Detection;

/// <summary>单条语句的分析上下文。</summary>
public sealed class StatementContext
{
    public required string Sql { get; init; }

    public required IReadOnlyList<SqlToken> Tokens { get; init; }

    public required SqlDialect Dialect { get; init; }

    public required AuditEvent Event { get; init; }

    public required DetectionOptions Options { get; init; }

    /// <summary>语句首关键字（大写）。</summary>
    public string FirstKeyword => TokenUtils.FirstKeyword(Tokens);

    public bool ContainsKeyword(string keyword) => TokenUtils.ContainsKeyword(Tokens, keyword);

    /// <summary>去掉注释后的 token（可执行注释视为内容保留）。</summary>
    public IReadOnlyList<SqlToken> CodeTokens =>
        Tokens.Where(t => t.Kind != TokKind.Comment).ToList();

    public string EvidenceOf(SqlToken token, int max = 200) => TokenUtils.Clamp(TokenUtils.Slice(Sql, token), max);

    public string EvidenceRange(int offset, int length, int max = 200)
    {
        if (offset < 0 || offset >= Sql.Length) return "";
        var len = Math.Min(length, Sql.Length - offset);
        return TokenUtils.Clamp(Sql.Substring(offset, len), max);
    }

    /// <summary>数据集市：是否在 FROM/JOIN 之后出现过指定对象（schema.table 任意一侧匹配）。</summary>
    public bool ReferencesObject(params string[] names)
    {
        foreach (var name in names)
        {
            var dot = name.IndexOf('.');
            var table = dot >= 0 ? name[(dot + 1)..] : name;
            var schema = dot >= 0 ? name[..dot] : null;

            for (var i = 0; i < Tokens.Count; i++)
            {
                var t = Tokens[i];
                if (!t.IsAnyIdentifier(table)) continue;
                if (schema is null) return true;

                // 形如 schema . table 或是 "schema"."table" 合并 token
                if (i >= 2 && Tokens[i - 1].IsPunct('.') && Tokens[i - 2].IsAnyIdentifier(schema)) return true;
                var combined = t.Value;
                if (combined.Contains('.', StringComparison.Ordinal)
                    && combined.EndsWith("." + table, StringComparison.OrdinalIgnoreCase))
                    return true;
            }
        }
        return false;
    }
}

/// <summary>针对单条语句的检测规则。</summary>
public interface IStatementRule
{
    RuleDefinition Definition { get; }

    /// <summary>评估一条语句，返回 0..n 个 finding。规则内部必须容错，不得抛出。</summary>
    IEnumerable<Finding> Evaluate(StatementContext context);
}
