using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace SqlAudit.Core.Sql;

/// <summary>
/// 语句归一化与指纹。归一化用于把同类语句聚合（忽略字面量差异），
/// 指纹用于基线聚类与去重。使用 SHA-256 而非 MD5。
/// </summary>
public static class SqlFingerprint
{
    public static string Compute(string sql, SqlDialect dialect)
    {
        var normalized = Normalize(sql, dialect);
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(normalized));
        return Convert.ToHexString(bytes)[..16].ToLowerInvariant();
    }

    /// <summary>
    /// 归一化：小写化关键字与标识符、字面量替换为占位符、去除注释、折叠空白。
    /// IN 列表这类变长字面量会被折叠成一个占位符，避免同一查询因参数个数不同而分裂。
    /// </summary>
    public static string Normalize(string sql, SqlDialect dialect)
    {
        var tokens = SqlLexer.Tokenize(sql, dialect);
        var sb = new StringBuilder(sql.Length);
        var prevPlaceholder = false;

        foreach (var token in tokens)
        {
            switch (token.Kind)
            {
                case TokKind.Comment:
                    continue;
                case TokKind.ExecutableComment:
                    sb.Append(" /*exec*/ ");
                    prevPlaceholder = false;
                    continue;
                case TokKind.String:
                case TokKind.HexLiteral:
                case TokKind.BitLiteral:
                    if (!prevPlaceholder) sb.Append('?');
                    prevPlaceholder = true;
                    continue;
                case TokKind.Number:
                    if (!prevPlaceholder) sb.Append('?');
                    prevPlaceholder = true;
                    continue;
                case TokKind.Variable:
                    sb.Append('@');
                    prevPlaceholder = false;
                    continue;
                case TokKind.Placeholder:
                    sb.Append('?');
                    prevPlaceholder = true;
                    continue;
                case TokKind.Identifier:
                case TokKind.QuotedIdentifier:
                    sb.Append(token.Value.ToLowerInvariant());
                    prevPlaceholder = false;
                    break;
                default:
                    sb.Append(token.Text);
                    prevPlaceholder = false;
                    break;
            }
            sb.Append(' ');
        }

        return string.Join(' ', sb.ToString().Split(' ', StringSplitOptions.RemoveEmptyEntries));
    }

    /// <summary>把 SQL 压成便于前端单行展示的短摘要。</summary>
    public static string Summarize(string sql, int max = 240)
    {
        if (string.IsNullOrEmpty(sql)) return "";
        var flat = string.Join(' ', sql.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries));
        return flat.Length <= max ? flat : flat[..max] + "…";
    }

    public static string FormatBytes(long bytes) => bytes switch
    {
        < 1024 => $"{bytes} B",
        < 1024 * 1024 => $"{bytes / 1024.0:0.#} KB",
        _ => $"{bytes / (1024.0 * 1024):0.#} MB",
    };

    public static string FormatDuration(double ms) => ms switch
    {
        < 1 => $"{ms:0.###} ms",
        < 1000 => $"{ms:0.#} ms",
        _ => $"{ms / 1000.0:0.##} s",
    };

    public static string FormatNumber(long value) =>
        value.ToString("N0", CultureInfo.InvariantCulture);
}
