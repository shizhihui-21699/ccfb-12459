using System.Globalization;
using System.Text.RegularExpressions;

namespace SqlAudit.Core.Parsing;

/// <summary>时间解析工具：审计日志里时间格式五花八门，统一兜底为 UTC。</summary>
public static partial class TimestampParser
{
    private static readonly string[] Formats =
    [
        "yyyy-MM-dd HH:mm:ss.ffffff",
        "yyyy-MM-dd HH:mm:ss.fff",
        "yyyy-MM-dd HH:mm:ss",
        "yyyy-MM-ddTHH:mm:ss.ffffff",
        "yyyy-MM-ddTHH:mm:ss.fff",
        "yyyy-MM-ddTHH:mm:ssK",
        "yyyy-MM-ddTHH:mm:ss.ffffffK",
        "yyyy-MM-dd HH:mm:ss zzz",
        "yyyy/MM/dd HH:mm:ss",
        "MMM d, yyyy HH:mm:ss",
        "MMM  d, yyyy HH:mm:ss",
        "MMM d yyyy HH:mm:ss",
    ];

    /// <summary>
    /// 解析时间。假定日志中的朴素时间即 UTC（生产审计日志一般统一时区），
    /// 带时区后缀时按其偏移换算。PostgreSQL csvlog 写作 "2026-11-12 00:35:25.000 UTC"，
    /// MySQL general log 写作 ISO8601 的 "...Z"，两者都按 UTC 处理。
    /// </summary>
    public static DateTimeOffset? Parse(string? text)
    {
        if (string.IsNullOrWhiteSpace(text)) return null;
        var value = text.Trim();

        // 处理 trailing 时区缩写：UTC / GMT / CST 等（CST 有歧义，统一按 UTC 处理并记录在文档中）
        value = StripTrailingZoneAbbreviation(value);

        if (DateTimeOffset.TryParse(value, CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var dto))
        {
            return dto;
        }

        if (DateTime.TryParseExact(value, Formats, CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var dt))
        {
            return new DateTimeOffset(dt, TimeSpan.Zero);
        }

        return null;
    }

    private static readonly string[] ZoneSuffixes =
    [
        " UTC", " GMT", " Z", " +00:00", " +0000",
    ];

    private static string StripTrailingZoneAbbreviation(string value)
    {
        foreach (var suffix in ZoneSuffixes)
        {
            if (value.EndsWith(suffix, StringComparison.OrdinalIgnoreCase))
                return value[..^suffix.Length].TrimEnd();
        }
        return value;
    }

    /// <summary>解析 unix 时间戳（秒或毫秒）。</summary>
    public static DateTimeOffset? FromUnix(long value)
    {
        // 大于 1e12 视为毫秒
        return value > 1_000_000_000_000
            ? DateTimeOffset.FromUnixTimeMilliseconds(value)
            : DateTimeOffset.FromUnixTimeSeconds(value);
    }

    /// <summary>解析 unix 时间戳（含小数秒）。</summary>
    public static DateTimeOffset? FromUnix(double value)
    {
        var ms = (long)Math.Round(value * 1000.0);
        return DateTimeOffset.FromUnixTimeMilliseconds(ms);
    }

    [GeneratedRegex(@"^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}", RegexOptions.CultureInvariant)]
    private static partial Regex IsoLikeRegex();

    public static bool LooksLikeTimestamp(string? text) =>
        !string.IsNullOrEmpty(text) && IsoLikeRegex().IsMatch(text.Trim());
}
