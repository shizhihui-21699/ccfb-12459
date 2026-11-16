using System.Globalization;
using System.Text.Json;

namespace SqlAudit.Core.Parsing;

/// <summary>JSON 属性读取工具，兼容字符串/数字/布尔多种存储形态。</summary>
internal static class JsonHelpers
{
    public static bool TryGet(JsonElement obj, string name, out JsonElement value)
    {
        if (obj.ValueKind == JsonValueKind.Object && obj.TryGetProperty(name, out value))
        {
            return value.ValueKind is not (JsonValueKind.Null or JsonValueKind.Undefined);
        }
        value = default;
        return false;
    }

    public static bool TryGetAny(JsonElement obj, out JsonElement value, params string[] names)
    {
        foreach (var name in names)
        {
            if (TryGet(obj, name, out value)) return true;
        }
        value = default;
        return false;
    }

    public static string? GetString(JsonElement obj, params string[] names)
    {
        if (!TryGetAny(obj, out var value, names)) return null;
        return value.ValueKind switch
        {
            JsonValueKind.String => value.GetString(),
            JsonValueKind.Number => value.ToString(),
            JsonValueKind.True => "true",
            JsonValueKind.False => "false",
            _ => value.ToString(),
        };
    }

    public static long? GetLong(JsonElement obj, params string[] names)
    {
        if (!TryGetAny(obj, out var value, names)) return null;
        switch (value.ValueKind)
        {
            case JsonValueKind.Number:
                if (value.TryGetInt64(out var l)) return l;
                if (value.TryGetDouble(out var d)) return (long)Math.Round(d);
                return null;
            case JsonValueKind.String:
                var s = value.GetString();
                if (string.IsNullOrWhiteSpace(s)) return null;
                if (long.TryParse(s, NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsed)) return parsed;
                if (double.TryParse(s, NumberStyles.Float, CultureInfo.InvariantCulture, out var dbl)) return (long)Math.Round(dbl);
                return null;
            default:
                return null;
        }
    }

    public static double? GetDouble(JsonElement obj, params string[] names)
    {
        if (!TryGetAny(obj, out var value, names)) return null;
        switch (value.ValueKind)
        {
            case JsonValueKind.Number:
                return value.TryGetDouble(out var d) ? d : null;
            case JsonValueKind.String:
                var s = value.GetString();
                if (!string.IsNullOrWhiteSpace(s))
                {
                    // 支持 "1234.5 ms" 这类带单位的值
                    var span = s.AsSpan().Trim();
                    var end = 0;
                    while (end < span.Length && (char.IsDigit(span[end]) || span[end] == '.' || span[end] == '-'))
                        end++;
                    if (end > 0 && double.TryParse(span[..end], NumberStyles.Float, CultureInfo.InvariantCulture, out var d2))
                    {
                        var unit = span[end..].Trim();
                        if (unit.StartsWith("s") && !unit.StartsWith("stat")) d2 *= 1000.0;
                        return d2;
                    }
                }
                return null;
            default:
                return null;
        }
    }

    public static bool? GetBool(JsonElement obj, params string[] names)
    {
        if (!TryGetAny(obj, out var value, names)) return null;
        return value.ValueKind switch
        {
            JsonValueKind.True => true,
            JsonValueKind.False => false,
            JsonValueKind.Number => value.TryGetInt64(out var l) ? l != 0 : null,
            JsonValueKind.String => bool.TryParse(value.GetString(), out var b) ? b : null,
            _ => null,
        };
    }

    public static DateTimeOffset? GetTimestamp(JsonElement obj, params string[] names)
    {
        if (!TryGetAny(obj, out var value, names)) return null;

        if (value.ValueKind == JsonValueKind.Number && value.TryGetInt64(out var unix))
            return TimestampParser.FromUnix(unix);
        if (value.ValueKind == JsonValueKind.Number && value.TryGetDouble(out var unixF))
            return TimestampParser.FromUnix(unixF);
        var text = GetString(obj, names);
        return TimestampParser.Parse(text);
    }
}
