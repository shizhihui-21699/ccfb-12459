using System.Globalization;
using SqlAudit.Core.Model;

namespace SqlAudit.Core.Parsing;

/// <summary>
/// PostgreSQL csvlog 解析器。列顺序取自 PostgreSQL 官方文档（log_destination=csvlog，共 23 列，
/// 19.8 章 “CSV 日志输出”）。列可能因版本差异略有增减，这里按下标读取并对越界做保护。
/// 下标：
///  0 log_time, 1 user_name, 2 database_name, 3 process_id, 4 connection_from,
///  5 session_id, 6 session_line_num, 7 command_tag, 8 session_start_time,
///  9 virtual_transaction_id, 10 transaction_id, 11 error_severity, 12 sql_state_code,
///  13 message, 14 detail, 15 hint, 16 internal_query, 17 internal_query_pos,
///  18 context, 19 query, 20 query_pos, 21 location, 22 application_name
/// </summary>
public sealed class PostgreSqlCsvLogParser : IAuditLogParser
{
    public AuditSource Source => AuditSource.PostgreSqlCsvLog;

    public bool LooksLike(ReadOnlySpan<char> sample)
    {
        // csvlog 的关键特征：每行有 20+ 个逗号字段，且首字段是时间戳。
        // 注意 PG 只在字段含逗号/引号/换行时才加引号，首字段往往不带引号，
        // 因此不能要求整行以 '"' 开头。
        var text = sample.Length > 16384 ? sample[..16384].ToString() : sample.ToString();
        var lines = text.Split('\n', 40);
        var hits = 0;

        foreach (var raw in lines)
        {
            var line = raw.TrimEnd('\r');
            if (line.Length < 40) continue;
            if (line.Count(c => c == ',') < 18) continue;

            var firstField = line.StartsWith('"')
                ? line[1..Math.Min(line.Length, 40)]
                : line[..Math.Min(line.Length, 40)];
            if (!TimestampParser.LooksLikeTimestamp(firstField)) continue;

            hits++;
            if (hits >= 2) return true;
        }

        return hits >= 1;
    }

    public ParseResult Parse(TextReader reader, string? sourceFile)
    {
        var result = new ParseResult { DetectedSource = AuditSource.PostgreSqlCsvLog };
        var csv = new CsvRecordReader(reader);
        List<string>? record;

        while ((record = csv.ReadRecord()) is not null)
        {
            var line = csv.RecordStartLine;
            if (record.Count == 1 && string.IsNullOrWhiteSpace(record[0])) continue;

            if (record.Count < 21)
            {
                result.Warn(line, $"csvlog 列数为 {record.Count}，少于预期 21 列，已跳过");
                continue;
            }

            var logTime = TimestampParser.Parse(Field(record, 0));
            if (logTime is null)
            {
                result.Warn(line, "无法解析 log_time 列");
                continue;
            }

            var commandTag = Field(record, 7);
            var message = Field(record, 13);
            var query = Field(record, 19);

            // csvlog 中语句通常位于 query 列（message 列在 log_statement 时也含语句）；
            // 优先取 query，缺失时回退 message（statement/error 日志的 message 即 SQL）。
            var statement = !string.IsNullOrWhiteSpace(query) ? query
                : !string.IsNullOrWhiteSpace(message) && LooksLikeSql(message) ? message
                : "";

            // 仅采集含 SQL 的记录：连接、断开、检查点等无语句事件跳过
            if (string.IsNullOrWhiteSpace(statement)) continue;

            var severity = Field(record, 11);
            var succeeded = !string.Equals(severity, "ERROR", StringComparison.OrdinalIgnoreCase)
                            && !string.Equals(severity, "FATAL", StringComparison.OrdinalIgnoreCase)
                            && !string.Equals(severity, "PANIC", StringComparison.OrdinalIgnoreCase);

            var ev = new AuditEvent
            {
                Source = AuditSource.PostgreSqlCsvLog,
                Timestamp = logTime.Value,
                Account = Field(record, 1),
                Database = Field(record, 2),
                SessionId = Field(record, 3),
                ClientHost = NormalizeHost(Field(record, 4)),
                CommandTag = commandTag,
                Statement = AuditLimits.Clamp(statement, AuditLimits.MaxStatementChars),
                Succeeded = succeeded,
                ErrorCode = Field(record, 12),
                ServerHost = Field(record, 22),
                SourceFile = sourceFile,
                SourceLine = line,
            };

            // 时长从 message 尾巴里的 "duration: 1234.567 ms" 提取（PG 在 log_min_duration_statement 时附加）
            var duration = ExtractDuration(message, Field(record, 14));
            if (duration is not null) ev.DurationMs = duration;

            // 标准 csvlog 没有“返回行数”列。启用 auto_explain（log_analyze=on）时，
            // 执行计划会写进 message/detail，其中根节点的 "actual ... rows=N" 即真实返回行数。
            var rows = ExtractActualRows(message) ?? ExtractActualRows(Field(record, 14));
            if (rows is not null) ev.RowsReturned = rows;

            ev.RawRecord = AuditLimits.Clamp(
                string.Join(",", record.Select(f => f.Replace('\n', ' '))), AuditLimits.MaxRawChars);

            result.Events.Add(ev);
        }

        return result;
    }

    private static string Field(List<string> record, int index) =>
        index < record.Count ? record[index] : "";

    private static string NormalizeHost(string connectionFrom)
    {
        if (string.IsNullOrWhiteSpace(connectionFrom)) return "";
        // connection_from 形如 "10.20.3.41:53122" 或 "[::1]:53122"，仅给 IPv6 时方括号处理
        var value = connectionFrom.Trim();
        if (value.EndsWith(']')) return value;
        var idx = value.LastIndexOf(':');
        if (idx > 0 && value.IndexOf(':') == idx) return value[..idx];
        return value;
    }

    private static readonly string[] DurationMarkers = ["duration: ", "执行时间: "];

    /// <summary>
    /// 从 auto_explain 输出中提取根节点的实际行数。
    /// 计划文本形如：
    /// <code>
    /// Query Text: SELECT * FROM core.customers
    /// Seq Scan on customers  (cost=0.00..15234.00 rows=758330 width=212) (actual time=0.021..612.3 rows=758330 loops=1)
    /// </code>
    /// 取第一个出现 "actual ... rows=" 的行（即根节点），没有则退回估算 rows=。
    /// </summary>
    internal static long? ExtractActualRows(string text)
    {
        if (string.IsNullOrEmpty(text) || !text.Contains("cost=", StringComparison.Ordinal)) return null;

        long? estimated = null;
        foreach (var line in text.Split('\n'))
        {
            var actualIdx = line.IndexOf("actual time=", StringComparison.OrdinalIgnoreCase);
            var rowsIdx = line.IndexOf("rows=", actualIdx >= 0 ? actualIdx : 0, StringComparison.OrdinalIgnoreCase);
            if (rowsIdx < 0) continue;

            var start = rowsIdx + "rows=".Length;
            var end = start;
            while (end < line.Length && char.IsDigit(line[end])) end++;
            if (end == start) continue;

            if (!long.TryParse(line[start..end], out var value)) continue;
            if (actualIdx >= 0) return value;
            estimated ??= value;
        }

        return estimated;
    }

    internal static double? ExtractDuration(string message, string detail)
    {
        foreach (var text in new[] { message, detail })
        {
            if (string.IsNullOrEmpty(text)) continue;
            foreach (var marker in DurationMarkers)
            {
                var idx = text.LastIndexOf(marker, StringComparison.OrdinalIgnoreCase);
                if (idx < 0) continue;
                var rest = text[(idx + marker.Length)..].Trim();
                var numEnd = 0;
                while (numEnd < rest.Length && (char.IsDigit(rest[numEnd]) || rest[numEnd] == '.')) numEnd++;
                if (numEnd == 0) continue;
                if (!double.TryParse(rest[..numEnd], NumberStyles.Float, CultureInfo.InvariantCulture, out var ms))
                    continue;
                var unit = rest[numEnd..].TrimStart().ToLowerInvariant();
                return unit.StartsWith("s") && !unit.StartsWith("statement") ? ms * 1000.0 : ms;
            }
        }
        return null;
    }

    private static bool LooksLikeSql(string text)
    {
        var t = text.TrimStart();
        if (t.Length < 6) return false;
        ReadOnlySpan<string> prefixes =
        [
            "SELECT", "INSERT", "UPDATE", "DELETE", "WITH", "CREATE", "ALTER", "DROP",
            "GRANT", "REVOKE", "COPY", "TRUNCATE", "BEGIN", "COMMIT", "ROLLBACK", "VACUUM",
        ];
        foreach (var p in prefixes)
        {
            if (t.StartsWith(p, StringComparison.OrdinalIgnoreCase)) return true;
        }
        return false;
    }
}
