using System.Globalization;
using System.Text;
using System.Text.Json;

namespace SqlAudit.SampleGen;

/// <summary>把数据集写成三种目标日志格式。</summary>
public static class LogWriters
{
    public static void WriteMySqlAuditJson(SampleDataset dataset, string path)
    {
        using var writer = new StreamWriter(path, false, new UTF8Encoding(false));
        var id = 0;
        foreach (var ev in dataset.Events)
        {
            id++;
            using var buffer = new MemoryStream();
            using (var json = new Utf8JsonWriter(buffer, new JsonWriterOptions { Indented = false }))
            {
                json.WriteStartObject();
                json.WriteString("timestamp", ev.Timestamp.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss.ffffff'Z'", CultureInfo.InvariantCulture));
                json.WriteNumber("id", id);
                json.WriteString("class", "general");
                json.WriteString("event", "status");
                json.WriteNumber("connection_id", long.TryParse(ev.SessionId, out var cid) ? cid : id);
                json.WriteString("server_id", "prod-mysql-01:3306");

                json.WriteStartObject("account");
                json.WriteString("user", ev.Account);
                json.WriteString("host", ev.ClientHost);
                json.WriteEndObject();

                json.WriteStartObject("general_data");
                json.WriteString("command", string.IsNullOrEmpty(ev.Command) ? "Query" : ev.Command);
                json.WriteString("sqltext", ev.Statement);
                json.WriteString("db", ev.Database);
                // 插件以微秒计时
                json.WriteNumber("query_time", Math.Round((ev.DurationMs ?? 0) * 1000.0, 0));
                if (ev.RowsReturned is { } rows) json.WriteNumber("rows_sent", rows);
                if (ev.RowsAffected is { } affected) json.WriteNumber("rows_affected", affected);
                json.WriteNumber("status", ev.Succeeded ? 0 : 1);
                if (!ev.Succeeded && ev.ErrorCode is not null) json.WriteString("error_code", ev.ErrorCode);
                json.WriteEndObject();

                json.WriteEndObject();
            }
            writer.WriteLine(Encoding.UTF8.GetString(buffer.ToArray()));
        }
    }

    public static void WriteMySqlGeneralLog(SampleDataset dataset, string path)
    {
        using var writer = new StreamWriter(path, false, new UTF8Encoding(false));
        writer.WriteLine("mysqld, Version: 8.0.39 (MySQL Community Server - GPL). started with:");
        writer.WriteLine("Tcp port: 3306  Unix socket: /var/run/mysqld/mysqld.sock");
        writer.WriteLine("Time                 Id Command    Argument");

        string? currentSession = null;
        foreach (var ev in dataset.Events)
        {
            // 会话切换时补一条 Connect，形成真实的 general log 观感
            if (ev.SessionId != currentSession)
            {
                currentSession = ev.SessionId;
                var stamp = ev.Timestamp.UtcDateTime.AddMilliseconds(-120);
                writer.WriteLine(
                    $"{stamp:yyyy-MM-dd'T'HH:mm:ss.ffffff'Z'}\t{ev.SessionId} Connect\t{ev.Account}@{ev.ClientHost} on {ev.Database} using TCP/IP");
            }

            var ts = ev.Timestamp.UtcDateTime;
            // 模拟 general log 对长语句的换行（按 80 列折行）
            var statement = ev.Statement;
            if (statement.Contains('\n') || statement.Length > 200)
            {
                var lines = statement.Split('\n');
                writer.WriteLine($"{ts:yyyy-MM-dd'T'HH:mm:ss.ffffff'Z'}\t{ev.SessionId} Query\t{lines[0]}");
                foreach (var line in lines.Skip(1))
                    writer.WriteLine($"\t\t\t{line}");
            }
            else
            {
                writer.WriteLine($"{ts:yyyy-MM-dd'T'HH:mm:ss.ffffff'Z'}\t{ev.SessionId} Query\t{statement}");
            }
        }
    }

    /// <summary>
    /// PostgreSQL csvlog：23 列，字段按需加引号，SQL 中的换行与双引号按 CSV 规则转义。
    /// </summary>
    public static void WritePostgreSqlCsvLog(SampleDataset dataset, string path)
    {
        using var writer = new StreamWriter(path, false, new UTF8Encoding(false));
        var lineNo = 0;
        foreach (var ev in dataset.Events)
        {
            lineNo++;
            var fields = new List<string>
            {
                ev.Timestamp.UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss.fff' UTC'", CultureInfo.InvariantCulture), // 0 log_time
                ev.Account,                          // 1 user_name
                ev.Database,                         // 2 database_name
                ev.SessionId,                        // 3 process_id
                $"{ev.ClientHost}:{40000 + lineNo % 20000}", // 4 connection_from
                $"69b{lineNo:x8}.{lineNo:x4}",       // 5 session_id
                lineNo.ToString(CultureInfo.InvariantCulture), // 6 session_line_num
                string.IsNullOrEmpty(ev.Command) ? "SELECT" : ev.Command, // 7 command_tag
                "2026-11-12 00:00:00 UTC",           // 8 session_start_time
                "3/8821",                            // 9 virtual_transaction_id
                "0",                                 // 10 transaction_id
                ev.Succeeded ? "LOG" : "ERROR",      // 11 error_severity
                ev.Succeeded ? "00000" : "42501",    // 12 sql_state_code
                BuildMessage(ev),                    // 13 message
                "",                                  // 14 detail
                "",                                  // 15 hint
                "",                                  // 16 internal_query
                "",                                  // 17 internal_query_pos
                "",                                  // 18 context
                ev.Statement,                        // 19 query
                "",                                  // 20 query_pos
                "pg_app@prod-pg-01",                 // 21 location
                "psql",                              // 22 application_name
            };

            writer.WriteLine(string.Join(",", fields.Select(EscapeCsvField)));
        }
    }

    private static string BuildMessage(SampleEvent ev)
    {
        if (!ev.Succeeded)
            return ev.ErrorCode is null ? "permission denied" : $"permission denied for table (code {ev.ErrorCode})";

        var duration = ev.DurationMs is { } ms
            ? $"duration: {ms.ToString("0.000", CultureInfo.InvariantCulture)} ms"
            : "statement";

        // 模拟启用 auto_explain（log_analyze=on）时的计划输出：
        // 只有慢查询才会被 auto_explain 记录，这里以 1s 为界。
        if (ev.RowsReturned is { } rows && ev.DurationMs is > 1000)
        {
            return duration
                   + "\nQuery Text: " + ev.Statement
                   + $"\nSeq Scan on {GuessTable(ev.Statement)}  (cost=0.00..15234.00 rows={rows} width=212)"
                   + $" (actual time=0.021..612.305 rows={rows} loops=1)"
                   + "\nPlanning Time: 0.412 ms\nExecution Time: " + (ev.DurationMs ?? 0).ToString("0.000", CultureInfo.InvariantCulture) + " ms";
        }

        return duration;
    }

    private static string GuessTable(string sql)
    {
        var idx = sql.IndexOf(" FROM ", StringComparison.OrdinalIgnoreCase);
        if (idx < 0) return "unknown";
        var rest = sql[(idx + 6)..].Trim();
        var end = rest.IndexOfAny([' ', '\n', ',', ';']);
        var name = end < 0 ? rest : rest[..end];
        var dot = name.LastIndexOf('.');
        return dot >= 0 ? name[(dot + 1)..] : name;
    }

    private static string EscapeCsvField(string value)
    {
        if (value.Length == 0) return "";
        var needsQuote = value.Contains(',') || value.Contains('"')
                         || value.Contains('\n') || value.Contains('\r');
        if (!needsQuote) return value;
        return "\"" + value.Replace("\"", "\"\"") + "\"";
    }
}
