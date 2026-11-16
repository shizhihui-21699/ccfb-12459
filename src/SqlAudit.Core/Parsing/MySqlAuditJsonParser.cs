using System.Text.Json;
using SqlAudit.Core.Model;

namespace SqlAudit.Core.Parsing;

/// <summary>
/// MySQL Enterprise Audit（JSON 新格式）解析器。
/// 记录形如：
/// <code>
/// {"timestamp":"2026-11-12T03:14:22.371Z","id":1,"class":"general","event":"status",
///  "connection_id":90412,"account":{"user":"app_reader","host":"10.20.3.41"},
///  "general_data":{"command":"Query","sqltext":"SELECT ...","query_time":1834,
///                  "rows_sent":12,"rows_affected":0,"status":0}}
/// </code>
/// 兼容性处理：
///  * 顶层也可能是 {"audit_record": {...}} 包装；
///  * 只采信 class 为 general/table_access（含 sqltext）的记录，连接/断连事件跳过；
///  * query_time 在该插件中以 <b>微秒</b> 计时，统一换算为毫秒；
///  * 字段名接受多套别名（sqltext/sql_text/query、rows_sent/rows/found_rows 等）。
/// </summary>
public sealed class MySqlAuditJsonParser : IAuditLogParser
{
    public AuditSource Source => AuditSource.MySqlAuditJson;

    public bool LooksLike(ReadOnlySpan<char> sample)
    {
        var text = sample.Length > 8192 ? sample[..8192] : sample;
        var s = text.ToString();
        if (!s.TrimStart().StartsWith('{') && !s.TrimStart().StartsWith('[')) return false;
        // 必须出现审计插件特征键
        return (s.Contains("\"class\"", StringComparison.Ordinal)
                || s.Contains("\"audit_record\"", StringComparison.Ordinal))
               && (s.Contains("sqltext", StringComparison.OrdinalIgnoreCase)
                   || s.Contains("\"general_data\"", StringComparison.Ordinal)
                   || s.Contains("\"table_access_data\"", StringComparison.Ordinal));
    }

    public ParseResult Parse(TextReader reader, string? sourceFile)
    {
        var result = new ParseResult { DetectedSource = AuditSource.MySqlAuditJson };

        foreach (var jsonRecord in JsonRecordReader.Read(reader))
        {
            var element = jsonRecord.Element;
            var line = jsonRecord.Line;
            var raw = jsonRecord.Raw;
            var record = element;
            if (JsonHelpers.TryGet(element, "audit_record", out var wrapped)
                && wrapped.ValueKind == JsonValueKind.Object)
            {
                record = wrapped;
            }

            var cls = JsonHelpers.GetString(record, "class");
            JsonElement data = record;
            if (JsonHelpers.TryGet(record, "general_data", out var gd) && gd.ValueKind == JsonValueKind.Object)
                data = gd;
            else if (JsonHelpers.TryGet(record, "table_access_data", out var td) && td.ValueKind == JsonValueKind.Object)
                data = td;

            var sqlText = JsonHelpers.GetString(data, "sqltext", "sql_text", "query", "statement")
                          ?? JsonHelpers.GetString(record, "sqltext", "sql_text", "query");
            if (string.IsNullOrWhiteSpace(sqlText)) continue;

            var timestamp = JsonHelpers.GetTimestamp(record, "timestamp", "ts", "time", "event_time")
                            ?? JsonHelpers.GetTimestamp(data, "timestamp", "ts");
            if (timestamp is null)
            {
                result.Warn(line, "记录缺少可解析的 timestamp，已跳过");
                continue;
            }

            var account = ResolveAccount(record);
            var ev = new AuditEvent
            {
                Source = AuditSource.MySqlAuditJson,
                Timestamp = timestamp.Value,
                Account = account.User,
                ClientHost = account.Host,
                Database = JsonHelpers.GetString(data, "db", "database", "dbname")
                           ?? JsonHelpers.GetString(record, "db", "database") ?? "",
                CommandTag = JsonHelpers.GetString(data, "command", "event", "cmd") ?? cls,
                SessionId = JsonHelpers.GetString(record, "connection_id", "connectionId", "session_id"),
                Statement = AuditLimits.Clamp(sqlText, AuditLimits.MaxStatementChars),
                ServerHost = JsonHelpers.GetString(record, "server_id", "server", "hostname"),
                SourceFile = sourceFile,
                SourceLine = line,
                RawRecord = AuditLimits.Clamp(raw, AuditLimits.MaxRawChars),
            };

            ev.RowsReturned = JsonHelpers.GetLong(data, "rows_sent", "rows_returned", "rows", "found_rows");
            ev.RowsAffected = JsonHelpers.GetLong(data, "rows_affected", "affected_rows");
            // query_time 单位为微秒；若记录直接给 duration_ms 则按毫秒
            var micros = JsonHelpers.GetDouble(data, "query_time", "query_time_us");
            if (micros is not null) ev.DurationMs = micros.Value / 1000.0;
            else ev.DurationMs = JsonHelpers.GetDouble(data, "duration_ms", "query_time_ms", "elapsed_ms");

            var status = JsonHelpers.GetLong(data, "status");
            ev.Succeeded = status is null or 0;
            ev.ErrorCode = JsonHelpers.GetString(data, "error_code", "errno", "mysql_errno");

            result.Events.Add(ev);
        }

        return result;
    }

    private static (string User, string Host) ResolveAccount(JsonElement record)
    {
        // 优先 account / login 对象
        foreach (var name in new[] { "account", "login" })
        {
            if (!JsonHelpers.TryGet(record, name, out var obj) || obj.ValueKind != JsonValueKind.Object)
                continue;
            var user = JsonHelpers.GetString(obj, "user", "user_name") ?? "";
            var host = JsonHelpers.GetString(obj, "host", "ip", "client_host") ?? "";
            if (user.Length > 0) return (user, host);
        }

        var flatUser = JsonHelpers.GetString(record, "user", "user_name", "account_user") ?? "";
        var flatHost = JsonHelpers.GetString(record, "host", "client_host", "ip", "remote_host") ?? "";
        return (flatUser, flatHost);
    }
}
