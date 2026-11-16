using System.Text.Json;
using Microsoft.Data.Sqlite;
using SqlAudit.Core.Analysis;
using SqlAudit.Core.Model;

namespace SqlAudit.Web.Storage;

/// <summary>
/// SQLite 仓储。选 SQLite 而非内存结构的原因：
///  * 审计数据量可达数十万行，重启后不应丢失；
///  * 部署只需一个文件，DBA 环境无需额外数据库；
///  * 单机分析平台并发低，WAL 模式足够。
/// findings 以 JSON 数组存一列（规则结果结构随规则演进，不适合逐列固化）。
/// </summary>
public sealed class SqliteAuditRepository : IAuditRepository
{
    private readonly string _connectionString;

    public SqliteAuditRepository(string databasePath)
    {
        var directory = Path.GetDirectoryName(Path.GetFullPath(databasePath));
        if (!string.IsNullOrEmpty(directory)) Directory.CreateDirectory(directory);
        _connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = databasePath,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Cache = SqliteCacheMode.Shared,
        }.ToString();
    }

    public IReadOnlyList<RuleDefinition> Rules => RuleCatalog.All;

    public async Task InitializeAsync(CancellationToken ct = default)
    {
        await using var conn = await OpenAsync(ct);
        var sql = """
            PRAGMA journal_mode = WAL;
            PRAGMA foreign_keys = ON;

            CREATE TABLE IF NOT EXISTS batches (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_name TEXT NOT NULL,
                file_size INTEGER NOT NULL,
                source INTEGER NOT NULL,
                auto_detected INTEGER NOT NULL,
                imported_at TEXT NOT NULL,
                event_count INTEGER NOT NULL,
                alert_count INTEGER NOT NULL,
                diagnostic_count INTEGER NOT NULL,
                note TEXT NULL
            );

            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                batch_id INTEGER NOT NULL REFERENCES batches(id) ON DELETE CASCADE,
                source INTEGER NOT NULL,
                ts TEXT NOT NULL,
                ts_unix INTEGER NOT NULL,
                account TEXT NOT NULL,
                db TEXT NOT NULL,
                client_host TEXT NULL,
                server_host TEXT NULL,
                command_tag TEXT NULL,
                session_id TEXT NULL,
                statement TEXT NOT NULL,
                statement_hash TEXT NOT NULL,
                rows_returned INTEGER NULL,
                rows_affected INTEGER NULL,
                duration_ms REAL NULL,
                succeeded INTEGER NOT NULL,
                error_code TEXT NULL,
                source_file TEXT NULL,
                source_line INTEGER NOT NULL,
                raw_record TEXT NULL,
                risk_score INTEGER NOT NULL,
                max_severity INTEGER NOT NULL,
                rule_ids TEXT NOT NULL,
                categories TEXT NOT NULL,
                findings_json TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS ix_events_ts ON events(ts_unix);
            CREATE INDEX IF NOT EXISTS ix_events_account ON events(account);
            CREATE INDEX IF NOT EXISTS ix_events_db ON events(db);
            CREATE INDEX IF NOT EXISTS ix_events_score ON events(risk_score DESC);
            CREATE INDEX IF NOT EXISTS ix_events_batch ON events(batch_id);
            """;

        await using var cmd = conn.CreateCommand();
        cmd.CommandText = sql;
        await cmd.ExecuteNonQueryAsync(ct);
    }

    public async Task<long> AddBatchAsync(
        ImportBatch batch, IReadOnlyList<AnalyzedEvent> events, CancellationToken ct = default)
    {
        await using var conn = await OpenAsync(ct);
        await using var tx = (SqliteTransaction)await conn.BeginTransactionAsync(ct);

        long batchId;
        await using (var insertBatch = conn.CreateCommand())
        {
            insertBatch.Transaction = tx;
            insertBatch.CommandText = """
                INSERT INTO batches (file_name, file_size, source, auto_detected, imported_at,
                                     event_count, alert_count, diagnostic_count, note)
                VALUES ($file, $size, $source, $auto, $imported, $events, $alerts, $diag, $note);
                SELECT last_insert_rowid();
                """;
            insertBatch.Parameters.AddWithValue("$file", batch.FileName);
            insertBatch.Parameters.AddWithValue("$size", batch.FileSize);
            insertBatch.Parameters.AddWithValue("$source", (int)batch.Source);
            insertBatch.Parameters.AddWithValue("$auto", batch.SourceWasAutoDetected ? 1 : 0);
            insertBatch.Parameters.AddWithValue("$imported", batch.ImportedAt.UtcDateTime.ToString("O"));
            insertBatch.Parameters.AddWithValue("$events", batch.EventCount);
            insertBatch.Parameters.AddWithValue("$alerts", batch.AlertCount);
            insertBatch.Parameters.AddWithValue("$diag", batch.DiagnosticCount);
            insertBatch.Parameters.AddWithValue("$note", (object?)batch.Note ?? DBNull.Value);
            batchId = (long)(await insertBatch.ExecuteScalarAsync(ct))!;
        }

        await using var insertEvent = conn.CreateCommand();
        insertEvent.Transaction = tx;
        insertEvent.CommandText = """
            INSERT INTO events (batch_id, source, ts, ts_unix, account, db, client_host, server_host,
                                command_tag, session_id, statement, statement_hash, rows_returned,
                                rows_affected, duration_ms, succeeded, error_code, source_file,
                                source_line, raw_record, risk_score, max_severity, rule_ids,
                                categories, findings_json)
            VALUES ($batch, $source, $ts, $tsUnix, $account, $db, $client, $server,
                    $command, $session, $statement, $hash, $rows, $affected, $duration,
                    $succeeded, $error, $file, $line, $raw, $score, $severity, $rules,
                    $categories, $findings);
            """;

        var p = insertEvent.Parameters;
        var pBatch = p.Add("$batch", SqliteType.Integer);
        var pSource = p.Add("$source", SqliteType.Integer);
        var pTs = p.Add("$ts", SqliteType.Text);
        var pTsUnix = p.Add("$tsUnix", SqliteType.Integer);
        var pAccount = p.Add("$account", SqliteType.Text);
        var pDb = p.Add("$db", SqliteType.Text);
        var pClient = p.Add("$client", SqliteType.Text);
        var pServer = p.Add("$server", SqliteType.Text);
        var pCommand = p.Add("$command", SqliteType.Text);
        var pSession = p.Add("$session", SqliteType.Text);
        var pStatement = p.Add("$statement", SqliteType.Text);
        var pHash = p.Add("$hash", SqliteType.Text);
        var pRows = p.Add("$rows", SqliteType.Integer);
        var pAffected = p.Add("$affected", SqliteType.Integer);
        var pDuration = p.Add("$duration", SqliteType.Real);
        var pSucceeded = p.Add("$succeeded", SqliteType.Integer);
        var pError = p.Add("$error", SqliteType.Text);
        var pFile = p.Add("$file", SqliteType.Text);
        var pLine = p.Add("$line", SqliteType.Integer);
        var pRaw = p.Add("$raw", SqliteType.Text);
        var pScore = p.Add("$score", SqliteType.Integer);
        var pSeverity = p.Add("$severity", SqliteType.Integer);
        var pRules = p.Add("$rules", SqliteType.Text);
        var pCategories = p.Add("$categories", SqliteType.Text);
        var pFindings = p.Add("$findings", SqliteType.Text);

        foreach (var item in events)
        {
            var ev = item.Event;
            pBatch.Value = batchId;
            pSource.Value = (int)ev.Source;
            pTs.Value = ev.Timestamp.UtcDateTime.ToString("O");
            pTsUnix.Value = ev.Timestamp.ToUnixTimeSeconds();
            pAccount.Value = ev.Account;
            pDb.Value = ev.Database;
            pClient.Value = (object?)ev.ClientHost ?? DBNull.Value;
            pServer.Value = (object?)ev.ServerHost ?? DBNull.Value;
            pCommand.Value = (object?)ev.CommandTag ?? DBNull.Value;
            pSession.Value = (object?)ev.SessionId ?? DBNull.Value;
            pStatement.Value = ev.Statement;
            pHash.Value = ev.StatementHash;
            pRows.Value = (object?)ev.RowsReturned ?? DBNull.Value;
            pAffected.Value = (object?)ev.RowsAffected ?? DBNull.Value;
            pDuration.Value = (object?)ev.DurationMs ?? DBNull.Value;
            pSucceeded.Value = ev.Succeeded ? 1 : 0;
            pError.Value = (object?)ev.ErrorCode ?? DBNull.Value;
            pFile.Value = (object?)ev.SourceFile ?? DBNull.Value;
            pLine.Value = ev.SourceLine;
            pRaw.Value = (object?)ev.RawRecord ?? DBNull.Value;
            pScore.Value = item.RiskScore;
            pSeverity.Value = (int)item.MaxSeverity;
            pRules.Value = string.Join(",", item.RuleIds);
            pCategories.Value = string.Join("|", item.Categories);
            pFindings.Value = JsonSerializer.Serialize(item.Findings, FindingJson.Options);

            await insertEvent.ExecuteNonQueryAsync(ct);
        }

        await tx.CommitAsync(ct);
        return batchId;
    }

    public async Task<IReadOnlyList<ImportBatch>> ListBatchesAsync(CancellationToken ct = default)
    {
        await using var conn = await OpenAsync(ct);
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            SELECT id, file_name, file_size, source, auto_detected, imported_at,
                   event_count, alert_count, diagnostic_count, note
            FROM batches ORDER BY id DESC
            """;

        var list = new List<ImportBatch>();
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            list.Add(new ImportBatch
            {
                Id = reader.GetInt64(0),
                FileName = reader.GetString(1),
                FileSize = reader.GetInt64(2),
                Source = (AuditSource)reader.GetInt32(3),
                SourceWasAutoDetected = reader.GetInt32(4) != 0,
                ImportedAt = DateTimeOffset.Parse(reader.GetString(5)),
                EventCount = reader.GetInt32(6),
                AlertCount = reader.GetInt32(7),
                DiagnosticCount = reader.GetInt32(8),
                Note = reader.IsDBNull(9) ? null : reader.GetString(9),
            });
        }
        return list;
    }

    public async Task<bool> DeleteBatchAsync(long batchId, CancellationToken ct = default)
    {
        await using var conn = await OpenAsync(ct);
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = "DELETE FROM batches WHERE id = $id";
        cmd.Parameters.AddWithValue("$id", batchId);
        return await cmd.ExecuteNonQueryAsync(ct) > 0;
    }

    public async Task<PageResult<AnalyzedEvent>> QueryEventsAsync(EventQuery query, CancellationToken ct = default)
    {
        await using var conn = await OpenAsync(ct);

        var (where, parameters) = BuildWhere(query);

        await using var countCmd = conn.CreateCommand();
        countCmd.CommandText = $"SELECT COUNT(*) FROM events e {where}";
        foreach (var (k, v) in parameters) countCmd.Parameters.AddWithValue(k, v);
        var total = Convert.ToInt32(await countCmd.ExecuteScalarAsync(ct));

        await using var cmd = conn.CreateCommand();
        cmd.CommandText = $"""
            SELECT e.id, e.batch_id, e.source, e.ts, e.account, e.db, e.client_host, e.server_host,
                   e.command_tag, e.session_id, e.statement, e.statement_hash, e.rows_returned,
                   e.rows_affected, e.duration_ms, e.succeeded, e.error_code, e.source_file,
                   e.source_line, e.raw_record, e.risk_score, e.max_severity, e.rule_ids,
                   e.categories, e.findings_json
            FROM events e
            {where}
            ORDER BY e.risk_score DESC, e.ts_unix DESC, e.id DESC
            LIMIT $limit OFFSET $offset
            """;
        foreach (var (k, v) in parameters) cmd.Parameters.AddWithValue(k, v);
        cmd.Parameters.AddWithValue("$limit", Math.Clamp(query.Limit, 1, 500));
        cmd.Parameters.AddWithValue("$offset", Math.Max(0, query.Offset));

        var items = new List<AnalyzedEvent>();
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            items.Add(ReadEvent(reader));
        }

        return new PageResult<AnalyzedEvent>(items, total,
            Math.Clamp(query.Limit, 1, 500), Math.Max(0, query.Offset));
    }

    public async Task<AnalyzedEvent?> GetEventAsync(long id, CancellationToken ct = default)
    {
        await using var conn = await OpenAsync(ct);
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            SELECT e.id, e.batch_id, e.source, e.ts, e.account, e.db, e.client_host, e.server_host,
                   e.command_tag, e.session_id, e.statement, e.statement_hash, e.rows_returned,
                   e.rows_affected, e.duration_ms, e.succeeded, e.error_code, e.source_file,
                   e.source_line, e.raw_record, e.risk_score, e.max_severity, e.rule_ids,
                   e.categories, e.findings_json
            FROM events e WHERE e.id = $id
            """;
        cmd.Parameters.AddWithValue("$id", id);
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        return await reader.ReadAsync(ct) ? ReadEvent(reader) : null;
    }

    public async Task<OverviewStats> GetOverviewAsync(CancellationToken ct = default)
    {
        await using var conn = await OpenAsync(ct);

        int Scalar(string sql)
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = sql;
            var value = cmd.ExecuteScalar();
            return value is null or DBNull ? 0 : Convert.ToInt32(value);
        }

        var total = Scalar("SELECT COUNT(*) FROM events");
        var alerted = Scalar("SELECT COUNT(*) FROM events WHERE risk_score > 0");
        var critical = Scalar($"SELECT COUNT(*) FROM events WHERE max_severity >= {(int)Severity.Critical}");

        var accounts = await ReadFacetsAsync(conn,
            "SELECT account, COUNT(*) FROM events GROUP BY account ORDER BY COUNT(*) DESC", ct);
        var databases = await ReadFacetsAsync(conn,
            "SELECT db, COUNT(*) FROM events WHERE db <> '' GROUP BY db ORDER BY COUNT(*) DESC", ct);
        var sources = await ReadFacetsAsync(conn,
            "SELECT source, COUNT(*) FROM events GROUP BY source ORDER BY COUNT(*) DESC", ct);

        var sourceLabels = sources
            .Select(s => new FacetCount(
                AuditSourceExtensions.ToLabel((AuditSource)int.Parse(s.Value)), s.Count))
            .ToList();

        // 规则命中统计：rule_ids 为逗号拼接，用 instr 精确匹配
        var ruleHits = new List<RuleCount>();
        foreach (var rule in RuleCatalog.All)
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "SELECT COUNT(*) FROM events WHERE instr(',' || rule_ids || ',', $pat) > 0";
            cmd.Parameters.AddWithValue("$pat", $",{rule.Id},");
            var count = Convert.ToInt32(await cmd.ExecuteScalarAsync(ct));
            if (count > 0) ruleHits.Add(new RuleCount(rule.Id, rule.NameZh, count));
        }

        var timeline = new List<DayCount>();
        await using (var cmd = conn.CreateCommand())
        {
            // 按小时聚合：审计数据通常跨度数天，按天粒度柱子太少看不出异常时段
            cmd.CommandText = """
                SELECT strftime('%Y-%m-%dT%H:00', ts_unix, 'unixepoch') AS bucket,
                       COUNT(*) AS total,
                       SUM(CASE WHEN risk_score > 0 THEN 1 ELSE 0 END) AS alerts
                FROM events GROUP BY bucket ORDER BY bucket
                """;
            await using var reader = await cmd.ExecuteReaderAsync(ct);
            while (await reader.ReadAsync(ct))
            {
                timeline.Add(new DayCount(reader.GetString(0), reader.GetInt32(1), reader.GetInt32(2)));
            }
        }

        var accountDatabases = new List<AccountDatabase>();
        await using (var cmd = conn.CreateCommand())
        {
            cmd.CommandText = """
                SELECT account, db, COUNT(*) FROM events
                GROUP BY account, db ORDER BY COUNT(*) DESC LIMIT 200
                """;
            await using var reader = await cmd.ExecuteReaderAsync(ct);
            while (await reader.ReadAsync(ct))
            {
                accountDatabases.Add(new AccountDatabase(
                    reader.GetString(0), reader.GetString(1), reader.GetInt32(2)));
            }
        }

        DateTimeOffset? earliest = null, latest = null;
        await using (var cmd = conn.CreateCommand())
        {
            cmd.CommandText = "SELECT MIN(ts), MAX(ts) FROM events";
            await using var reader = await cmd.ExecuteReaderAsync(ct);
            if (await reader.ReadAsync(ct) && !reader.IsDBNull(0))
            {
                earliest = DateTimeOffset.Parse(reader.GetString(0));
                latest = DateTimeOffset.Parse(reader.GetString(1));
            }
        }

        return new OverviewStats
        {
            TotalEvents = total,
            AlertedEvents = alerted,
            CriticalEvents = critical,
            Accounts = accounts,
            Databases = databases,
            Sources = sourceLabels,
            RuleHits = ruleHits.OrderByDescending(r => r.Count).ToList(),
            Timeline = timeline,
            AccountDatabases = accountDatabases,
            Earliest = earliest,
            Latest = latest,
        };
    }

    public async Task<IReadOnlyList<SessionChain>> GetChainsAsync(CancellationToken ct = default)
    {
        // 会话链需要全量事件参与计算，但只需带回告警事件
        var query = new EventQuery { AlertsOnly = true, Limit = 500 };
        var page = await QueryEventsAsync(query, ct);
        if (page.Total > page.Items.Count)
        {
            // 告警事件超过单页上限时按批读取
            var all = new List<AnalyzedEvent>(page.Items);
            for (var offset = 500; offset < page.Total; offset += 500)
            {
                var next = await QueryEventsAsync(new EventQuery { AlertsOnly = true, Limit = 500, Offset = offset }, ct);
                all.AddRange(next.Items);
            }
            return SessionCorrelator.Correlate(all);
        }

        return SessionCorrelator.Correlate(page.Items);
    }

    private static async Task<List<FacetCount>> ReadFacetsAsync(
        SqliteConnection conn, string sql, CancellationToken ct)
    {
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = sql;
        var list = new List<FacetCount>();
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            list.Add(new FacetCount(reader.GetString(0), reader.GetInt32(1)));
        }
        return list;
    }

    private static (string Where, List<(string, object)> Parameters) BuildWhere(EventQuery q)
    {
        var clauses = new List<string>();
        var parameters = new List<(string, object)>();

        if (!string.IsNullOrWhiteSpace(q.Account))
        {
            clauses.Add("e.account = $account");
            parameters.Add(("$account", q.Account));
        }
        if (!string.IsNullOrWhiteSpace(q.Database))
        {
            clauses.Add("e.db = $db");
            parameters.Add(("$db", q.Database));
        }
        if (q.From is { } from)
        {
            clauses.Add("e.ts_unix >= $from");
            parameters.Add(("$from", from.ToUnixTimeSeconds()));
        }
        if (q.To is { } to)
        {
            clauses.Add("e.ts_unix <= $to");
            parameters.Add(("$to", to.ToUnixTimeSeconds()));
        }
        if (q.AlertsOnly)
        {
            clauses.Add("e.risk_score > 0");
        }
        if (q.MinSeverity is { } minSeverity)
        {
            clauses.Add("e.max_severity >= $minSeverity");
            parameters.Add(("$minSeverity", (int)minSeverity));
        }
        if (q.Source is { } source)
        {
            clauses.Add("e.source = $source");
            parameters.Add(("$source", (int)source));
        }
        if (q.BatchId is { } batchId)
        {
            clauses.Add("e.batch_id = $batch");
            parameters.Add(("$batch", batchId));
        }
        if (!string.IsNullOrWhiteSpace(q.Text))
        {
            clauses.Add("(e.statement LIKE $text OR e.account LIKE $text OR e.client_host LIKE $text)");
            parameters.Add(("$text", $"%{q.Text.Trim()}%"));
        }
        if (q.RuleIds is { Count: > 0 })
        {
            // rule_ids 为 ",R-001,R-002," 形式，组合成 OR 精确匹配
            var ors = new List<string>();
            for (var i = 0; i < q.RuleIds.Count; i++)
            {
                ors.Add($"instr(',' || e.rule_ids || ',', $rule{i}) > 0");
                parameters.Add(($"$rule{i}", $",{q.RuleIds[i]},"));
            }
            clauses.Add("(" + string.Join(" OR ", ors) + ")");
        }

        var where = clauses.Count == 0 ? "" : "WHERE " + string.Join(" AND ", clauses);
        return (where, parameters);
    }

    private static AnalyzedEvent ReadEvent(SqliteDataReader reader)
    {
        var ev = new AuditEvent
        {
            Id = reader.GetInt64(0),
            Source = (AuditSource)reader.GetInt32(2),
            Timestamp = DateTimeOffset.Parse(reader.GetString(3)),
            Account = reader.GetString(4),
            Database = reader.GetString(5),
            ClientHost = reader.IsDBNull(6) ? null : reader.GetString(6),
            ServerHost = reader.IsDBNull(7) ? null : reader.GetString(7),
            CommandTag = reader.IsDBNull(8) ? null : reader.GetString(8),
            SessionId = reader.IsDBNull(9) ? null : reader.GetString(9),
            Statement = reader.GetString(10),
            StatementHash = reader.GetString(11),
            RowsReturned = reader.IsDBNull(12) ? null : reader.GetInt64(12),
            RowsAffected = reader.IsDBNull(13) ? null : reader.GetInt64(13),
            DurationMs = reader.IsDBNull(14) ? null : reader.GetDouble(14),
            Succeeded = reader.GetInt32(15) != 0,
            ErrorCode = reader.IsDBNull(16) ? null : reader.GetString(16),
            SourceFile = reader.IsDBNull(17) ? null : reader.GetString(17),
            SourceLine = reader.GetInt32(18),
            RawRecord = reader.IsDBNull(19) ? null : reader.GetString(19),
        };

        var findings = JsonSerializer.Deserialize<List<Finding>>(reader.GetString(24), FindingJson.Options)
                       ?? new List<Finding>();

        return new AnalyzedEvent
        {
            Event = ev,
            Findings = findings,
            RiskScore = reader.GetInt32(20),
            MaxSeverity = (Severity)reader.GetInt32(21),
            RuleIds = reader.GetString(22).Length == 0
                ? Array.Empty<string>()
                : reader.GetString(22).Split(',', StringSplitOptions.RemoveEmptyEntries),
            Categories = reader.GetString(23).Length == 0
                ? Array.Empty<string>()
                : reader.GetString(23).Split('|', StringSplitOptions.RemoveEmptyEntries),
        };
    }

    private async Task<SqliteConnection> OpenAsync(CancellationToken ct)
    {
        var conn = new SqliteConnection(_connectionString);
        await conn.OpenAsync(ct);
        return conn;
    }
}

internal static class FindingJson
{
    public static readonly JsonSerializerOptions Options = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull,
    };
}
