using SqlAudit.Core.Model;

namespace SqlAudit.SampleGen;

/// <summary>
/// 构造模拟审计数据集：大量正常业务流量 + 若干埋点攻击场景。
/// 正常流量刻意包含“报表账号的大批量导出”与“AND 1=1 占位条件”，
/// 用来验证检测规则不会把这些误报为注入。
/// </summary>
public static class DatasetBuilder
{
    private static readonly DateTimeOffset Base = new(2026, 11, 12, 0, 0, 0, TimeSpan.Zero);

    public static SampleDataset BuildMySqlAudit() => BuildMySqlCore();

    private static SampleDataset BuildMySqlCore()
    {
        var rng = new Random(20261112);
        var events = new List<SampleEvent>();
        var expected = new Dictionary<string, string[]>(StringComparer.Ordinal);

        // ---------- 正常业务基线（约 3 天）----------
        var accounts = new[]
        {
            ("app_reader", "app", "10.20.3.41"),
            ("app_writer", "app", "10.20.3.42"),
            ("report_bot", "analytics", "10.20.7.15"),
            ("svc_sync", "billing", "10.20.4.9"),
        };

        for (var day = 0; day < 3; day++)
        {
            for (var hour = 0; hour < 24; hour++)
            {
                // 白天流量密集，夜间稀疏
                var density = hour is >= 8 and <= 20 ? 14 : 3;
                for (var k = 0; k < density; k++)
                {
                    var (account, db, host) = accounts[rng.Next(accounts.Length)];
                    var ts = Base.AddDays(day).AddHours(hour)
                        .AddMinutes(rng.Next(60)).AddSeconds(rng.Next(60));
                    var session = (100000 + day * 5000 + hour * 40 + k).ToString();
                    events.Add(MakeNormal(account, db, host, session, ts, rng));

                    // 报表账号的例行导出：真正的大批量，但每天固定，属基线内
                    if (account == "report_bot" && hour is 2 or 14 && k == 0)
                    {
                        events.Add(new SampleEvent
                        {
                            Timestamp = ts.AddSeconds(5),
                            Account = "report_bot",
                            Database = "analytics",
                            ClientHost = host,
                            SessionId = session,
                            Statement =
                                "SELECT d.date_key, d.channel, SUM(f.amount) AS total, COUNT(*) AS cnt "
                                + "FROM dw.fact_orders f JOIN dw.dim_date d ON d.id = f.date_id "
                                + "WHERE d.date_key BETWEEN '2026-10-01' AND '2026-10-31' "
                                + "GROUP BY d.date_key, d.channel ORDER BY d.date_key",
                            RowsReturned = 86_000 + rng.Next(20_000),
                            DurationMs = 1_800 + rng.Next(900),
                        });
                    }
                }
            }
        }

        // 正常业务里常见的 AND 1=1 动态拼接（应只报低危/提示，不算攻击）
        events.Add(new SampleEvent
        {
            Timestamp = Base.AddHours(10).AddMinutes(3),
            Account = "app_writer",
            Database = "app",
            ClientHost = "10.20.3.42",
            SessionId = "102310",
            Statement = "SELECT id, status FROM app.orders WHERE 1 = 1 AND status = 'PAID' AND created_at >= '2026-11-01'",
            RowsReturned = 340,
            DurationMs = 12,
            Label = "normal-and-one-equals-one",
        });
        expected["normal-and-one-equals-one"] = [];

        // 正常的多表 UNION（报表合并，不应告警）
        events.Add(new SampleEvent
        {
            Timestamp = Base.AddHours(11).AddMinutes(20),
            Account = "report_bot",
            Database = "analytics",
            ClientHost = "10.20.7.15",
            SessionId = "104420",
            Statement =
                "SELECT channel AS source, SUM(amount) AS total FROM dw.sales_channel_a GROUP BY channel "
                + "UNION ALL SELECT channel, SUM(amount) FROM dw.sales_channel_b GROUP BY channel",
            RowsReturned = 26,
            DurationMs = 640,
            Label = "normal-union-all",
        });
        expected["normal-union-all"] = [];

        // 正常访问业务表 users（不含系统字典，不应告警）
        events.Add(new SampleEvent
        {
            Timestamp = Base.AddHours(9).AddMinutes(41),
            Account = "app_reader",
            Database = "app",
            ClientHost = "10.20.3.41",
            SessionId = "101341",
            Statement = "SELECT id, email, display_name FROM app.users WHERE id = ?",
            RowsReturned = 1,
            DurationMs = 2,
            Label = "normal-users-select",
        });
        expected["normal-users-select"] = [];

        // ---------- 埋点 1：外部 IP 的 SQL 注入 ----------
        var attackerHost = "45.77.13.88";
        var attackerSession = "904211";

        var inj1 = new SampleEvent
        {
            Timestamp = Base.AddDays(2).AddHours(3).AddMinutes(14).AddSeconds(22),
            Account = "app_reader",
            Database = "app",
            ClientHost = attackerHost,
            SessionId = attackerSession,
            Statement = "SELECT id, email FROM app.users WHERE email = 'x' OR 1=1 -- ' AND status = 'ACTIVE'",
            RowsReturned = 18_442,
            DurationMs = 96,
            Label = "inject-tautology",
        };
        events.Add(inj1);
        expected["inject-tautology"] = [RuleCatalog.Tautology];

        var inj2 = new SampleEvent
        {
            Timestamp = inj1.Timestamp.AddSeconds(41),
            Account = "app_reader",
            Database = "app",
            ClientHost = attackerHost,
            SessionId = attackerSession,
            Statement =
                "SELECT id, email FROM app.users WHERE id = 1 UNION SELECT NULL, NULL, NULL, NULL, NULL -- ",
            RowsReturned = 5,
            DurationMs = 31,
            Label = "inject-union-nulls",
        };
        events.Add(inj2);
        expected["inject-union-nulls"] = [RuleCatalog.UnionInjection];

        var inj3 = new SampleEvent
        {
            Timestamp = inj2.Timestamp.AddSeconds(18),
            Account = "app_reader",
            Database = "app",
            ClientHost = attackerHost,
            SessionId = attackerSession,
            Statement =
                "SELECT id, email FROM app.users WHERE id = 1 UNION SELECT table_name, column_name FROM information_schema.columns -- ",
            RowsReturned = 3_812,
            DurationMs = 74,
            Label = "inject-union-dict",
        };
        events.Add(inj3);
        expected["inject-union-dict"] = [RuleCatalog.UnionInjection];

        var inj4 = new SampleEvent
        {
            Timestamp = inj3.Timestamp.AddSeconds(9),
            Account = "app_reader",
            Database = "app",
            ClientHost = attackerHost,
            SessionId = attackerSession,
            Statement =
                "SELECT id FROM app.users WHERE id = 1 AND (SELECT 1 FROM (SELECT SLEEP(5)) x) = 1",
            RowsReturned = 0,
            DurationMs = 5_021,
            Label = "inject-sleep",
        };
        events.Add(inj4);
        expected["inject-sleep"] = [RuleCatalog.TimeBasedBlind];

        var inj5 = new SampleEvent
        {
            Timestamp = inj4.Timestamp.AddSeconds(26),
            Account = "app_reader",
            Database = "app",
            ClientHost = attackerHost,
            SessionId = attackerSession,
            Statement =
                "SELECT /*!50000 id, email FROM app.users WHERE 1=1 AND */ password_hash FROM mysql.user",
            RowsReturned = 2,
            DurationMs = 12,
            Label = "inject-exec-comment",
        };
        events.Add(inj5);
        expected["inject-exec-comment"] = [RuleCatalog.ExecutableComment, RuleCatalog.CredentialStoreAccess];

        var inj6 = new SampleEvent
        {
            Timestamp = inj5.Timestamp.AddSeconds(7),
            Account = "app_reader",
            Database = "app",
            ClientHost = attackerHost,
            SessionId = attackerSession,
            Statement =
                "SELECT id FROM app.users WHERE id = 1; DROP TABLE app.audit_probe; -- ",
            RowsReturned = 0,
            DurationMs = 44,
            Succeeded = false,
            ErrorCode = "1142",
            Label = "inject-stacked",
        };
        events.Add(inj6);
        expected["inject-stacked"] = [RuleCatalog.StackedQuery];

        // 埋点 2：账号 app_reader 突然无 WHERE 全量导出
        var exfil = new SampleEvent
        {
            Timestamp = Base.AddDays(2).AddHours(3).AddMinutes(31),
            Account = "app_reader",
            Database = "billing",
            ClientHost = attackerHost,
            SessionId = attackerSession,
            Statement = "SELECT * FROM billing.invoices",
            RowsReturned = 412_880,
            DurationMs = 8_940,
            Label = "exfil-select-star",
        };
        events.Add(exfil);
        expected["exfil-select-star"] = [RuleCatalog.LargeResultSet];

        // 埋点 3：凭据表读取（另一来源，来自内网跳板）
        var cred = new SampleEvent
        {
            Timestamp = Base.AddDays(2).AddHours(4).AddMinutes(2),
            Account = "svc_sync",
            Database = "billing",
            ClientHost = "10.20.4.9",
            SessionId = "880311",
            Statement = "SELECT user, host, authentication_string FROM mysql.user WHERE super_priv = 'Y'",
            RowsReturned = 6,
            DurationMs = 8,
            Label = "cred-mysql-user",
        };
        events.Add(cred);
        expected["cred-mysql-user"] = [RuleCatalog.CredentialStoreAccess];

        // 埋点 4：越权提权
        var grant = new SampleEvent
        {
            Timestamp = Base.AddDays(2).AddHours(4).AddMinutes(5),
            Account = "svc_sync",
            Database = "billing",
            ClientHost = "10.20.4.9",
            SessionId = "880311",
            Statement = "GRANT ALL PRIVILEGES ON *.* TO 'svc_sync'@'%' WITH GRANT OPTION",
            RowsAffected = 0,
            DurationMs = 15,
            Label = "grant-all",
        };
        events.Add(grant);
        expected["grant-all"] = [RuleCatalog.PrivilegeChange];

        // 埋点 5：批量落盘
        var outfile = new SampleEvent
        {
            Timestamp = Base.AddDays(2).AddHours(4).AddMinutes(9),
            Account = "svc_sync",
            Database = "billing",
            ClientHost = "10.20.4.9",
            SessionId = "880311",
            Statement =
                "SELECT * FROM billing.payments INTO OUTFILE '/tmp/payments_dump.csv'",
            RowsAffected = 240_118,
            DurationMs = 3_400,
            Label = "outfile-dump",
        };
        events.Add(outfile);
        expected["outfile-dump"] = [RuleCatalog.BulkExport];

        events.Sort((a, b) => a.Timestamp.CompareTo(b.Timestamp));

        return new SampleDataset
        {
            Name = "mysql-audit",
            Events = events,
            ExpectedFindings = expected,
        };
    }

    /// <summary>一批正常业务语句。</summary>
    private static SampleEvent MakeNormal(
        string account, string db, string host, string session, DateTimeOffset ts, Random rng)
    {
        var templates = db switch
        {
            "app" => new (string Sql, long Rows)[]
            {
                ("SELECT id, sku, qty FROM app.cart_items WHERE cart_id = ?", 1),
                ("SELECT id, status FROM app.orders WHERE user_id = ? ORDER BY created_at DESC LIMIT 20", 20),
                ("UPDATE app.cart_items SET qty = ? WHERE id = ?", 0),
                ("INSERT INTO app.order_events (order_id, event_type, created_at) VALUES (?, ?, NOW())", 0),
                ("SELECT COUNT(*) FROM app.orders WHERE created_at >= CURDATE()", 1),
                ("SELECT p.id, p.name, p.price FROM app.products p WHERE p.category_id = ? LIMIT 50", 50),
            },
            "billing" => new (string, long)[]
            {
                ("SELECT id, amount, currency FROM billing.invoices WHERE id = ?", 1),
                ("SELECT id FROM billing.payments WHERE invoice_id = ? ORDER BY paid_at DESC LIMIT 10", 10),
                ("UPDATE billing.invoices SET status = ? WHERE id = ?", 0),
                ("SELECT SUM(amount) FROM billing.payments WHERE created_at >= ? AND created_at < ?", 1),
            },
            _ => new (string, long)[]
            {
                ("SELECT id, value FROM analytics.metrics_daily WHERE metric_key = ? AND day = ?", 1),
                ("INSERT INTO analytics.events_raw (event, payload, ts) VALUES (?, ?, ?)", 0),
                ("SELECT DISTINCT segment FROM analytics.audience WHERE campaign_id = ?", 12),
                ("SELECT id, name FROM analytics.dashboards WHERE owner_id = ?", 4),
            },
        };

        var (sql, rows) = templates[rng.Next(templates.Length)];
        var duration = rng.NextDouble() * 40 + 0.5;
        var failed = rng.Next(100) < 2;
        return new SampleEvent
        {
            Timestamp = ts,
            Account = account,
            Database = db,
            ClientHost = host,
            SessionId = session,
            Statement = sql,
            RowsReturned = sql.StartsWith("SELECT", StringComparison.Ordinal) ? rows : null,
            RowsAffected = sql.StartsWith("SELECT", StringComparison.Ordinal) ? null : rows,
            DurationMs = Math.Round(duration, 2),
            Succeeded = !failed,
            ErrorCode = failed ? "1213" : null,
        };
    }

    // ================= PostgreSQL =================

    public static SampleDataset BuildPostgreSql()
    {
        var rng = new Random(20261113);
        var events = new List<SampleEvent>();
        var expected = new Dictionary<string, string[]>(StringComparer.Ordinal);

        var accounts = new[]
        {
            ("pg_app", "core", "10.30.2.21"),
            ("pg_app", "core", "10.30.2.22"),
            ("pg_report", "dw", "10.30.7.8"),
            ("pg_sync", "core", "10.30.4.30"),
        };

        for (var day = 0; day < 3; day++)
        {
            for (var hour = 0; hour < 24; hour++)
            {
                var density = hour is >= 8 and <= 20 ? 11 : 2;
                for (var k = 0; k < density; k++)
                {
                    var (account, db, host) = accounts[rng.Next(accounts.Length)];
                    var ts = Base.AddDays(day).AddHours(hour).AddMinutes(rng.Next(60)).AddSeconds(rng.Next(60));
                    var session = $"66{rng.Next(10000, 99999)}";
                    var isRead = rng.Next(3) != 0;
                    events.Add(new SampleEvent
                    {
                        Timestamp = ts,
                        Account = account,
                        Database = db,
                        ClientHost = host,
                        SessionId = session,
                        Command = "SELECT",
                        Statement = isRead
                            ? "SELECT o.id, o.total FROM core.orders o WHERE o.customer_id = $1 LIMIT 25"
                            : "UPDATE core.orders SET updated_at = now() WHERE id = $1",
                        RowsReturned = isRead ? 25 : null,
                        RowsAffected = isRead ? null : 1,
                        DurationMs = Math.Round(rng.NextDouble() * 30 + 0.4, 2),
                    });

                    // pg_report 的例行大导出（同样属基线内）
                    if (account == "pg_report" && hour == 2 && k == 0)
                    {
                        events.Add(new SampleEvent
                        {
                            Timestamp = ts.AddSeconds(3),
                            Account = "pg_report",
                            Database = "dw",
                            ClientHost = host,
                            SessionId = session,
                            Command = "SELECT",
                            Statement =
                                "SELECT date_trunc('day', created_at) AS d, count(*), sum(amount) "
                                + "FROM dw.fact_events WHERE created_at >= $1 GROUP BY 1 ORDER BY 1",
                            RowsReturned = 61_000 + rng.Next(10_000),
                            DurationMs = 2_400,
                        });
                    }
                }
            }
        }

        // 埋点 1：PG 时间盲注
        var pg1 = new SampleEvent
        {
            Timestamp = Base.AddDays(2).AddHours(6).AddMinutes(11),
            Account = "pg_app",
            Database = "core",
            ClientHost = "203.0.113.77",
            SessionId = "66901",
            Command = "SELECT",
            Statement = "SELECT id FROM core.orders WHERE id = 1 AND pg_sleep(8) IS NULL",
            RowsReturned = 1,
            DurationMs = 8_040,
            Label = "pg-sleep",
        };
        events.Add(pg1);
        expected["pg-sleep"] = [RuleCatalog.TimeBasedBlind];

        // 埋点 2：PG UNION 读 pg_catalog
        var pg2 = new SampleEvent
        {
            Timestamp = pg1.Timestamp.AddSeconds(30),
            Account = "pg_app",
            Database = "core",
            ClientHost = "203.0.113.77",
            SessionId = "66901",
            Command = "SELECT",
            Statement =
                "SELECT id, name FROM core.products WHERE id = 1 UNION SELECT usename, passwd FROM pg_catalog.pg_shadow",
            RowsReturned = 4,
            DurationMs = 22,
            Label = "pg-union-shadow",
        };
        events.Add(pg2);
        expected["pg-union-shadow"] = [RuleCatalog.UnionInjection, RuleCatalog.CredentialStoreAccess];

        // 埋点 3：PG COPY ... TO PROGRAM（命令执行）
        var pg3 = new SampleEvent
        {
            Timestamp = pg2.Timestamp.AddMinutes(2),
            Account = "pg_sync",
            Database = "core",
            ClientHost = "10.30.4.30",
            SessionId = "66211",
            Command = "COPY",
            Statement = "COPY (SELECT * FROM core.users) TO PROGRAM 'gzip > /tmp/users.gz'",
            RowsAffected = 120_000,
            DurationMs = 5_200,
            Label = "pg-copy-program",
        };
        events.Add(pg3);
        expected["pg-copy-program"] = [RuleCatalog.BulkExport];

        // 埋点 4：PG 提权
        var pg4 = new SampleEvent
        {
            Timestamp = pg3.Timestamp.AddMinutes(3),
            Account = "pg_sync",
            Database = "core",
            ClientHost = "10.30.4.30",
            SessionId = "66211",
            Command = "ALTER ROLE",
            Statement = "ALTER ROLE pg_sync WITH SUPERUSER CREATEROLE",
            RowsAffected = 0,
            DurationMs = 6,
            Label = "pg-grant-superuser",
        };
        events.Add(pg4);
        expected["pg-grant-superuser"] = [RuleCatalog.PrivilegeChange];

        // 埋点 5：无过滤的大结果集
        var pg5 = new SampleEvent
        {
            Timestamp = pg3.Timestamp.AddMinutes(6),
            Account = "pg_app",
            Database = "core",
            ClientHost = "203.0.113.77",
            SessionId = "66901",
            Command = "SELECT",
            Statement = "SELECT * FROM core.customers",
            RowsReturned = 758_330,
            DurationMs = 12_600,
            Label = "pg-exfil-all",
        };
        events.Add(pg5);
        expected["pg-exfil-all"] = [RuleCatalog.LargeResultSet];

        events.Sort((a, b) => a.Timestamp.CompareTo(b.Timestamp));

        return new SampleDataset
        {
            Name = "pg-csvlog",
            Events = events,
            ExpectedFindings = expected,
        };
    }

    /// <summary>
    /// MySQL general log 数据集：格式限制导致没有 rows_sent，因此不埋“返回行数”类场景。
    /// </summary>
    public static SampleDataset BuildMySqlGeneral()
    {
        var rng = new Random(20261114);
        var events = new List<SampleEvent>();
        var expected = new Dictionary<string, string[]>(StringComparer.Ordinal);

        for (var day = 0; day < 2; day++)
        {
            for (var hour = 8; hour < 20; hour++)
            {
                for (var k = 0; k < 6; k++)
                {
                    var ts = Base.AddDays(day).AddHours(hour).AddMinutes(rng.Next(60)).AddSeconds(rng.Next(60));
                    events.Add(new SampleEvent
                    {
                        Timestamp = ts,
                        Account = rng.Next(2) == 0 ? "legacy_app" : "legacy_report",
                        Database = "legacy",
                        ClientHost = "10.40.1.3",
                        SessionId = (700000 + day * 1000 + hour * 10 + k).ToString(),
                        Statement = rng.Next(3) switch
                        {
                            0 => "SELECT id, code FROM legacy.item_master WHERE id = 42",
                            1 => "UPDATE legacy.stock SET qty = qty - 1 WHERE item_id = 42",
                            _ => "SELECT COUNT(*) FROM legacy.movements WHERE created_at >= '2026-11-01'",
                        },
                        DurationMs = Math.Round(rng.NextDouble() * 20, 2),
                    });
                }
            }
        }

        // 跨行 SQL（general log 常见）：应被正确合并为一条语句
        var multiLine = new SampleEvent
        {
            Timestamp = Base.AddDays(1).AddHours(13).AddMinutes(5),
            Account = "legacy_app",
            Database = "legacy",
            ClientHost = "10.40.1.3",
            SessionId = "801002",
            Statement = "SELECT id, name\nFROM legacy.item_master\nWHERE id = 42",
            Label = "general-multiline-normal",
        };
        events.Add(multiLine);

        // 埋点：堆叠注入
        var inj = new SampleEvent
        {
            Timestamp = Base.AddDays(1).AddHours(15).AddMinutes(2),
            Account = "legacy_app",
            Database = "legacy",
            ClientHost = "10.40.1.3",
            SessionId = "802001",
            Statement = "SELECT id FROM legacy.item_master WHERE code = 'A1'; DELETE FROM legacy.stock WHERE 1=1; -- ",
            Label = "general-stacked",
        };
        events.Add(inj);
        expected["general-stacked"] = [RuleCatalog.StackedQuery, RuleCatalog.Tautology];

        // 埋点：时间盲注
        var sleep = new SampleEvent
        {
            Timestamp = inj.Timestamp.AddMinutes(1),
            Account = "legacy_app",
            Database = "legacy",
            ClientHost = "10.40.1.3",
            SessionId = "802001",
            Statement = "SELECT IF(SUBSTRING(database(),1,1)='l', SLEEP(6), 0)",
            DurationMs = 6_002,
            Label = "general-sleep",
        };
        events.Add(sleep);
        expected["general-sleep"] = [RuleCatalog.TimeBasedBlind];

        events.Sort((a, b) => a.Timestamp.CompareTo(b.Timestamp));
        return new SampleDataset
        {
            Name = "mysql-general",
            Events = events,
            ExpectedFindings = expected,
        };
    }
}
