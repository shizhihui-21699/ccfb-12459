using SqlAudit.Core.Analysis;
using SqlAudit.Core.Detection;
using SqlAudit.Core.Model;
using SqlAudit.Core.Sql;

namespace SqlAudit.Core.Tests;

public class BaselineTests
{
    private static AuditEvent Read(string account, string db, long rows) => new()
    {
        Source = AuditSource.MySqlAuditJson,
        Account = account,
        Database = db,
        Statement = "SELECT id FROM t WHERE id = 1",
        RowsReturned = rows,
        Timestamp = DateTimeOffset.UnixEpoch,
    };

    [Fact]
    public void BaselineComputesPercentiles()
    {
        var events = Enumerable.Range(1, 100).Select(i => Read("a", "db", i * 10)).ToList();
        var index = BaselineIndex.Build(events);
        var stats = index.For("a", "db", minSamples: 10);

        Assert.NotNull(stats);
        Assert.Equal(100, stats!.Count);
        Assert.Equal(500, stats.P50);
        Assert.Equal(1000, stats.Max);
    }

    [Fact]
    public void BaselineRequiresMinimumSamples()
    {
        var events = Enumerable.Range(1, 5).Select(i => Read("a", "db", i)).ToList();
        var index = BaselineIndex.Build(events);
        Assert.Null(index.For("a", "db", minSamples: 20));
    }

    [Fact]
    public void BaselineFallsBackToAccountAcrossDatabases()
    {
        var events = new List<AuditEvent>();
        for (var i = 0; i < 30; i++) events.Add(Read("a", $"db{i % 5}", i * 10));
        var index = BaselineIndex.Build(events);

        Assert.Null(index.For("a", "nonexistent", 20));
        Assert.NotNull(index.ForAccount("a", 20));
    }

    [Fact]
    public void BaselineIgnoresWriteStatements()
    {
        var events = new List<AuditEvent>
        {
            new()
            {
                Source = AuditSource.MySqlAuditJson, Account = "a", Database = "db",
                Statement = "UPDATE t SET x = 1", RowsReturned = 999_999,
                Timestamp = DateTimeOffset.UnixEpoch,
            },
        };
        var index = BaselineIndex.Build(events);
        Assert.Equal(0, index.TotalSamples);
    }

    [Fact]
    public void RoutineReportExportIsNotAnomalousOnceBaselineEstablished()
    {
        // 报表账号每天固定导出约 8 万行：这是基线内行为，不应报「返回行数异常」
        var events = new List<AuditEvent>();
        for (var i = 0; i < 30; i++)
        {
            events.Add(new AuditEvent
            {
                Source = AuditSource.MySqlAuditJson,
                Account = "report_bot",
                Database = "analytics",
                Statement = "SELECT d.date_key, SUM(f.amount) FROM dw.fact_orders f GROUP BY d.date_key",
                RowsReturned = 80_000 + i * 100,
                Timestamp = DateTimeOffset.UnixEpoch.AddHours(i),
            });
        }

        var analyzer = new AuditAnalyzer(new DetectionOptions());
        var analyzed = analyzer.AnalyzeBatch(events);

        Assert.DoesNotContain(analyzed, a => a.RuleIds.Contains(RuleCatalog.LargeResultSet));
    }

    [Fact]
    public void SuddenSpikeAboveOwnBaselineIsFlagged()
    {
        var events = new List<AuditEvent>();
        // 常规流量：每次 10~100 行
        for (var i = 0; i < 40; i++)
        {
            events.Add(new AuditEvent
            {
                Source = AuditSource.MySqlAuditJson,
                Account = "app_reader",
                Database = "billing",
                Statement = "SELECT id, amount FROM billing.invoices WHERE id = 1",
                RowsReturned = 10 + i,
                Timestamp = DateTimeOffset.UnixEpoch.AddMinutes(i),
            });
        }
        // 突发：无过滤条件导出全表
        events.Add(new AuditEvent
        {
            Source = AuditSource.MySqlAuditJson,
            Account = "app_reader",
            Database = "billing",
            Statement = "SELECT * FROM billing.invoices",
            RowsReturned = 400_000,
            Timestamp = DateTimeOffset.UnixEpoch.AddHours(1),
        });

        var analyzer = new AuditAnalyzer(new DetectionOptions());
        var analyzed = analyzer.AnalyzeBatch(events);

        var spike = analyzed.Single(a => a.Event.RowsReturned == 400_000);
        Assert.Contains(RuleCatalog.LargeResultSet, spike.RuleIds);
        Assert.Equal(Severity.Critical, spike.MaxSeverity);
    }
}

public class RiskScorerTests
{
    private static readonly Dictionary<string, string> Categories =
        RuleCatalog.All.ToDictionary(r => r.Id, r => r.Category, StringComparer.OrdinalIgnoreCase);

    private static Finding Make(string ruleId, Severity severity) => new()
    {
        RuleId = ruleId,
        RuleName = ruleId,
        Severity = severity,
        Message = "test",
    };

    [Fact]
    public void DuplicateRuleHitsCountOnce()
    {
        var findings = new[]
        {
            Make(RuleCatalog.Tautology, Severity.Critical),
            Make(RuleCatalog.Tautology, Severity.Critical),
            Make(RuleCatalog.Tautology, Severity.Critical),
        };
        var (score, _) = RiskScorer.Score(findings, Categories);
        var single = RiskScorer.Score([Make(RuleCatalog.Tautology, Severity.Critical)], Categories).Score;
        Assert.Equal(single, score);
    }

    [Fact]
    public void DifferentRulesExceedSingleRule()
    {
        var one = RiskScorer.Score([Make(RuleCatalog.Tautology, Severity.Critical)], Categories).Score;
        var two = RiskScorer.Score(
            [Make(RuleCatalog.Tautology, Severity.Critical), Make(RuleCatalog.StackedQuery, Severity.Critical)],
            Categories).Score;
        Assert.True(two > one, "两条不同规则应提高风险分");
    }

    [Fact]
    public void ScoreIsCappedAt100()
    {
        var findings = RuleCatalog.All.Select(r => Make(r.Id, Severity.Critical)).ToList();
        var (score, _) = RiskScorer.Score(findings, Categories);
        Assert.InRange(score, 0, 100);
        Assert.Equal(100, score);
    }

    [Fact]
    public void NoFindingsMeansZeroScore()
    {
        var (score, severity) = RiskScorer.Score([], Categories);
        Assert.Equal(0, score);
        Assert.Equal(Severity.None, severity);
    }

    [Fact]
    public void MaxSeverityReflectsHighestFinding()
    {
        var (_, severity) = RiskScorer.Score(
            [Make(RuleCatalog.Tautology, Severity.Low), Make(RuleCatalog.TimeBasedBlind, Severity.High)],
            Categories);
        Assert.Equal(Severity.High, severity);
    }
}

public class SessionCorrelatorTests
{
    private static AuditEvent Ev(string session, string statement, int minute, string account = "a") => new()
    {
        Source = AuditSource.MySqlAuditJson,
        Account = account,
        Database = "app",
        ClientHost = "1.2.3.4",
        SessionId = session,
        Statement = statement,
        Timestamp = DateTimeOffset.UnixEpoch.AddMinutes(minute),
        RowsReturned = 1,
    };

    [Fact]
    public void SingleInjectionSignalDoesNotFormChain()
    {
        var analyzer = new AuditAnalyzer();
        var ev = Ev("s1", "SELECT * FROM t WHERE id = 1 OR 1=1", 0);
        var analyzed = new[] { analyzer.Analyze(ev) };

        var chains = SessionCorrelator.Correlate(analyzed);
        Assert.Empty(chains);
    }

    [Fact]
    public void TwoDifferentInjectionRulesInSameSessionFormChain()
    {
        var analyzer = new AuditAnalyzer();
        var events = new[]
        {
            analyzer.Analyze(Ev("s1", "SELECT * FROM t WHERE id = 1 OR 1=1", 0)),
            analyzer.Analyze(Ev("s1", "SELECT * FROM t WHERE id = 1 UNION SELECT NULL, NULL", 1)),
        };

        var chains = SessionCorrelator.Correlate(events);
        var chain = Assert.Single(chains);
        Assert.Equal(2, chain.EventCount);
        Assert.Contains("注入探测", chain.Stages);
        Assert.Contains("信息收集", chain.Stages);
    }

    [Fact]
    public void EventsOutsideWindowAreSeparated()
    {
        var analyzer = new AuditAnalyzer();
        var events = new[]
        {
            analyzer.Analyze(Ev("s1", "SELECT * FROM t WHERE id = 1 OR 1=1", 0)),
            analyzer.Analyze(Ev("s1", "SELECT * FROM t WHERE id = 1 UNION SELECT NULL, NULL", 120)),
        };

        // 默认窗口 30 分钟，相隔 2 小时不构成同一条链
        Assert.Empty(SessionCorrelator.Correlate(events));
    }

    [Fact]
    public void DifferentSessionsAreNotMerged()
    {
        var analyzer = new AuditAnalyzer();
        var events = new[]
        {
            analyzer.Analyze(Ev("s1", "SELECT * FROM t WHERE id = 1 OR 1=1", 0)),
            analyzer.Analyze(Ev("s2", "SELECT * FROM t WHERE id = 1 UNION SELECT NULL, NULL", 1)),
        };
        Assert.Empty(SessionCorrelator.Correlate(events));
    }

    [Fact]
    public void CriticalEventAloneCanFormChain()
    {
        var analyzer = new AuditAnalyzer();
        // 堆叠 DROP 是严重级别；即使只有一条规则，也应作为独立事件进入链路视图
        var events = new[]
        {
            analyzer.Analyze(Ev("s1", "SELECT 1; DROP TABLE t", 0)),
            analyzer.Analyze(Ev("s1", "SELECT * FROM t WHERE id = 1 OR 1=1", 1)),
        };
        var chain = Assert.Single(SessionCorrelator.Correlate(events));
        Assert.Equal(Severity.Critical, chain.MaxSeverity);
    }

    [Fact]
    public void StagesFollowChronologicalOrder()
    {
        var analyzer = new AuditAnalyzer();
        // 先提权，再导出 —— 阶段顺序应体现时间先后，而不是固定表顺序
        var events = new[]
        {
            analyzer.Analyze(Ev("s1", "GRANT ALL PRIVILEGES ON *.* TO 'x'@'%'", 0)),
            analyzer.Analyze(Ev("s1", "SELECT * FROM t INTO OUTFILE '/tmp/x'", 1)),
        };
        var chain = Assert.Single(SessionCorrelator.Correlate(events));
        var privilegeIdx = chain.Stages.ToList().IndexOf("权限变更");
        var exfilIdx = chain.Stages.ToList().IndexOf("数据外泄");
        Assert.True(privilegeIdx >= 0 && exfilIdx > privilegeIdx,
            $"权限变更应先于数据外泄，实际顺序: {string.Join(" → ", chain.Stages)}");
    }
}

public class AnalyzerTests
{
    [Fact]
    public void CleanTrafficProducesNoFindings()
    {
        var analyzer = new AuditAnalyzer();
        var ev = new AuditEvent
        {
            Source = AuditSource.MySqlAuditJson,
            Account = "app",
            Database = "app",
            Statement = "SELECT id, name FROM app.products WHERE category_id = 5 LIMIT 20",
            RowsReturned = 20,
            Timestamp = DateTimeOffset.UnixEpoch,
        };
        var analyzed = analyzer.Analyze(ev);
        Assert.False(analyzed.HasFindings);
        Assert.Equal(0, analyzed.RiskScore);
    }

    [Fact]
    public void RuleExceptionsAreContainedPerStatement()
    {
        // 畸形输入不应让整个分析抛出
        var analyzer = new AuditAnalyzer();
        var evilInputs = new[]
        {
            "", "'''''", "((((((", "/*", "$$", ";;;", "SELECT " + new string('x', 100_000),
            "\u0000\u0001", "SELECT 1 UNION", "OR OR OR",
        };

        foreach (var sql in evilInputs)
        {
            var ev = new AuditEvent
            {
                Source = AuditSource.MySqlAuditJson,
                Account = "a",
                Database = "d",
                Statement = sql,
                Timestamp = DateTimeOffset.UnixEpoch,
            };
            var ex = Record.Exception(() => analyzer.Analyze(ev));
            Assert.Null(ex);
        }
    }

    [Fact]
    public void DialectIsChosenBySource()
    {
        Assert.Equal(SqlDialect.PostgreSql, AuditAnalyzer.DialectFor(AuditSource.PostgreSqlCsvLog));
        Assert.Equal(SqlDialect.MySql, AuditAnalyzer.DialectFor(AuditSource.MySqlAuditJson));
        Assert.Equal(SqlDialect.MySql, AuditAnalyzer.DialectFor(AuditSource.MySqlGeneralLog));
    }
}
