using SqlAudit.Core.Analysis;
using SqlAudit.Core.Detection;
using SqlAudit.Core.Model;

namespace SqlAudit.Core.Tests;

/// <summary>规则级测试：既验证真阳性，也验证“不该报的不报”。</summary>
public class DetectionRuleTests
{
    private static readonly AuditAnalyzer Analyzer = new(new DetectionOptions());

    private static IReadOnlyList<Finding> Evaluate(
        string sql, AuditSource source = AuditSource.MySqlAuditJson,
        long? rows = null, string account = "tester", string db = "app")
    {
        var ev = new AuditEvent
        {
            Source = source,
            Account = account,
            Database = db,
            Statement = sql,
            RowsReturned = rows,
            Timestamp = DateTimeOffset.UnixEpoch,
        };
        var analyzed = Analyzer.Analyze(ev);
        return analyzed.Findings;
    }

    private static bool HasRule(IReadOnlyList<Finding> findings, string ruleId) =>
        findings.Any(f => string.Equals(f.RuleId, ruleId, StringComparison.OrdinalIgnoreCase));

    // ---------------- R-001 永真条件 ----------------

    [Theory]
    [InlineData("SELECT * FROM users WHERE email = 'x' OR 1=1")]
    [InlineData("SELECT * FROM users WHERE email = 'x' OR 'a'='a'")]
    [InlineData("SELECT * FROM users WHERE id = 5 OR 2>1")]
    [InlineData("SELECT * FROM users WHERE id = 5 OR TRUE")]
    [InlineData("SELECT * FROM users WHERE id = 5 OR 'anything'")]
    [InlineData("SELECT * FROM users WHERE id = 5 OR 1 LIKE '%'")]
    [InlineData("SELECT * FROM t WHERE 1=1")]
    [InlineData("DELETE FROM users WHERE id = 3 OR 0x41='A'")]
    public void TautologyIsDetected(string sql)
    {
        Assert.True(HasRule(Evaluate(sql), RuleCatalog.Tautology), $"应命中永真条件: {sql}");
    }

    [Theory]
    [InlineData("SELECT 1")]
    [InlineData("SELECT id FROM users WHERE id = 1")]
    [InlineData("SELECT id FROM users WHERE id = 1 AND status = 'active'")]
    // 常见 ORM 拼接：WHERE 1=1 AND ... 属正常写法，不应告警
    [InlineData("SELECT id FROM orders WHERE 1 = 1 AND status = 'PAID'")]
    [InlineData("SELECT * FROM t WHERE a = b")]
    [InlineData("SELECT * FROM t WHERE id IN (1, 2, 3)")]
    // 非布尔上下文的常量投影
    [InlineData("SELECT 1 = 1 AS is_same")]
    [InlineData("UPDATE t SET flag = 1 WHERE id = 2")]
    public void NonTautologyIsNotFlagged(string sql)
    {
        Assert.False(HasRule(Evaluate(sql), RuleCatalog.Tautology), $"不应命中永真条件: {sql}");
    }

    [Fact]
    public void OrTautologyIsCritical()
    {
        var findings = Evaluate("SELECT * FROM users WHERE id = 1 OR 1=1");
        var f = findings.Single(x => x.RuleId == RuleCatalog.Tautology);
        Assert.Equal(Severity.Critical, f.Severity);
    }

    [Fact]
    public void AndTautologyIsLowSeverity()
    {
        var findings = Evaluate("SELECT * FROM users WHERE status = 'x' AND 1=1");
        var f = findings.Single(x => x.RuleId == RuleCatalog.Tautology);
        Assert.Equal(Severity.Low, f.Severity);
    }

    // ---------------- R-002 堆叠查询 ----------------

    [Theory]
    [InlineData("SELECT * FROM users WHERE id = 1; DROP TABLE users")]
    [InlineData("SELECT * FROM users WHERE id = 1; DELETE FROM users; --")]
    [InlineData("SELECT 1; INSERT INTO t VALUES (1)")]
    [InlineData("SELECT 1; UPDATE users SET admin = 1")]
    [InlineData("SELECT 1; GRANT ALL ON *.* TO 'x'@'%'")]
    public void StackedWritesAreDetected(string sql)
    {
        Assert.True(HasRule(Evaluate(sql), RuleCatalog.StackedQuery), $"应命中堆叠查询: {sql}");
    }

    [Theory]
    [InlineData("SELECT * FROM users WHERE id = 1")]
    [InlineData("SELECT * FROM t WHERE note = 'a; DELETE FROM users'")]
    public void NonStackedAreNotFlagged(string sql)
    {
        Assert.False(HasRule(Evaluate(sql), RuleCatalog.StackedQuery), $"不应命中堆叠查询: {sql}");
    }

    // ---------------- R-003 UNION 注入 ----------------

    [Theory]
    [InlineData("SELECT id FROM users WHERE id = 1 UNION SELECT NULL, NULL, NULL")]
    [InlineData("SELECT id FROM users WHERE id = 1 UNION SELECT table_name FROM information_schema.tables")]
    [InlineData("SELECT id FROM users WHERE id = 1 UNION SELECT @@version")]
    [InlineData("SELECT id FROM users WHERE id = 1 UNION SELECT 0x61646d696e")]
    public void UnionInjectionIsDetected(string sql)
    {
        Assert.True(HasRule(Evaluate(sql), RuleCatalog.UnionInjection), $"应命中 UNION 注入: {sql}");
    }

    [Theory]
    [InlineData("SELECT a FROM t1 UNION ALL SELECT a FROM t2")]
    [InlineData("SELECT channel, SUM(x) FROM a GROUP BY channel UNION ALL SELECT channel, SUM(x) FROM b GROUP BY channel")]
    [InlineData("SELECT id, name FROM products WHERE active = 1 UNION SELECT id, name FROM archived_products")]
    public void LegitimateUnionIsNotFlagged(string sql)
    {
        Assert.False(HasRule(Evaluate(sql), RuleCatalog.UnionInjection), $"不应命中 UNION 注入: {sql}");
    }

    // ---------------- R-004 时间盲注 ----------------

    [Theory]
    [InlineData("SELECT * FROM t WHERE id = 1 AND SLEEP(5)")]
    [InlineData("SELECT IF(1=1, SLEEP(3), 0)")]
    [InlineData("SELECT BENCHMARK(5000000, MD5('x'))")]
    [InlineData("SELECT * FROM t WHERE id = 1 AND (SELECT 1 FROM (SELECT SLEEP(5)) x) = 1")]
    public void MySqlTimeBlindIsDetected(string sql)
    {
        Assert.True(HasRule(Evaluate(sql), RuleCatalog.TimeBasedBlind), $"应命中时间盲注: {sql}");
    }

    [Theory]
    [InlineData("SELECT * FROM orders WHERE id = 1 AND pg_sleep(8) IS NULL")]
    [InlineData("SELECT pg_sleep(2)")]
    public void PostgreSqlTimeBlindIsDetected(string sql)
    {
        Assert.True(HasRule(Evaluate(sql, AuditSource.PostgreSqlCsvLog), RuleCatalog.TimeBasedBlind));
    }

    [Fact]
    public void ShortSleepIsMediumSeverity()
    {
        var findings = Evaluate("SELECT * FROM t WHERE id = 1 AND SLEEP(0.01)");
        var f = findings.Single(x => x.RuleId == RuleCatalog.TimeBasedBlind);
        Assert.True(f.Severity < Severity.High, "短延时应当降级");
    }

    [Fact]
    public void SleepFunctionInNormalSelectIsStillReported()
    {
        // 业务代码确实会用 SLEEP 做限流；这类命中仍需人工确认，但不应静默丢弃
        var findings = Evaluate("SELECT SLEEP(1)");
        Assert.True(HasRule(findings, RuleCatalog.TimeBasedBlind));
    }

    // ---------------- R-005 返回行数 ----------------

    [Fact]
    public void LargeResultWithoutWhereIsCritical()
    {
        var findings = Evaluate("SELECT * FROM billing.invoices", rows: 412_880);
        var f = findings.Single(x => x.RuleId == RuleCatalog.LargeResultSet);
        Assert.Equal(Severity.Critical, f.Severity);
    }

    [Fact]
    public void SmallResultIsNotFlagged()
    {
        var findings = Evaluate("SELECT id FROM users WHERE id = 1", rows: 1);
        Assert.False(HasRule(findings, RuleCatalog.LargeResultSet));
    }

    [Fact]
    public void RowsBelowAbsoluteThresholdNotFlaggedWithoutBaseline()
    {
        var findings = Evaluate("SELECT id FROM users WHERE id = 1", rows: 5_000);
        Assert.False(HasRule(findings, RuleCatalog.LargeResultSet));
    }

    // ---------------- R-006 授权变更 ----------------

    [Theory]
    [InlineData("GRANT ALL PRIVILEGES ON *.* TO 'x'@'%' WITH GRANT OPTION")]
    [InlineData("GRANT SELECT ON app.users TO 'reader'@'%'")]
    [InlineData("REVOKE ALL ON *.* FROM 'x'@'%'")]
    [InlineData("ALTER USER 'root'@'localhost' IDENTIFIED BY 'newpass'")]
    [InlineData("CREATE USER 'backdoor'@'%' IDENTIFIED BY 'p@ss'")]
    [InlineData("SET PASSWORD FOR 'root'@'localhost' = PASSWORD('x')")]
    public void MySqlPrivilegeChangesAreDetected(string sql)
    {
        Assert.True(HasRule(Evaluate(sql), RuleCatalog.PrivilegeChange), $"应命中授权变更: {sql}");
    }

    [Theory]
    [InlineData("ALTER ROLE pg_sync WITH SUPERUSER CREATEROLE")]
    [InlineData("CREATE ROLE analyst LOGIN PASSWORD 'x'")]
    [InlineData("GRANT SELECT ON core.orders TO analyst")]
    [InlineData("SET ROLE admin")]
    public void PostgreSqlPrivilegeChangesAreDetected(string sql)
    {
        Assert.True(HasRule(Evaluate(sql, AuditSource.PostgreSqlCsvLog), RuleCatalog.PrivilegeChange));
    }

    [Fact]
    public void GlobalGrantIsCritical()
    {
        var findings = Evaluate("GRANT ALL PRIVILEGES ON *.* TO 'x'@'%' WITH GRANT OPTION");
        var f = findings.Single(x => x.RuleId == RuleCatalog.PrivilegeChange);
        Assert.Equal(Severity.Critical, f.Severity);
    }

    [Fact]
    public void NormalDmlIsNotPrivilegeChange()
    {
        Assert.False(HasRule(Evaluate("UPDATE users SET name = 'x' WHERE id = 1"), RuleCatalog.PrivilegeChange));
    }

    // ---------------- R-007 凭据表访问 ----------------

    [Theory]
    [InlineData("SELECT user, authentication_string FROM mysql.user")]
    [InlineData("SELECT * FROM information_schema.USER_PRIVILEGES")]
    [InlineData("SELECT usename, passwd FROM pg_catalog.pg_shadow", AuditSource.PostgreSqlCsvLog)]
    [InlineData("SELECT rolname FROM pg_catalog.pg_authid", AuditSource.PostgreSqlCsvLog)]
    public void CredentialTablesAreDetected(string sql, AuditSource source = AuditSource.MySqlAuditJson)
    {
        Assert.True(HasRule(Evaluate(sql, source), RuleCatalog.CredentialStoreAccess), $"应命中凭据表访问: {sql}");
    }

    [Theory]
    [InlineData("SELECT id, email FROM app.users WHERE id = 1")]
    [InlineData("SELECT name FROM app.user WHERE id = 1")]
    public void BusinessUserTableIsNotFlagged(string sql)
    {
        Assert.False(HasRule(Evaluate(sql), RuleCatalog.CredentialStoreAccess), $"不应命中凭据表访问: {sql}");
    }

    [Fact]
    public void LoadFileIsDetected()
    {
        var findings = Evaluate("SELECT LOAD_FILE('/etc/passwd')");
        Assert.True(HasRule(findings, RuleCatalog.CredentialStoreAccess));
    }

    // ---------------- R-008 可执行注释 ----------------

    [Fact]
    public void ExecutableCommentIsDetected()
    {
        var findings = Evaluate("SELECT /*!50000 1 FROM mysql.user */ 1");
        Assert.True(HasRule(findings, RuleCatalog.ExecutableComment));
        Assert.Equal(Severity.High, findings.Single(x => x.RuleId == RuleCatalog.ExecutableComment).Severity);
    }

    [Fact]
    public void ExecutableCommentNotFlaggedInPostgreSql()
    {
        // PG 不执行 /*! */，不应在 PG 方言下告警
        var findings = Evaluate("SELECT /*!50000 1 */ 1", AuditSource.PostgreSqlCsvLog);
        Assert.False(HasRule(findings, RuleCatalog.ExecutableComment));
    }

    [Fact]
    public void NormalHintCommentIsNotFlagged()
    {
        Assert.False(HasRule(Evaluate("SELECT /*+ MAX_EXECUTION_TIME(1000) */ 1"), RuleCatalog.ExecutableComment));
    }

    // ---------------- R-009 批量导出 ----------------

    [Theory]
    [InlineData("SELECT * FROM t INTO OUTFILE '/tmp/x.csv'")]
    [InlineData("SELECT * FROM t INTO DUMPFILE '/tmp/x.bin'")]
    [InlineData("LOAD DATA INFILE '/tmp/x.csv' INTO TABLE t")]
    public void MySqlExportIsDetected(string sql)
    {
        Assert.True(HasRule(Evaluate(sql), RuleCatalog.BulkExport), $"应命中批量导出: {sql}");
    }

    [Theory]
    [InlineData("COPY (SELECT * FROM core.users) TO PROGRAM 'gzip > /tmp/users.gz'")]
    [InlineData("COPY core.users TO '/tmp/users.csv'")]
    [InlineData("SELECT lo_export(1234, '/tmp/x')")]
    [InlineData("SELECT pg_read_file('/etc/passwd')")]
    public void PostgreSqlExportIsDetected(string sql)
    {
        Assert.True(HasRule(Evaluate(sql, AuditSource.PostgreSqlCsvLog), RuleCatalog.BulkExport));
    }

    [Fact]
    public void NormalInsertIsNotExport()
    {
        Assert.False(HasRule(Evaluate("INSERT INTO t VALUES (1)"), RuleCatalog.BulkExport));
    }
}
