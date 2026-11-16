using SqlAudit.Core.Model;
using SqlAudit.Core.Parsing;

namespace SqlAudit.Core.Tests;

public class ParserTests
{
    private static ParseResult Parse(string content, AuditSource? source)
    {
        var factory = new AuditLogParserFactory();
        using var reader = new StringReader(content);
        return factory.Parse(reader, source, "test.log");
    }

    // ---------------- MySQL 审计插件 JSON ----------------

    private const string MySqlJsonLines = """
        {"timestamp":"2026-11-12T03:14:22.371000Z","id":1,"class":"general","event":"status","connection_id":90412,"account":{"user":"app_reader","host":"10.20.3.41"},"general_data":{"command":"Query","sqltext":"SELECT id FROM app.users WHERE id = 42","db":"app","query_time":1834,"rows_sent":1,"status":0}}
        {"timestamp":"2026-11-12T03:14:23.000000Z","id":2,"class":"general","event":"status","connection_id":90412,"account":{"user":"app_reader","host":"10.20.3.41"},"general_data":{"command":"Query","sqltext":"SELECT id FROM app.users WHERE id = 43","db":"app","query_time":2100,"rows_sent":1,"status":0}}
        """;

    [Fact]
    public void MySqlJsonLinesParsesBothRecords()
    {
        var result = Parse(MySqlJsonLines, AuditSource.MySqlAuditJson);
        Assert.Equal(2, result.Events.Count);
        Assert.Equal("app_reader", result.Events[0].Account);
        Assert.Equal("10.20.3.41", result.Events[0].ClientHost);
        Assert.Equal("app", result.Events[0].Database);
        Assert.Equal(1, result.Events[0].RowsReturned);
        // query_time 是微秒 → 毫秒
        Assert.Equal(1.834, result.Events[0].DurationMs!.Value, 3);
    }

    [Fact]
    public void MySqlJsonArrayIsParsed()
    {
        var content = "[" + MySqlJsonLines.Trim().Replace("\n", ",") + "]";
        var result = Parse(content, AuditSource.MySqlAuditJson);
        Assert.Equal(2, result.Events.Count);
    }

    [Fact]
    public void MySqlJsonWrappedObjectIsParsed()
    {
        var content = "{\"audit_record\":{\"timestamp\":\"2026-11-12T03:14:22Z\",\"account\":{\"user\":\"u\",\"host\":\"h\"},\"general_data\":{\"command\":\"Query\",\"sqltext\":\"SELECT 1\"}}}";
        var result = Parse(content, AuditSource.MySqlAuditJson);
        Assert.Single(result.Events);
        Assert.Equal("u", result.Events[0].Account);
    }

    [Fact]
    public void MySqlJsonSkipsRecordsWithoutSql()
    {
        const string content = """
            {"timestamp":"2026-11-12T03:14:22Z","class":"connection","event":"connect","account":{"user":"u","host":"h"}}
            {"timestamp":"2026-11-12T03:14:23Z","class":"general","account":{"user":"u","host":"h"},"general_data":{"sqltext":"SELECT 1"}}
            """;
        var result = Parse(content, AuditSource.MySqlAuditJson);
        Assert.Single(result.Events);
    }

    [Fact]
    public void MySqlJsonMalformedLineIsSkippedNotFatal()
    {
        const string content = """
            {"timestamp":"2026-11-12T03:14:22Z","account":{"user":"u","host":"h"},"general_data":{"sqltext":"SELECT 1"}}
            { this is not json }
            {"timestamp":"2026-11-12T03:14:24Z","account":{"user":"u","host":"h"},"general_data":{"sqltext":"SELECT 2"}}
            """;
        var result = Parse(content, AuditSource.MySqlAuditJson);
        Assert.Equal(2, result.Events.Count);
    }

    // ---------------- MySQL general log ----------------

    [Fact]
    public void GeneralLogTabFormatIsParsed()
    {
        const string content = """
            2026-11-12T03:14:22.371842Z	90412 Query	SELECT id FROM app.users WHERE id = 42
            2026-11-12T03:14:23.000000Z	90413 Query	SELECT id FROM app.orders WHERE id = 7
            """;
        var result = Parse(content, AuditSource.MySqlGeneralLog);
        Assert.Equal(2, result.Events.Count);
        Assert.Equal("90412", result.Events[0].SessionId);
        Assert.Equal("Query", result.Events[0].CommandTag);
        Assert.StartsWith("SELECT id", result.Events[0].Statement);
    }

    [Fact]
    public void GeneralLogMultilineStatementIsJoined()
    {
        const string content = "2026-11-12T03:14:22.371842Z\t90412 Query\tSELECT id, name\nFROM app.users\nWHERE id = 42\n";
        var result = Parse(content, AuditSource.MySqlGeneralLog);
        Assert.Single(result.Events);
        Assert.Contains("FROM app.users", result.Events[0].Statement);
        Assert.Contains("WHERE id = 42", result.Events[0].Statement);
    }

    [Fact]
    public void GeneralLogAccountIsBackfilledFromConnect()
    {
        const string content = """
            2026-11-12T03:14:20.000000Z	90412 Connect	app_reader@10.20.3.41 on app using TCP/IP
            2026-11-12T03:14:22.371842Z	90412 Query	SELECT 1
            """;
        var result = Parse(content, AuditSource.MySqlGeneralLog);
        var ev = Assert.Single(result.Events);
        Assert.Equal("app_reader", ev.Account);
        Assert.Equal("10.20.3.41", ev.ClientHost);
        Assert.Equal("app", ev.Database);
    }

    [Fact]
    public void GeneralLogHeaderLinesAreIgnored()
    {
        const string content = """
            mysqld, Version: 8.0.39 (MySQL Community Server - GPL). started with:
            Tcp port: 3306  Unix socket: /var/run/mysqld/mysqld.sock
            Time                 Id Command    Argument
            2026-11-12T03:14:22.371842Z	90412 Query	SELECT 1
            """;
        var result = Parse(content, AuditSource.MySqlGeneralLog);
        Assert.Single(result.Events);
    }

    // ---------------- PostgreSQL csvlog ----------------

    private const string PgCsv =
        "2026-11-12 03:14:22.371 UTC,pg_app,core,66901,10.30.2.21:54321,69b00001.0001,1,SELECT," +
        "2026-11-12 03:00:00 UTC,3/8821,0,LOG,00000,duration: 22.500 ms,,,,,," +
        "\"SELECT * FROM core.users WHERE id = $1\",,pg_app@prod-pg-01,psql\n";

    [Fact]
    public void PgCsvLogIsParsed()
    {
        var result = Parse(PgCsv, AuditSource.PostgreSqlCsvLog);
        var ev = Assert.Single(result.Events);
        Assert.Equal("pg_app", ev.Account);
        Assert.Equal("core", ev.Database);
        Assert.Equal("66901", ev.SessionId);
        Assert.Equal("10.30.2.21", ev.ClientHost);
        Assert.Equal("SELECT", ev.CommandTag);
        Assert.Equal("SELECT * FROM core.users WHERE id = $1", ev.Statement);
        Assert.Equal(22.5, ev.DurationMs!.Value, 3);
        Assert.True(ev.Succeeded);
    }

    [Fact]
    public void PgCsvLogMultilineSqlIsOneRecord()
    {
        var content =
            "2026-11-12 03:14:22.371 UTC,pg_app,core,66901,10.30.2.21:54321,69b00001.0001,1,SELECT," +
            "2026-11-12 03:00:00 UTC,3/8821,0,LOG,00000,statement,,,,,," +
            "\"SELECT id\nFROM core.orders\nWHERE id = 1\",,pg_app,psql\n";
        var result = Parse(content, AuditSource.PostgreSqlCsvLog);
        var ev = Assert.Single(result.Events);
        Assert.Contains("FROM core.orders", ev.Statement);
    }

    [Fact]
    public void PgCsvLogErrorRecordIsMarkedFailed()
    {
        var content = PgCsv.Replace(",LOG,00000,", ",ERROR,42501,");
        var result = Parse(content, AuditSource.PostgreSqlCsvLog);
        var ev = Assert.Single(result.Events);
        Assert.False(ev.Succeeded);
        Assert.Equal("42501", ev.ErrorCode);
    }

    [Fact]
    public void PgCsvLogQuotedCommaInsideFieldIsSingleField()
    {
        // detail 列本身含逗号，用引号包裹后仍应算作一个字段，不能打乱后面的列位置
        // 布局：... message(13) , detail(14) , hint..context(15-18) , query(19) , ...
        var content =
            "2026-11-12 03:14:22.371 UTC,pg_app,core,66901,\"10.30.2.21:54321\",69b00001.0001,1,SELECT," +
            "2026-11-12 03:00:00 UTC,3/8821,0,LOG,00000," +
            "\"duration: 5.000 ms\",\"detail, with comma\",,,,," +
            "\"SELECT 1\",,pg_app,psql\n";
        var result = Parse(content, AuditSource.PostgreSqlCsvLog);
        var ev = Assert.Single(result.Events);
        Assert.Equal(5.0, ev.DurationMs!.Value, 3);
    }

    [Fact]
    public void PgCsvLogExtractsRowsFromAutoExplain()
    {
        // message 列含换行与逗号（引号包裹），模拟 auto_explain 把计划写进日志
        const string plan = "duration: 1200.000 ms\nQuery Text: SELECT * FROM core.customers\n" +
                            "Seq Scan on customers  (cost=0.00..15234.00 rows=758330 width=212) (actual time=0.021..612.305 rows=758330 loops=1)";
        var content =
            "2026-11-12 03:14:22.371 UTC,pg_app,core,66901,10.30.2.21:54321,69b00001.0001,1,SELECT," +
            "2026-11-12 03:00:00 UTC,3/8821,0,LOG,00000," +
            // 13 message（引号包裹，内含换行）；14-18 detail/hint/internal_query/pos/context 皆空
            "\"" + plan.Replace("\"", "\"\"") + "\",,,,," + "," +
            // 19 query；20 query_pos；21 location；22 application_name
            "\"SELECT * FROM core.customers\",,pg_app,psql\n";
        var result = Parse(content, AuditSource.PostgreSqlCsvLog);
        var ev = Assert.Single(result.Events);
        Assert.Equal(758_330, ev.RowsReturned);
    }

    // ---------------- 自动识别 ----------------

    [Theory]
    [InlineData(MySqlJsonLines, AuditSource.MySqlAuditJson)]
    [InlineData("2026-11-12T03:14:22.371842Z\t90412 Query\tSELECT 1\n2026-11-12T03:14:23Z\t90413 Query\tSELECT 2\n", AuditSource.MySqlGeneralLog)]
    public void AutoDetectIdentifies(string content, AuditSource expected)
    {
        var result = Parse(content, null);
        Assert.Equal(expected, result.DetectedSource);
        Assert.NotEmpty(result.Events);
    }

    [Fact]
    public void AutoDetectDoesNotConfuseGeneralLogWithCsvLog()
    {
        // 两个格式都以时间戳开头；csvlog 的第二字段是用户名，general log 是 TAB+数字线程号
        const string general = "2026-11-12T03:14:22.371842Z\t90412 Query\tSELECT id, name, x FROM t WHERE a IN (1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20)\n"
                               + "2026-11-12T03:14:23.371842Z\t90413 Query\tSELECT 2\n";
        var result = Parse(general, null);
        Assert.Equal(AuditSource.MySqlGeneralLog, result.DetectedSource);
    }

    [Fact]
    public void AutoDetectThrowsOnGarbage()
    {
        Assert.Throws<InvalidDataException>(() => Parse("not a log file at all\nsecond line", null));
    }

    [Fact]
    public void EmptyFileProducesNoEvents()
    {
        var result = Parse("", AuditSource.MySqlAuditJson);
        Assert.Empty(result.Events);
    }
}

public class TimestampParserTests
{
    [Theory]
    [InlineData("2026-11-12T03:14:22.371Z")]
    [InlineData("2026-11-12 03:14:22")]
    [InlineData("2026-11-12 03:14:22.371 UTC")]
    [InlineData("2026-11-12T03:14:22.371842Z")]
    [InlineData("2026-11-12 03:14:22 +00:00")]
    public void ParsesCommonAuditTimestamps(string text)
    {
        var ts = TimestampParser.Parse(text);
        Assert.NotNull(ts);
        Assert.Equal(2026, ts!.Value.UtcDateTime.Year);
        Assert.Equal(3, ts.Value.UtcDateTime.Hour);
    }

    [Fact]
    public void ParsesUnixSecondsAndMillis()
    {
        var seconds = TimestampParser.FromUnix(1_762_900_000L);
        var millis = TimestampParser.FromUnix(1_762_900_000_000L);
        Assert.Equal(seconds, millis);
    }

    [Fact]
    public void ReturnsNullOnGarbage()
    {
        Assert.Null(TimestampParser.Parse("not a time"));
        Assert.Null(TimestampParser.Parse(""));
        Assert.Null(TimestampParser.Parse(null));
    }
}

public class CsvRecordReaderTests
{
    private static List<List<string>> ReadAll(string content)
    {
        var reader = new CsvRecordReader(new StringReader(content));
        var records = new List<List<string>>();
        List<string>? record;
        while ((record = reader.ReadRecord()) is not null) records.Add(record);
        return records;
    }

    [Fact]
    public void SplitsPlainFields()
    {
        var records = ReadAll("a,b,c\n1,2,3\n");
        Assert.Equal(2, records.Count);
        Assert.Equal(new[] { "a", "b", "c" }, records[0]);
    }

    [Fact]
    public void HandlesQuotedFieldWithComma()
    {
        var records = ReadAll("\"a,b\",c\n");
        Assert.Equal(new[] { "a,b", "c" }, records[0]);
    }

    [Fact]
    public void HandlesEscapedQuotes()
    {
        var records = ReadAll("\"say \"\"hi\"\"\",x\n");
        Assert.Equal("say \"hi\"", records[0][0]);
        Assert.Equal("x", records[0][1]);
    }

    [Fact]
    public void HandlesNewlineInsideQuotes()
    {
        var records = ReadAll("\"line1\nline2\",b\n");
        Assert.Single(records);
        Assert.Equal("line1\nline2", records[0][0]);
    }

    [Fact]
    public void HandlesEmptyFields()
    {
        var records = ReadAll("a,,c\n");
        Assert.Equal(new[] { "a", "", "c" }, records[0]);
    }

    [Fact]
    public void HandlesTrailingEmptyField()
    {
        var records = ReadAll("a,b,\n");
        Assert.Equal(new[] { "a", "b", "" }, records[0]);
    }

    [Fact]
    public void ReportsRecordStartLineAcrossMultilineFields()
    {
        var reader = new CsvRecordReader(new StringReader("a,b\n\"x\ny\",c\nd,e\n"));
        reader.ReadRecord();
        reader.ReadRecord();
        Assert.Equal(2, reader.RecordStartLine);
        reader.ReadRecord();
        Assert.Equal(4, reader.RecordStartLine);
    }
}
