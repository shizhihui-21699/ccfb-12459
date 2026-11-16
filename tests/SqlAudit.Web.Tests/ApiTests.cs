using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using SqlAudit.Web.Storage;

namespace SqlAudit.Web.Tests;

/// <summary>
/// 端到端接口测试。每个测试类使用独立的临时 SQLite 文件，
/// 避免共享状态导致用例相互干扰。
/// </summary>
public sealed class ApiFactory : WebApplicationFactory<Program>
{
    private readonly string _dbPath =
        Path.Combine(Path.GetTempPath(), $"sqlaudit-test-{Guid.NewGuid():N}.db");

    protected override void ConfigureWebHost(Microsoft.AspNetCore.Hosting.IWebHostBuilder builder)
    {
        builder.ConfigureAppConfiguration((_, config) =>
        {
            config.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Storage:DatabasePath"] = _dbPath,
            });
        });
    }

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        if (!disposing) return;
        foreach (var suffix in new[] { "", "-wal", "-shm" })
        {
            try
            {
                var path = _dbPath + suffix;
                if (File.Exists(path)) File.Delete(path);
            }
            catch (IOException)
            {
                // 临时文件清理失败不影响测试结论
            }
        }
    }
}

/// <summary>
/// 每个测试方法一个独立应用实例与独立 SQLite 文件。
/// 不用 IClassFixture 共享数据库，否则先导入的用例会污染后跑的用例的总数断言。
/// </summary>
public class ApiTests : IDisposable
{
    private readonly ApiFactory _factory;
    private readonly HttpClient _client;

    public ApiTests()
    {
        _factory = new ApiFactory();
        _client = _factory.CreateClient();
    }

    public void Dispose()
    {
        _client.Dispose();
        _factory.Dispose();
    }

    private const string MySqlJson = """
        {"timestamp":"2026-11-14T03:14:22.000000Z","id":1,"class":"general","connection_id":904211,"account":{"user":"app_reader","host":"45.77.13.88"},"general_data":{"command":"Query","sqltext":"SELECT id, email FROM app.users WHERE email = 'x' OR 1=1 -- '","db":"app","query_time":96000,"rows_sent":18442,"status":0}}
        {"timestamp":"2026-11-14T03:16:03.000000Z","id":2,"class":"general","connection_id":904211,"account":{"user":"app_reader","host":"45.77.13.88"},"general_data":{"command":"Query","sqltext":"SELECT id FROM app.users WHERE id = 1; DROP TABLE app.audit_probe; --","db":"app","query_time":44000,"rows_sent":0,"status":0}}
        {"timestamp":"2026-11-14T03:31:00.000000Z","id":3,"class":"general","connection_id":904211,"account":{"user":"app_reader","host":"45.77.13.88"},"general_data":{"command":"Query","sqltext":"SELECT * FROM billing.invoices","db":"billing","query_time":8940000,"rows_sent":412880,"status":0}}
        {"timestamp":"2026-11-14T09:00:00.000000Z","id":4,"class":"general","connection_id":111,"account":{"user":"report_bot","host":"10.20.7.15"},"general_data":{"command":"Query","sqltext":"SELECT id, status FROM app.orders WHERE id = 42","db":"app","query_time":5000,"rows_sent":1,"status":0}}
        """;

    private async Task<JsonElement> ImportAsync(string content, string fileName, string source = "auto")
    {
        using var form = new MultipartFormDataContent();
        var fileContent = new ByteArrayContent(Encoding.UTF8.GetBytes(content));
        fileContent.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
        form.Add(fileContent, "file", fileName);
        form.Add(new StringContent(source), "source");

        var response = await _client.PostAsync("/api/import", form);
        var body = await response.Content.ReadAsStringAsync();
        Assert.True(response.IsSuccessStatusCode, $"导入失败: {response.StatusCode} {body}");
        return JsonDocument.Parse(body).RootElement;
    }

    [Fact]
    public async Task HealthEndpointResponds()
    {
        var response = await _client.GetAsync("/api/health");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task MetaListsThreeSourcesPlusAuto()
    {
        var meta = await _client.GetFromJsonAsync<JsonElement>("/api/meta");
        var codes = meta.GetProperty("sources").EnumerateArray()
            .Select(s => s.GetProperty("code").GetString()).ToList();

        Assert.Contains("auto", codes);
        Assert.Contains("mysql-audit", codes);
        Assert.Contains("mysql-general", codes);
        Assert.Contains("pg-csvlog", codes);
    }

    [Fact]
    public async Task ImportDetectsFormatAndCountsAlerts()
    {
        var result = await ImportAsync(MySqlJson, "audit.json");

        Assert.True(result.GetProperty("autoDetected").GetBoolean());
        Assert.Equal("mysql-audit", result.GetProperty("sourceCode").GetString());
        Assert.Equal(4, result.GetProperty("parsedEvents").GetInt32());
        // OR 1=1、堆叠 DROP、无 WHERE 全表导出 → 3 条告警；第 4 条是干净查询
        Assert.Equal(3, result.GetProperty("alertedEvents").GetInt32());
    }

    [Fact]
    public async Task ExplicitSourceOverridesDetection()
    {
        var result = await ImportAsync(MySqlJson, "audit.json", source: "mysql-general");
        // 显式指定为 general log 时 JSON 内容解析不出事件，但不应报错
        Assert.False(result.GetProperty("autoDetected").GetBoolean());
        Assert.Equal("mysql-general", result.GetProperty("sourceCode").GetString());
    }

    [Fact]
    public async Task UnknownSourceIsRejected()
    {
        using var form = new MultipartFormDataContent();
        form.Add(new ByteArrayContent(Encoding.UTF8.GetBytes(MySqlJson)), "file", "x.json");
        form.Add(new StringContent("oracle-audit"), "source");

        var response = await _client.PostAsync("/api/import", form);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task EmptyFileIsRejected()
    {
        using var form = new MultipartFormDataContent();
        form.Add(new ByteArrayContent([]), "file", "empty.json");

        var response = await _client.PostAsync("/api/import", form);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task DisallowedExtensionIsRejected()
    {
        using var form = new MultipartFormDataContent();
        form.Add(new ByteArrayContent(Encoding.UTF8.GetBytes("x")), "file", "payload.exe");
        var response = await _client.PostAsync("/api/import", form);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task UnrecognizableContentReportsClearError()
    {
        using var form = new MultipartFormDataContent();
        form.Add(new ByteArrayContent(Encoding.UTF8.GetBytes("hello world\nthis is not a log")), "file", "x.log");
        form.Add(new StringContent("auto"), "source");

        var response = await _client.PostAsync("/api/import", form);
        var body = await response.Content.ReadAsStringAsync();
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Contains("无法识别", body);
    }

    [Fact]
    public async Task EventsCanBeFilteredByAccount()
    {
        await ImportInto(_client, MySqlJson, "audit.json");

        var page = await _client.GetFromJsonAsync<JsonElement>("/api/events?account=app_reader&limit=50");
        var items = page.GetProperty("items").EnumerateArray().ToList();

        Assert.NotEmpty(items);
        Assert.All(items, i => Assert.Equal("app_reader", i.GetProperty("account").GetString()));
    }

    [Fact]
    public async Task EventsCanBeFilteredByTimeRange()
    {
        await ImportInto(_client, MySqlJson, "audit.json");

        var page = await _client.GetFromJsonAsync<JsonElement>(
            "/api/events?from=2026-11-14T03:00:00Z&to=2026-11-14T03:20:00Z&limit=50");
        Assert.Equal(2, page.GetProperty("total").GetInt32());
    }

    [Fact]
    public async Task EventsCanBeFilteredByRule()
    {
        await ImportInto(_client, MySqlJson, "audit.json");

        var page = await _client.GetFromJsonAsync<JsonElement>("/api/events?rules=R-002&limit=50");
        var items = page.GetProperty("items").EnumerateArray().ToList();

        Assert.Single(items);
        Assert.Contains("DROP TABLE", items[0].GetProperty("statement").GetString());
    }

    [Fact]
    public async Task EventsCanBeFilteredByDatabase()
    {
        await ImportInto(_client, MySqlJson, "audit.json");

        var page = await _client.GetFromJsonAsync<JsonElement>("/api/events?database=billing&limit=50");
        var items = page.GetProperty("items").EnumerateArray().ToList();
        Assert.Single(items);
        Assert.Equal("billing", items[0].GetProperty("database").GetString());
    }

    [Fact]
    public async Task AlertsOnlyExcludesCleanQueries()
    {
        await ImportInto(_client, MySqlJson, "audit.json");

        var all = await _client.GetFromJsonAsync<JsonElement>("/api/events?limit=50");
        var alerts = await _client.GetFromJsonAsync<JsonElement>("/api/events?alertsOnly=true&limit=50");

        Assert.Equal(4, all.GetProperty("total").GetInt32());
        Assert.Equal(3, alerts.GetProperty("total").GetInt32());
    }

    [Fact]
    public async Task MinSeverityFiltersLowerSeverities()
    {
        await ImportInto(_client, MySqlJson, "audit.json");

        var page = await _client.GetFromJsonAsync<JsonElement>("/api/events?minSeverity=critical&limit=50");
        var items = page.GetProperty("items").EnumerateArray().ToList();

        Assert.NotEmpty(items);
        Assert.All(items, i => Assert.Equal("critical", i.GetProperty("maxSeverity").GetString()));
    }

    [Fact]
    public async Task EventDetailIncludesFindingsWithOffsets()
    {
        await ImportInto(_client, MySqlJson, "audit.json");

        var page = await _client.GetFromJsonAsync<JsonElement>("/api/events?rules=R-001&limit=1");
        var id = page.GetProperty("items")[0].GetProperty("id").GetInt64();

        var detail = await _client.GetFromJsonAsync<JsonElement>($"/api/events/{id}");
        var findings = detail.GetProperty("findings").EnumerateArray().ToList();

        Assert.NotEmpty(findings);
        var tautology = findings.First(f => f.GetProperty("ruleId").GetString() == "R-001");
        var offset = tautology.GetProperty("offset").GetInt32();
        var length = tautology.GetProperty("length").GetInt32();
        var statement = detail.GetProperty("statement").GetString()!;

        Assert.True(offset >= 0 && offset + length <= statement.Length);
        Assert.Contains("1=1", statement.Substring(offset, length));
    }

    [Fact]
    public async Task EventListDoesNotEmbedFindings()
    {
        await ImportInto(_client, MySqlJson, "audit.json");

        var page = await _client.GetFromJsonAsync<JsonElement>("/api/events?limit=1");
        var item = page.GetProperty("items")[0];

        // 列表接口不应带 findings / rawRecord，降低载荷
        Assert.True(item.GetProperty("findings").ValueKind is JsonValueKind.Null or JsonValueKind.Undefined);
    }

    [Fact]
    public async Task MissingEventReturns404()
    {
        var response = await _client.GetAsync("/api/events/999999");
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task OverviewAggregatesFacets()
    {
        await ImportInto(_client, MySqlJson, "audit.json");

        var overview = await _client.GetFromJsonAsync<JsonElement>("/api/overview");

        Assert.Equal(4, overview.GetProperty("totalEvents").GetInt32());
        Assert.Equal(3, overview.GetProperty("alertedEvents").GetInt32());
        Assert.Contains(overview.GetProperty("accounts").EnumerateArray(),
            a => a.GetProperty("value").GetString() == "app_reader");
        Assert.Contains(overview.GetProperty("databases").EnumerateArray(),
            d => d.GetProperty("value").GetString() == "billing");
        Assert.NotEmpty(overview.GetProperty("timeline").EnumerateArray());
    }

    [Fact]
    public async Task ChainsDetectMultiStepAttack()
    {
        await ImportInto(_client, MySqlJson, "audit.json");

        var chains = await _client.GetFromJsonAsync<JsonElement>("/api/chains");
        var list = chains.EnumerateArray().ToList();

        var chain = Assert.Single(list);
        Assert.Equal("app_reader", chain.GetProperty("account").GetString());
        Assert.Equal(3, chain.GetProperty("eventCount").GetInt32());
        Assert.Contains("注入探测", chain.GetProperty("stages").EnumerateArray()
            .Select(s => s.GetString()));
    }

    [Fact]
    public async Task RulesExposeHitCounts()
    {
        await ImportInto(_client, MySqlJson, "audit.json");

        var rules = await _client.GetFromJsonAsync<JsonElement>("/api/rules");
        var r1 = rules.EnumerateArray().First(r => r.GetProperty("id").GetString() == "R-001");

        Assert.True(r1.GetProperty("hitCount").GetInt32() > 0);
        Assert.False(string.IsNullOrWhiteSpace(r1.GetProperty("description").GetString()));
    }

    [Fact]
    public async Task BatchCanBeDeletedWithItsEvents()
    {
        var imported = await ImportInto(_client, MySqlJson, "audit.json");
        var batchId = imported.GetProperty("batchId").GetInt64();

        var before = await _client.GetFromJsonAsync<JsonElement>("/api/events?limit=1");
        Assert.Equal(4, before.GetProperty("total").GetInt32());

        var del = await _client.DeleteAsync($"/api/batches/{batchId}");
        Assert.Equal(HttpStatusCode.OK, del.StatusCode);

        var after = await _client.GetFromJsonAsync<JsonElement>("/api/events?limit=1");
        Assert.Equal(0, after.GetProperty("total").GetInt32());
    }

    [Fact]
    public async Task ImportedDataSurvivesRepeatedQueries()
    {
        await ImportInto(_client, MySqlJson, "audit.json");

        for (var i = 0; i < 3; i++)
        {
            var page = await _client.GetFromJsonAsync<JsonElement>("/api/events?limit=50");
            Assert.Equal(4, page.GetProperty("total").GetInt32());
        }
    }

    [Fact]
    public async Task IndexHtmlIsServed()
    {
        var response = await _client.GetAsync("/");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var html = await response.Content.ReadAsStringAsync();
        Assert.Contains("SQL 审计分析平台", html);
    }

    [Fact]
    public async Task StaticAssetsAreServed()
    {
        foreach (var asset in new[] { "/app.js", "/styles.css" })
        {
            var response = await _client.GetAsync(asset);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        }
    }

    [Fact]
    public async Task PostgreSqlCsvlogImportsWithCorrectFields()
    {
        var csv =
            "2026-11-14 06:11:00.000 UTC,pg_app,core,66901,203.0.113.77:51000,69b00001.0001,1,SELECT," +
            "2026-11-14 06:00:00 UTC,3/8821,0,LOG,00000,duration: 8040.000 ms,,,,,," +
            "\"SELECT id FROM core.orders WHERE id = 1 AND pg_sleep(8) IS NULL\",,pg_app@prod-pg-01,psql\n";

        var result = await ImportInto(_client, csv, "postgresql.csv");

        Assert.Equal("pg-csvlog", result.GetProperty("sourceCode").GetString());
        Assert.Equal(1, result.GetProperty("parsedEvents").GetInt32());
        Assert.Equal(1, result.GetProperty("alertedEvents").GetInt32());

        var page = await _client.GetFromJsonAsync<JsonElement>("/api/events?rules=R-004&limit=5");
        var item = page.GetProperty("items")[0];
        Assert.Equal("pg-csvlog", item.GetProperty("source").GetString());
        Assert.Equal("pg_app", item.GetProperty("account").GetString());
        Assert.Equal("203.0.113.77", item.GetProperty("clientHost").GetString());
    }

    private static async Task<JsonElement> ImportInto(HttpClient client, string content, string fileName)
    {
        using var form = new MultipartFormDataContent();
        var fileContent = new ByteArrayContent(Encoding.UTF8.GetBytes(content));
        fileContent.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
        form.Add(fileContent, "file", fileName);
        form.Add(new StringContent("auto"), "source");

        var response = await client.PostAsync("/api/import", form);
        var body = await response.Content.ReadAsStringAsync();
        Assert.True(response.IsSuccessStatusCode, $"导入失败: {response.StatusCode} {body}");
        return JsonDocument.Parse(body).RootElement;
    }
}

public class RepositoryTests
{
    [Fact]
    public async Task InitializeIsIdempotent()
    {
        var path = Path.Combine(Path.GetTempPath(), $"sqlaudit-repo-{Guid.NewGuid():N}.db");
        try
        {
            var repo = new SqliteAuditRepository(path);
            await repo.InitializeAsync();
            await repo.InitializeAsync();
            Assert.Empty(await repo.ListBatchesAsync());
        }
        finally
        {
            foreach (var suffix in new[] { "", "-wal", "-shm" })
            {
                var p = path + suffix;
                if (File.Exists(p)) File.Delete(p);
            }
        }
    }

    [Fact]
    public async Task SqlInjectionInPayloadDoesNotBreakQueries()
    {
        // 审计日志里的 SQL 会原样入库；参数化查询应保证它不会被当作 SQL 执行
        var path = Path.Combine(Path.GetTempPath(), $"sqlaudit-repo-{Guid.NewGuid():N}.db");
        try
        {
            var repo = new SqliteAuditRepository(path);
            await repo.InitializeAsync();

            const string evil = "SELECT * FROM t WHERE id = 1'; DROP TABLE events; --";
            var ev = new SqlAudit.Core.Model.AuditEvent
            {
                Source = SqlAudit.Core.Model.AuditSource.MySqlAuditJson,
                Account = "a'; DROP TABLE events; --",
                Database = "d'; DROP TABLE events; --",
                Statement = evil,
                Timestamp = DateTimeOffset.UnixEpoch,
            };

            await repo.AddBatchAsync(
                new ImportBatch
                {
                    FileName = "x.json",
                    Source = SqlAudit.Core.Model.AuditSource.MySqlAuditJson,
                    ImportedAt = DateTimeOffset.UtcNow,
                    EventCount = 1,
                },
                [new SqlAudit.Core.Analysis.AnalyzedEvent
                {
                    Event = ev,
                    Findings = [],
                }]);

            var page = await repo.QueryEventsAsync(new EventQuery { Limit = 10 });
            Assert.Equal(1, page.Total);
            Assert.Equal(evil, page.Items[0].Event.Statement);

            // 表仍然存在
            var again = await repo.QueryEventsAsync(new EventQuery { Limit = 10 });
            Assert.Equal(1, again.Total);
        }
        finally
        {
            foreach (var suffix in new[] { "", "-wal", "-shm" })
            {
                var p = path + suffix;
                if (File.Exists(p)) File.Delete(p);
            }
        }
    }
}
