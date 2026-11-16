using SqlAudit.Core.Analysis;
using SqlAudit.Core.Detection;
using SqlAudit.Core.Model;
using SqlAudit.Core.Parsing;

namespace SqlAudit.SampleGen;

/// <summary>
/// 生成模拟审计日志，并做一次端到端自检：
/// 写出文件 → 用真实解析器读回 → 跑检测规则 → 确认每个埋点都被命中、正常流量不误报。
/// 自检失败时返回非零退出码，便于 CI 使用。
/// </summary>
public static class Program
{
    public static int Main(string[] args)
    {
        var outDir = args.Length > 0
            ? args[0]
            : Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "..", "samples");

        outDir = Path.GetFullPath(outDir);
        Directory.CreateDirectory(outDir);

        Console.WriteLine($"输出目录: {outDir}");

        var failures = new List<string>();
        var factory = new AuditLogParserFactory();
        var analyzer = new AuditAnalyzer(new DetectionOptions());

        // ---------- MySQL 审计 JSON ----------
        var mysqlAudit = DatasetBuilder.BuildMySqlAudit();
        var mysqlAuditPath = Path.Combine(outDir, "mysql-audit.json");
        LogWriters.WriteMySqlAuditJson(mysqlAudit, mysqlAuditPath);
        Verify("MySQL 审计 JSON", mysqlAuditPath, AuditSource.MySqlAuditJson, mysqlAudit, factory, analyzer, failures);

        // ---------- MySQL general log ----------
        var general = DatasetBuilder.BuildMySqlGeneral();
        var generalPath = Path.Combine(outDir, "mysql-general.log");
        LogWriters.WriteMySqlGeneralLog(general, generalPath);
        Verify("MySQL general log", generalPath, AuditSource.MySqlGeneralLog, general, factory, analyzer, failures);

        // ---------- PostgreSQL csvlog ----------
        var pg = DatasetBuilder.BuildPostgreSql();
        var pgPath = Path.Combine(outDir, "postgresql.csv");
        LogWriters.WritePostgreSqlCsvLog(pg, pgPath);
        Verify("PostgreSQL csvlog", pgPath, AuditSource.PostgreSqlCsvLog, pg, factory, analyzer, failures);

        Console.WriteLine();
        if (failures.Count > 0)
        {
            Console.WriteLine($"自检失败 {failures.Count} 项：");
            foreach (var f in failures) Console.WriteLine("  ✗ " + f);
            return 1;
        }

        Console.WriteLine("全部自检通过。");
        return 0;
    }

    private static void Verify(
        string label,
        string path,
        AuditSource source,
        SampleDataset dataset,
        AuditLogParserFactory factory,
        AuditAnalyzer analyzer,
        List<string> failures)
    {
        var fileSize = new FileInfo(path).Length;
        Console.WriteLine();
        Console.WriteLine($"── {label} ──");
        Console.WriteLine($"  文件: {Path.GetFileName(path)}（{fileSize / 1024.0:0.#} KB，{dataset.Events.Count} 条事件）");

        ParseResult parsed;
        using (var reader = new StreamReader(path))
        {
            parsed = factory.Parse(reader, source, Path.GetFileName(path));
        }

        // 自动识别也应给出同样的结论
        using (var reader = new StreamReader(path))
        {
            var auto = factory.Parse(reader, null, Path.GetFileName(path));
            if (auto.DetectedSource != source)
                failures.Add($"{label}: 自动识别得到 {auto.DetectedSource}，期望 {source}");
        }

        var analyzed = analyzer.AnalyzeBatch(parsed.Events);
        var chains = SessionCorrelator.Correlate(analyzed);

        Console.WriteLine($"  解析: {parsed.Events.Count} 条，诊断 {parsed.Diagnostics.Count} 条");
        Console.WriteLine($"  告警: {analyzed.Count(a => a.HasFindings)} 条，攻击链: {chains.Count} 条");

        if (parsed.Events.Count == 0)
        {
            failures.Add($"{label}: 解析结果为 0 条事件");
            return;
        }

        if (parsed.Events.Count != dataset.Events.Count)
            failures.Add($"{label}: 解析事件数 {parsed.Events.Count} != 生成数 {dataset.Events.Count}");

        // 埋点自检：按语句文本匹配回生成时的 Label
        var byStatement = dataset.Events
            .Where(e => e.Label is not null)
            .ToDictionary(e => Normalize(e.Statement), e => e.Label!, StringComparer.Ordinal);

        var matchedLabels = new HashSet<string>(StringComparer.Ordinal);
        var falsePositives = new List<AnalyzedEvent>();

        foreach (var item in analyzed)
        {
            var key = Normalize(item.Event.Statement);
            if (byStatement.TryGetValue(key, out var eventLabel))
            {
                matchedLabels.Add(eventLabel);
                var expectedRules = dataset.ExpectedFindings.TryGetValue(eventLabel, out var rules) ? rules : [];
                if (expectedRules.Length == 0)
                {
                    if (item.HasFindings)
                        falsePositives.Add(item);
                    continue;
                }

                foreach (var rule in expectedRules)
                {
                    if (!item.RuleIds.Contains(rule, StringComparer.OrdinalIgnoreCase))
                        failures.Add($"{eventLabel}: 期望命中 {rule}，实际命中 [{string.Join(",", item.RuleIds)}]");
                }
            }
        }

        foreach (var expectedLabel in dataset.ExpectedFindings.Keys)
        {
            if (!matchedLabels.Contains(expectedLabel))
                failures.Add($"埋点 {expectedLabel} 未在解析结果中找到");
        }

        foreach (var fp in falsePositives)
        {
            failures.Add($"正常流量被误报 {{account={fp.Event.Account}, score={fp.RiskScore}, rules=[{string.Join(",", fp.RuleIds)}]}}: "
                         + fp.Event.Statement[..Math.Min(90, fp.Event.Statement.Length)]);
        }

        // 输出几条告警摘要，便于人工核对
        foreach (var item in analyzed.Where(a => a.HasFindings).OrderByDescending(a => a.RiskScore).Take(5))
        {
            Console.WriteLine($"    · [{item.MaxSeverity.ToLabel()} {item.RiskScore}] {item.Event.Account}@{item.Event.ClientHost}: "
                              + item.Event.Statement[..Math.Min(70, item.Event.Statement.Length)]);
        }
    }

    private static string Normalize(string sql) =>
        string.Join(' ', sql.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries));
}
