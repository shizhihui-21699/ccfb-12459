using SqlAudit.Core.Detection;
using SqlAudit.Core.Detection.Rules;
using SqlAudit.Core.Model;
using SqlAudit.Core.Sql;

namespace SqlAudit.Core.Analysis;

/// <summary>单语句分析结果（不含基线，供逐条解析时复用）。</summary>
public sealed record StatementAnalysis(IReadOnlyList<Finding> Findings, string StatementHash);

/// <summary>
/// 分析引擎：先把事件解析出的 SQL 交给各条语句规则，再做风险评分。
/// 返回行数规则依赖基线，因此必须先 Build 基线再调用 AnalyzeBatch。
/// </summary>
public sealed class AuditAnalyzer
{
    private readonly DetectionOptions _options;
    private readonly List<IStatementRule> _statementRules;

    public AuditAnalyzer(DetectionOptions? options = null)
    {
        _options = options ?? new DetectionOptions();
        _statementRules =
        [
            new TautologyRule(),
            new StackedQueryRule(),
            new UnionInjectionRule(),
            new TimeBasedBlindRule(),
            new PrivilegeChangeRule(),
            new CredentialStoreAccessRule(),
            new ExecutableCommentRule(),
            new BulkExportRule(),
        ];
    }

    public DetectionOptions Options => _options;

    /// <summary>与基线无关的规则（用于导入阶段逐条处理）。</summary>
    public IReadOnlyList<Finding> EvaluateStatement(AuditEvent ev)
    {
        if (!ev.HasStatement) return [];

        var dialect = DialectFor(ev.Source);
        var tokens = SqlLexer.Tokenize(ev.Statement, dialect);
        var ctx = new StatementContext
        {
            Sql = ev.Statement,
            Tokens = tokens,
            Dialect = dialect,
            Event = ev,
            Options = _options,
        };

        var findings = new List<Finding>();
        foreach (var rule in _statementRules)
        {
            try
            {
                findings.AddRange(rule.Evaluate(ctx));
            }
            catch (Exception ex)
            {
                // 单条规则失败不应影响整体分析，记录为诊断性 finding
                findings.Add(new Finding
                {
                    RuleId = rule.Definition.Id,
                    RuleName = rule.Definition.Name,
                    Severity = Severity.None,
                    Message = $"规则执行异常（已跳过）：{ex.GetType().Name}",
                });
            }

            if (findings.Count >= _options.MaxFindingsPerStatement) break;
        }

        return findings;
    }

    /// <summary>对一批事件做完整分析（含基线自适应）。</summary>
    public IReadOnlyList<AnalyzedEvent> AnalyzeBatch(IReadOnlyList<AuditEvent> events)
    {
        var baseline = BaselineIndex.Build(events);
        var largeSetRule = new LargeResultSetRule(baseline);
        var results = new List<AnalyzedEvent>(events.Count);

        foreach (var ev in events)
        {
            var findings = new List<Finding>(EvaluateStatement(ev));

            if (ev.HasStatement)
            {
                try
                {
                    var dialect = DialectFor(ev.Source);
                    var ctx = new StatementContext
                    {
                        Sql = ev.Statement,
                        Tokens = SqlLexer.Tokenize(ev.Statement, dialect),
                        Dialect = dialect,
                        Event = ev,
                        Options = _options,
                    };
                    findings.AddRange(largeSetRule.Evaluate(ctx));
                }
                catch
                {
                    // 忽略：基线规则失败时退化为仅语句规则
                }
            }

            results.Add(Build(ev, findings));
        }

        return results;
    }

    public AnalyzedEvent Analyze(AuditEvent ev, BaselineIndex? baseline = null)
    {
        var findings = new List<Finding>(EvaluateStatement(ev));
        if (ev.HasStatement)
        {
            baseline ??= BaselineIndex.Build([]);
            var rule = new LargeResultSetRule(baseline);
            var dialect = DialectFor(ev.Source);
            var ctx = new StatementContext
            {
                Sql = ev.Statement,
                Tokens = SqlLexer.Tokenize(ev.Statement, dialect),
                Dialect = dialect,
                Event = ev,
                Options = _options,
            };
            findings.AddRange(rule.Evaluate(ctx));
        }
        return Build(ev, findings);
    }

    private AnalyzedEvent Build(AuditEvent ev, List<Finding> findings)
    {
        // 丢弃严重度为 None 的诊断项，但保留到 Findings 里便于调试时能看到
        var effective = findings.Where(f => f.Severity != Severity.None).ToList();

        var categories = RuleCatalog.All.ToDictionary(r => r.Id, r => r.Category, StringComparer.OrdinalIgnoreCase);
        var (score, maxSeverity) = RiskScorer.Score(effective, categories);

        var categoryList = effective
            .Select(f => categories.TryGetValue(f.RuleId, out var c) ? c : "其他")
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        var ruleIds = effective
            .OrderByDescending(f => f.Severity)
            .Select(f => f.RuleId)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        return new AnalyzedEvent
        {
            Event = ev,
            Findings = effective,
            RiskScore = score,
            MaxSeverity = maxSeverity,
            Categories = categoryList,
            RuleIds = ruleIds,
        };
    }

    public static SqlDialect DialectFor(AuditSource source) => source switch
    {
        AuditSource.PostgreSqlCsvLog => SqlDialect.PostgreSql,
        _ => SqlDialect.MySql,
    };
}
