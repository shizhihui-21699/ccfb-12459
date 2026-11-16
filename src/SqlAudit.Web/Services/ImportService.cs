using System.Diagnostics;
using System.Text;
using SqlAudit.Core.Analysis;
using SqlAudit.Core.Detection;
using SqlAudit.Core.Model;
using SqlAudit.Core.Parsing;
using SqlAudit.Core.Sql;
using SqlAudit.Web.Storage;

namespace SqlAudit.Web.Services;

public sealed class ImportResult
{
    public long BatchId { get; init; }

    public required string FileName { get; init; }

    public AuditSource Source { get; init; }

    public string SourceCode => Source.ToCode();

    public string SourceLabel => Source.ToLabel();

    public bool AutoDetected { get; init; }

    public int ParsedEvents { get; init; }

    public int AlertedEvents { get; init; }

    public int CriticalEvents { get; init; }

    public int DiagnosticCount { get; init; }

    public long ElapsedMs { get; init; }

    public IReadOnlyList<ParseDiagnostic> Diagnostics { get; init; } = [];
}

/// <summary>
/// 导入流程：识别格式 → 解析 → 计算语句指纹 → 批量分析（含基线）→ 落库。
/// 解析全部在服务端完成；文件大小上限由应用层限制，避免误传巨型文件打满内存。
/// </summary>
public sealed class ImportService
{
    public const long MaxFileBytes = 256L * 1024 * 1024;

    private readonly IAuditRepository _repository;
    private readonly AuditLogParserFactory _factory = new();
    private readonly DetectionOptions _options;
    private readonly ILogger<ImportService> _logger;

    public ImportService(IAuditRepository repository, DetectionOptions options, ILogger<ImportService> logger)
    {
        _repository = repository;
        _options = options;
        _logger = logger;
    }

    public async Task<ImportResult> ImportAsync(
        Stream stream, string fileName, AuditSource? requestedSource, string? note,
        CancellationToken ct = default)
    {
        var sw = Stopwatch.StartNew();

        await using var buffer = new MemoryStream();
        await stream.CopyToAsync(buffer, ct);
        var size = buffer.Length;
        if (size == 0) throw new InvalidDataException("文件为空");
        if (size > MaxFileBytes) throw new InvalidDataException($"文件超过上限 {MaxFileBytes / 1024 / 1024} MB");

        buffer.Position = 0;
        var parseResult = ParseWithEncodingDetection(buffer, requestedSource, fileName);

        var detected = parseResult.DetectedSource ?? requestedSource ?? AuditSource.MySqlAuditJson;
        var autoDetected = requestedSource is null;

        // 语句指纹（用于聚合与去重，检测流程内部不依赖它）
        foreach (var ev in parseResult.Events)
        {
            if (ev.HasStatement)
                ev.StatementHash = SqlFingerprint.Compute(ev.Statement, AuditAnalyzer.DialectFor(ev.Source));
        }

        var analyzer = new AuditAnalyzer(_options);
        var analyzed = analyzer.AnalyzeBatch(parseResult.Events);

        var alerts = analyzed.Count(a => a.HasFindings);
        var critical = analyzed.Count(a => a.MaxSeverity >= Severity.Critical);

        var batch = new ImportBatch
        {
            FileName = fileName,
            FileSize = size,
            Source = detected,
            SourceWasAutoDetected = autoDetected,
            ImportedAt = DateTimeOffset.UtcNow,
            EventCount = analyzed.Count,
            AlertCount = alerts,
            DiagnosticCount = parseResult.Diagnostics.Count,
            Note = note,
        };

        var batchId = await _repository.AddBatchAsync(batch, analyzed, ct);
        sw.Stop();

        _logger.LogInformation(
            "导入 {File}: {Source} {Events} 条事件, {Alerts} 条告警, 耗时 {Ms} ms",
            fileName, detected, analyzed.Count, alerts, sw.ElapsedMilliseconds);

        return new ImportResult
        {
            BatchId = batchId,
            FileName = fileName,
            Source = detected,
            AutoDetected = autoDetected,
            ParsedEvents = analyzed.Count,
            AlertedEvents = alerts,
            CriticalEvents = critical,
            DiagnosticCount = parseResult.Diagnostics.Count,
            ElapsedMs = sw.ElapsedMilliseconds,
            Diagnostics = parseResult.Diagnostics.Take(50).ToList(),
        };
    }

    /// <summary>
    /// 编码探测：审计日志可能来自 Windows 导出（UTF-8 BOM / UTF-16LE）。
    /// 先看 BOM，再按 UTF-8 严格解码，失败则回退 GB18030（国内 DBA 环境常见）。
    /// </summary>
    private ParseResult ParseWithEncodingDetection(
        MemoryStream buffer, AuditSource? requestedSource, string fileName)
    {
        var bytes = buffer.ToArray();

        Encoding encoding;
        var preambleLength = 0;
        if (bytes.Length >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF)
        {
            encoding = new UTF8Encoding(false);
            preambleLength = 3;
        }
        else if (bytes.Length >= 2 && bytes[0] == 0xFF && bytes[1] == 0xFE)
        {
            encoding = Encoding.Unicode;
            preambleLength = 2;
        }
        else if (bytes.Length >= 2 && bytes[0] == 0xFE && bytes[1] == 0xFF)
        {
            encoding = Encoding.BigEndianUnicode;
            preambleLength = 2;
        }
        else
        {
            encoding = new UTF8Encoding(false, throwOnInvalidBytes: false);
            if (!IsValidUtf8(bytes))
            {
                try
                {
                    Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
                    encoding = Encoding.GetEncoding("GB18030");
                }
                catch (ArgumentException)
                {
                    encoding = new UTF8Encoding(false, false);
                }
            }
        }

        var text = encoding.GetString(bytes, preambleLength, bytes.Length - preambleLength);
        using var reader = new StringReader(text);
        return _factory.Parse(reader, requestedSource, fileName);
    }

    private static bool IsValidUtf8(ReadOnlySpan<byte> bytes)
    {
        try
        {
            new UTF8Encoding(false, throwOnInvalidBytes: true).GetCharCount(bytes);
            return true;
        }
        catch (DecoderFallbackException)
        {
            return false;
        }
    }
}
