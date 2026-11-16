using SqlAudit.Core.Model;

namespace SqlAudit.Core.Parsing;

/// <summary>解析诊断信息，用于导入报告里说明“哪些行被跳过、为什么”。</summary>
public sealed record ParseDiagnostic(int Line, string Message);

/// <summary>单个文件/单个数据块的解析结果。</summary>
public sealed class ParseResult
{
    public List<AuditEvent> Events { get; } = new();

    public List<ParseDiagnostic> Diagnostics { get; } = new();

    /// <summary>识别到的来源格式（自动识别时可能与请求的不同）。</summary>
    public AuditSource? DetectedSource { get; set; }

    public int SkippedLines { get; set; }

    public void Warn(int line, string message)
    {
        // 避免同一类错误刷屏：每个文件最多保留 200 条诊断
        if (Diagnostics.Count < 200) Diagnostics.Add(new ParseDiagnostic(line, message));
        else SkippedLines++;
    }
}

/// <summary>日志格式解析器。</summary>
public interface IAuditLogParser
{
    AuditSource Source { get; }

    /// <summary>用于自动识别：判断文本前几行是否像本格式。</summary>
    bool LooksLike(ReadOnlySpan<char> sample);

    ParseResult Parse(TextReader reader, string? sourceFile);
}
