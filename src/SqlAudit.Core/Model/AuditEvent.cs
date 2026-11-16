namespace SqlAudit.Core.Model;

/// <summary>
/// 一条规范化的数据库审计事件。不同来源的日志（MySQL 审计 JSON / general log / PostgreSQL csvlog）
/// 都会被解析成该结构后再进入检测流程。
/// </summary>
public sealed class AuditEvent
{
    public long Id { get; set; }

    public AuditSource Source { get; set; }

    /// <summary>事件时间（统一为 UTC）。</summary>
    public DateTimeOffset Timestamp { get; set; }

    /// <summary>数据库账号（登录用户名，不含 host 部分）。</summary>
    public string Account { get; set; } = "";

    /// <summary>默认数据库 / schema。</summary>
    public string Database { get; set; } = "";

    /// <summary>客户端地址，如 10.20.3.41 或 10.20.3.41:53122。</summary>
    public string? ClientHost { get; set; }

    /// <summary>数据库实例标识（审计日志中通常带有 server id / 主机名）。</summary>
    public string? ServerHost { get; set; }

    /// <summary>命令标签，如 Query / SELECT / Connect / Execute。</summary>
    public string? CommandTag { get; set; }

    /// <summary>会话 / 连接标识，用于把同一连接的连续操作串起来。</summary>
    public string? SessionId { get; set; }

    /// <summary>SQL 原文（可能被截断为前 N 字符，原文上限见 AuditLimits）。</summary>
    public string Statement { get; set; } = "";

    /// <summary>返回行数（日志中能提供时）。</summary>
    public long? RowsReturned { get; set; }

    /// <summary>影响行数（DML）。</summary>
    public long? RowsAffected { get; set; }

    /// <summary>执行耗时（毫秒）。</summary>
    public double? DurationMs { get; set; }

    public bool Succeeded { get; set; } = true;

    public string? ErrorCode { get; set; }

    /// <summary>来源文件名，便于回溯。</summary>
    public string? SourceFile { get; set; }

    /// <summary>来源文件中的行号（记录起始行）。</summary>
    public int SourceLine { get; set; }

    /// <summary>解析后的 SQL 指纹（字面量归一化后的 SHA-256，前 16 位十六进制）。</summary>
    public string StatementHash { get; set; } = "";

    /// <summary>原始记录（受限长度，便于人工核对）。</summary>
    public string? RawRecord { get; set; }

    public bool HasStatement => !string.IsNullOrWhiteSpace(Statement);
}

public static class AuditLimits
{
    public const int MaxStatementChars = 16_000;
    public const int MaxRawChars = 8_000;

    public static string Clamp(string? text, int max)
    {
        if (string.IsNullOrEmpty(text)) return "";
        return text.Length <= max ? text : text[..max];
    }
}
