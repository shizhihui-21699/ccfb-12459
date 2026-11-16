namespace SqlAudit.Core.Model;

/// <summary>审计日志来源格式。</summary>
public enum AuditSource
{
    MySqlAuditJson = 1,
    MySqlGeneralLog = 2,
    PostgreSqlCsvLog = 3,
}

public static class AuditSourceExtensions
{
    public static string ToLabel(this AuditSource source) => source switch
    {
        AuditSource.MySqlAuditJson => "MySQL 审计日志",
        AuditSource.MySqlGeneralLog => "MySQL general log",
        AuditSource.PostgreSqlCsvLog => "PostgreSQL csvlog",
        _ => source.ToString(),
    };

    public static string ToCode(this AuditSource source) => source switch
    {
        AuditSource.MySqlAuditJson => "mysql-audit",
        AuditSource.MySqlGeneralLog => "mysql-general",
        AuditSource.PostgreSqlCsvLog => "pg-csvlog",
        _ => source.ToString(),
    };

    public static bool TryParseCode(string? code, out AuditSource source)
    {
        switch (code?.Trim().ToLowerInvariant())
        {
            case "mysql-audit":
            case "mysql":
            case "mysql-audit-json":
                source = AuditSource.MySqlAuditJson;
                return true;
            case "mysql-general":
            case "general":
            case "mysql-general-log":
                source = AuditSource.MySqlGeneralLog;
                return true;
            case "pg-csvlog":
            case "pg":
            case "postgres":
            case "postgresql":
            case "pg-csv":
                source = AuditSource.PostgreSqlCsvLog;
                return true;
            default:
                source = default;
                return false;
        }
    }
}
