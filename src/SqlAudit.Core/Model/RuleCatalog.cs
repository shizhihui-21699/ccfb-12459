namespace SqlAudit.Core.Model;

/// <summary>平台内置的检测规则清单。</summary>
public static class RuleCatalog
{
    public const string Tautology = "R-001";
    public const string StackedQuery = "R-002";
    public const string UnionInjection = "R-003";
    public const string TimeBasedBlind = "R-004";
    public const string LargeResultSet = "R-005";
    public const string PrivilegeChange = "R-006";
    public const string CredentialStoreAccess = "R-007";
    public const string ExecutableComment = "R-008";
    public const string BulkExport = "R-009";

    public static readonly IReadOnlyList<RuleDefinition> All = new List<RuleDefinition>
    {
        new(
            Tautology,
            "tautology-condition",
            "永真条件",
            "SQL 注入",
            "WHERE 之后以 OR 连接的恒真字面量比较（1=1、'a'='a'、OR TRUE 等）。ORM 生成的 WHERE 1=1 属正常写法，"
            + "仅在 OR 连接、且两侧为等价字面量时告警。",
            Severity.Critical),
        new(
            StackedQuery,
            "stacked-queries",
            "堆叠查询",
            "SQL 注入",
            "单条审计记录中出现以分号分隔的多条语句，且后续语句为 INSERT/UPDATE/DELETE/DDL/GRANT 等写操作。"
            + "正常业务日志一般为单语句（存储过程体内的分号由解析器按引号与美元引用识别后排除）。",
            Severity.Critical),
        new(
            UnionInjection,
            "union-injection",
            "UNION 拼接注入",
            "SQL 注入",
            "检测 UNION SELECT，并结合高置信特征判定：全 NULL 占位列、读取 information_schema/pg_catalog/mysql.user、"
            + "调用 version()/current_user/@@version、十六进制或 CHAR() 构造字符串。普通业务 UNION 查询不会告警。",
            Severity.High),
        new(
            TimeBasedBlind,
            "time-based-blind",
            "时间盲注函数",
            "SQL 注入",
            "调用 SLEEP()、BENCHMARK()、pg_sleep() 等延时函数，或 WAITFOR DELAY。按延时参数与函数类型分级。",
            Severity.High),
        new(
            LargeResultSet,
            "large-result-set",
            "返回行数异常",
            "数据外泄",
            "返回行数超过绝对阈值，或远超该账号在同库的历史分布（P99 的倍数）。使用基线自适应，避免把日常报表误报。",
            Severity.High),
        new(
            PrivilegeChange,
            "privilege-change",
            "授权变更",
            "权限变更",
            "GRANT/REVOKE/CREATE USER/ALTER ROLE 等权限语句。授予 ALL PRIVILEGES ON *.*、SUPERUSER、WITH GRANT OPTION 时升级为严重。",
            Severity.High),
        new(
            CredentialStoreAccess,
            "credential-store-access",
            "凭据表访问",
            "敏感对象",
            "读取 mysql.user、information_schema.USER_PRIVILEGES、pg_shadow、pg_authid 等账号口令表，或调用 LOAD_FILE() 读服务器文件。",
            Severity.High),
        new(
            ExecutableComment,
            "executable-comment",
            "可执行注释混淆",
            "SQL 注入",
            "使用 MySQL 版本化注释 /*!50000 ... */ 包裹可执行内容，常用于绕过 WAF 与关键字匹配。",
            Severity.High),
        new(
            BulkExport,
            "bulk-export",
            "批量导出/落盘",
            "数据外泄",
            "INTO OUTFILE/DUMPFILE、COPY ... TO PROGRAM、lo_export 等将查询结果写入文件或执行外部命令的语句。",
            Severity.Critical),
    };

    public static RuleDefinition? Get(string id) =>
        All.FirstOrDefault(r => string.Equals(r.Id, id, StringComparison.OrdinalIgnoreCase));

    public static string NameOf(string id) => Get(id)?.NameZh ?? id;
}
