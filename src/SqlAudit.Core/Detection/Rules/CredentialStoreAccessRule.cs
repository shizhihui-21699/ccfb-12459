using SqlAudit.Core.Model;
using SqlAudit.Core.Sql;

namespace SqlAudit.Core.Detection.Rules;

/// <summary>
/// R-007 凭据表 / 敏感系统对象访问。
/// 读取账号口令散列与权限表，往往是提权的前置侦察：
///   MySQL: mysql.user / mysql.db / mysql.tables_priv / information_schema.USER_PRIVILEGES
///   PG:    pg_shadow / pg_authid / pg_user / pg_roles / pg_catalog.pg_authid
/// 也覆盖 LOAD_FILE()/@secure_file_priv 绕过与 dblink / pg_read_file 等越权读取。
/// </summary>
public sealed class CredentialStoreAccessRule : IStatementRule
{
    public RuleDefinition Definition { get; } = RuleCatalog.Get(RuleCatalog.CredentialStoreAccess)!;

    // (schema, object, 说明)
    private static readonly (string Schema, string Object, string Label)[] Targets =
    [
        ("mysql", "user", "MySQL 账号口令散列表 mysql.user"),
        ("mysql", "db", "MySQL 库级权限表 mysql.db"),
        ("mysql", "tables_priv", "MySQL 表级权限表 mysql.tables_priv"),
        ("mysql", "columns_priv", "MySQL 列级权限表 mysql.columns_priv"),
        ("mysql", "global_grants", "MySQL 全局授权表 mysql.global_grants"),
        ("information_schema", "USER_PRIVILEGES", "information_schema.USER_PRIVILEGES"),
        ("pg_catalog", "pg_shadow", "PostgreSQL 口令表 pg_catalog.pg_shadow"),
        ("pg_catalog", "pg_authid", "PostgreSQL 认证表 pg_catalog.pg_authid"),
        ("pg_catalog", "pg_user", "PostgreSQL 用户视图 pg_catalog.pg_user"),
        ("pg_catalog", "pg_roles", "PostgreSQL 角色视图 pg_catalog.pg_roles"),
        ("pg_catalog", "pg_file_settings", "PostgreSQL 配置视图 pg_file_settings"),
        ("pg_catalog", "pg_read_file", "PostgreSQL 服务器文件读取函数"),
    ];

    public IEnumerable<Finding> Evaluate(StatementContext ctx)
    {
        var tokens = ctx.CodeTokens;
        if (tokens.Count == 0) yield break;

        // 只读类语句才有侦察价值；写操作由其他规则覆盖
        for (var i = 0; i < tokens.Count; i++)
        {
            var t = tokens[i];
            if (t.Kind is not (TokKind.Identifier or TokKind.QuotedIdentifier)) continue;

            foreach (var (schema, obj, label) in Targets)
            {
                if (!string.Equals(t.Value, obj, StringComparison.OrdinalIgnoreCase)) continue;

                // 需要限定 schema 前缀，避免误报业务表 user
                var hasSchema = i >= 2 && tokens[i - 1].IsPunct('.')
                                && tokens[i - 2].IsAnyIdentifier(schema);
                // 或者无条件查找 schema token（应对 schema 与表名被空格/别名隔开）
                var schemaPresent = tokens.Any(x => x.IsAnyIdentifier(schema));

                if (!hasSchema && !schemaPresent) continue;

                var from = Math.Max(0, i - 2);
                var offset = tokens[from].Offset;
                var length = Math.Max(1, t.End - offset);

                yield return new Finding
                {
                    RuleId = RuleCatalog.CredentialStoreAccess,
                    RuleName = RuleCatalog.CredentialStoreAccess,
                    Severity = Severity.High,
                    Message = $"访问敏感系统对象：{label}，可能用于提取账号口令散列或枚举权限以实施提权。",
                    Evidence = ctx.EvidenceRange(offset, Math.Min(length, 200)),
                    Offset = offset,
                    Length = Math.Min(length, 200),
                };
                break;
            }
        }

        // LOAD_FILE() 读取服务器文件
        foreach (var call in TokenUtils.FunctionCalls(tokens))
        {
            if (!call.Name.Equals("LOAD_FILE", StringComparison.OrdinalIgnoreCase)) continue;
            yield return new Finding
            {
                RuleId = RuleCatalog.CredentialStoreAccess,
                RuleName = RuleCatalog.CredentialStoreAccess,
                Severity = Severity.Critical,
                Message = "调用 LOAD_FILE() 读取数据库服务器本地文件，可窃取配置文件中的凭据或私钥。",
                Evidence = ctx.EvidenceRange(tokens[call.NameIndex].Offset,
                    Math.Max(1, tokens[call.CloseIndex].End - tokens[call.NameIndex].Offset)),
                Offset = tokens[call.NameIndex].Offset,
                Length = Math.Max(1, tokens[call.CloseIndex].End - tokens[call.NameIndex].Offset),
            };
        }
    }
}
