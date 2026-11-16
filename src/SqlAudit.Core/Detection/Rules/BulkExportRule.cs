using SqlAudit.Core.Model;
using SqlAudit.Core.Sql;

namespace SqlAudit.Core.Detection.Rules;

/// <summary>
/// R-009 批量导出 / 落盘 / 命令执行。
/// SELECT ... INTO OUTFILE、INTO DUMPFILE、LOAD DATA ... LOCAL INFILE（服务端视角是读文件）、
/// PostgreSQL COPY ... TO PROGRAM（直接执行命令）、COPY TO/FROM 文件、lo_export、pg_read_file。
/// 这类语句一旦出现，几乎都意味着数据被搬到数据库主机的文件系统或外部进程，属数据外泄高危动作。
/// </summary>
public sealed class BulkExportRule : IStatementRule
{
    public RuleDefinition Definition { get; } = RuleCatalog.Get(RuleCatalog.BulkExport)!;

    public IEnumerable<Finding> Evaluate(StatementContext ctx)
    {
        var tokens = ctx.CodeTokens;
        if (tokens.Count == 0) yield break;

        for (var i = 0; i < tokens.Count; i++)
        {
            var t = tokens[i];

            // MySQL: INTO OUTFILE / INTO DUMPFILE
            if (t.IsKeyword("OUTFILE") || t.IsKeyword("DUMPFILE"))
            {
                var from = Math.Max(0, i - 1);
                var offset = tokens[from].Offset;
                var length = t.End - offset;
                yield return new Finding
                {
                    RuleId = RuleCatalog.BulkExport,
                    RuleName = RuleCatalog.BulkExport,
                    Severity = Severity.Critical,
                    Message = $"使用 SELECT ... {t.Value.ToUpperInvariant()} 将查询结果写入数据库主机文件系统，"
                              + "是批量导出数据、绕开应用层审计的常见手法。",
                    Evidence = ctx.EvidenceRange(offset, Math.Max(length, 1)),
                    Offset = offset,
                    Length = Math.Max(length, 1),
                };
                continue;
            }

            // MySQL: LOAD DATA ... INFILE
            if (t.IsKeyword("INFILE"))
            {
                yield return new Finding
                {
                    RuleId = RuleCatalog.BulkExport,
                    RuleName = RuleCatalog.BulkExport,
                    Severity = Severity.High,
                    Message = "使用 LOAD DATA ... INFILE 读取数据库主机上的文件，可能用于落地外泄文件或植入数据。",
                    Evidence = ctx.EvidenceRange(t.Offset, t.Length),
                    Offset = t.Offset,
                    Length = t.Length,
                };
                continue;
            }

            // PostgreSQL: COPY ... TO/FROM PROGRAM / 'file'
            if (t.IsKeyword("COPY"))
            {
                var window = tokens.Skip(i + 1).Take(12).ToList();
                var hasProgram = window.Any(x => x.IsKeyword("PROGRAM"));
                var hasTo = window.Any(x => x.IsKeyword("TO")) || window.Any(x => x.IsKeyword("FROM"));
                var hasFile = window.Any(x => x.Kind == TokKind.String);

                if (hasProgram)
                {
                    var offset = t.Offset;
                    var last = window.LastOrDefault();
                    var length = Math.Max(1, (last.End > 0 ? last.End : t.End) - offset);
                    yield return new Finding
                    {
                        RuleId = RuleCatalog.BulkExport,
                        RuleName = RuleCatalog.BulkExport,
                        Severity = Severity.Critical,
                        Message = "PostgreSQL COPY ... PROGRAM 会在数据库主机上执行 shell 命令，"
                                  + "等价于命令执行，是提权与数据外泄的关键步骤。",
                        Evidence = ctx.EvidenceRange(offset, Math.Min(length, 240)),
                        Offset = offset,
                        Length = Math.Min(length, 240),
                    };
                }
                else if (hasTo && hasFile)
                {
                    yield return new Finding
                    {
                        RuleId = RuleCatalog.BulkExport,
                        RuleName = RuleCatalog.BulkExport,
                        Severity = Severity.High,
                        Message = "PostgreSQL COPY 直接写入/读取服务器主机文件，可能批量搬移数据。",
                        Evidence = ctx.EvidenceRange(t.Offset, Math.Min(200, ctx.Sql.Length - t.Offset)),
                        Offset = t.Offset,
                        Length = Math.Max(1, Math.Min(200, ctx.Sql.Length - t.Offset)),
                    };
                }
                continue;
            }

            // PG: lo_export / pg_read_file / pg_read_binary_file / pg_ls_dir
            if (t.Kind == TokKind.Identifier && i + 1 < tokens.Count && tokens[i + 1].IsPunct('('))
            {
                var name = t.Value.ToUpperInvariant();
                if (name is "LO_EXPORT" or "PG_READ_FILE" or "PG_READ_BINARY_FILE" or "PG_LS_DIR"
                    or "LOAD_FILE" or "SYS_EXEC" or "XP_CMDSHELL")
                {
                    var close = TokenUtils.MatchParen(tokens, i + 1);
                    var end = close > 0 ? tokens[close] : tokens[i + 1];
                    yield return new Finding
                    {
                        RuleId = RuleCatalog.BulkExport,
                        RuleName = RuleCatalog.BulkExport,
                        Severity = Severity.Critical,
                        Message = $"调用 {name}()，可读写数据库主机文件或执行系统命令。",
                        Evidence = ctx.EvidenceRange(t.Offset, end.End - t.Offset),
                        Offset = t.Offset,
                        Length = end.End - t.Offset,
                    };
                }
            }
        }
    }
}
