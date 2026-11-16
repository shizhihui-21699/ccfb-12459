using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;
using SqlAudit.Core.Model;

namespace SqlAudit.Core.Parsing;

/// <summary>
/// MySQL general query log（general_log=ON）解析器。
///
/// 真实落盘格式（MySQL 5.7/8.0，log_output=FILE）以制表符分隔三段：
/// <code>
/// 2026-11-12T03:14:22.371842Z	90412 Query	SELECT id FROM app.users WHERE id = 42
/// 2026-11-12T03:14:22.900113Z	90412 Connect	app_reader@10.20.3.41 on app using TCP/IP
/// </code>
/// 即「时间戳 TAB 线程ID+空格+命令 TAB 参数」。老版本（5.6 之前）使用 `YYMMDD HH:MM:SS`
/// 时间格式并以空格对齐，这里一并兼容。
///
/// 语句可能跨多行：不以时间戳开头的后续行并入上一条语句。
/// general log 不含 rows_sent 与耗时，因此返回行数类规则不会触发（属格式客观限制）。
/// </summary>
public sealed partial class MySqlGeneralLogParser : IAuditLogParser
{
    public AuditSource Source => AuditSource.MySqlGeneralLog;

    /// <summary>ISO 时间戳行首。</summary>
    [GeneratedRegex(@"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?", RegexOptions.CultureInvariant)]
    private static partial Regex IsoHead();

    /// <summary>老格式：YYMMDD HH:MM:SS 或 YYMMDD H:MM:SS。</summary>
    [GeneratedRegex(@"^\d{6}\s+\d{1,2}:\d{2}:\d{2}", RegexOptions.CultureInvariant)]
    private static partial Regex LegacyHead();

    [GeneratedRegex(@"^\d{6}\s+\d{1,2}:\d{2}:\d{2}\s+(\d+)\s+(\w+(?:\s\w+)?)\s*(.*)$", RegexOptions.CultureInvariant)]
    private static partial Regex LegacyLine();

    private static readonly HashSet<string> SqlCommands = new(StringComparer.OrdinalIgnoreCase)
    {
        "Query", "Execute", "Prepare", "Long Data", "Stmt",
    };

    public bool LooksLike(ReadOnlySpan<char> sample)
    {
        var text = sample.Length > 16384 ? sample[..16384].ToString() : sample.ToString();
        if (text.Contains("\"class\"", StringComparison.Ordinal)) return false; // 更像审计插件 JSON

        var lines = text.Split('\n', 60);
        var hits = 0;

        foreach (var raw in lines)
        {
            var line = raw.TrimEnd('\r');
            if (line.Length == 0) continue;

            // 新格式必须带制表符分隔时间戳/线程号/命令；这区分开了 PostgreSQL csvlog
            // （csvlog 的同一位置是逗号，且第二字段是用户名而非线程号）
            var iso = IsoHead().Match(line);
            if (iso.Success)
            {
                var rest = line[iso.Length..];
                if (rest.Length > 0 && rest[0] == '\t')
                {
                    hits++;
                    if (hits >= 2) return true;
                    continue;
                }
            }

            // 老格式 YYMMDD HH:MM:SS
            if (LegacyLine().IsMatch(line))
            {
                hits++;
                if (hits >= 2) return true;
            }
        }

        return hits >= 1;
    }

    public ParseResult Parse(TextReader reader, string? sourceFile)
    {
        var result = new ParseResult { DetectedSource = AuditSource.MySqlGeneralLog };

        string? line;
        var lineNo = 0;

        string? pendingStamp = null;
        string? pendingThread = null;
        string? pendingCommand = null;
        string? pendingUserHost = null;
        var pendingBody = new StringBuilder();
        var pendingStartLine = 0;

        // general log 的 Query 行不带账号，只在 Connect 行出现：
        //   90412 Connect  app_reader@10.20.3.41 on app using TCP/IP
        // 因此按线程号记住最近一次 Connect 的身份，再回填到后续 Query 事件上。
        var threadAccounts = new Dictionary<string, (string User, string Host, string Database)>(StringComparer.Ordinal);

        void Flush()
        {
            if (pendingStamp is null) return;

            var body = pendingBody.ToString().Trim();
            var command = pendingCommand;
            var userHost = pendingUserHost;
            var stamp = pendingStamp;
            var thread = pendingThread;
            var startLine = pendingStartLine;

            pendingStamp = null;
            pendingThread = null;
            pendingCommand = null;
            pendingUserHost = null;
            pendingBody.Clear();

            if (body.Length == 0 || command is null) return;

            // Connect 行：登记线程身份（不产出事件，因为不含业务 SQL）
            if (!SqlCommands.Contains(command))
            {
                if (command.Equals("Connect", StringComparison.OrdinalIgnoreCase) && thread is not null)
                {
                    var (u, h) = SplitUserHost(userHost);
                    threadAccounts[thread] = (u, h, SplitDatabase(userHost));
                }
                return;
            }

            var ts = TimestampParser.Parse(stamp);
            if (ts is null)
            {
                result.Warn(startLine, "无法解析 general log 时间戳，已跳过");
                return;
            }

            var (user, host) = SplitUserHost(userHost);
            var database = "";
            if (user.Length == 0 && thread is not null && threadAccounts.TryGetValue(thread, out var identity))
            {
                user = identity.User;
                host = identity.Host;
                database = identity.Database;
            }
            else if (thread is not null && !threadAccounts.ContainsKey(thread))
            {
                threadAccounts[thread] = (user, host, "");
            }

            result.Events.Add(new AuditEvent
            {
                Source = AuditSource.MySqlGeneralLog,
                Timestamp = ts.Value,
                Account = user,
                ClientHost = host,
                Database = database,
                SessionId = thread,
                CommandTag = command,
                Statement = AuditLimits.Clamp(body, AuditLimits.MaxStatementChars),
                SourceFile = sourceFile,
                SourceLine = startLine,
                RawRecord = AuditLimits.Clamp($"{stamp} {thread} {command} {body}", AuditLimits.MaxRawChars),
            });
        }

        while ((line = reader.ReadLine()) is not null)
        {
            lineNo++;
            if (line.Length == 0) continue;

            // 文件头跳过
            if (line.StartsWith("mysqld,", StringComparison.Ordinal)
                || line.StartsWith("Tcp port:", StringComparison.Ordinal)
                || line.StartsWith("Time ", StringComparison.Ordinal)
                || line.StartsWith("Time\t", StringComparison.Ordinal)
                || line.StartsWith("# Time:", StringComparison.Ordinal))
            {
                continue;
            }

            if (TryParseHead(line, out var stamp, out var thread, out var command, out var argument))
            {
                Flush();
                pendingStamp = stamp;
                pendingThread = thread;
                pendingCommand = command;
                pendingStartLine = lineNo;
                pendingBody.Append(argument);

                if (command.Equals("Connect", StringComparison.OrdinalIgnoreCase))
                    pendingUserHost = argument;
                continue;
            }

            // 续行：并入当前语句
            if (pendingStamp is not null)
            {
                pendingBody.Append('\n').Append(line.TrimStart('\t'));
            }
        }

        Flush();
        return result;
    }

    /// <summary>
    /// 解析一行语句头。支持：
    ///   新格式 `2026-11-12T03:14:22.371842Z \t 90412 Query \t SELECT ...`
    ///   新格式 `2026-11-12 03:14:22 \t 90412 Query \t ...`
    ///   老格式 `261112  3:14:22 90412 Query SELECT ...`
    /// </summary>
    private static bool TryParseHead(
        string line, out string stamp, out string? thread, out string command, out string argument)
    {
        stamp = "";
        thread = null;
        command = "";
        argument = "";

        Match m = IsoHead().Match(line);
        if (m.Success)
        {
            stamp = m.Value;
        }
        else
        {
            m = LegacyHead().Match(line);
            if (!m.Success) return false;
            stamp = m.Value;

            var legacy = LegacyLine().Match(line);
            if (!legacy.Success) return false;
            thread = legacy.Groups[1].Value;
            command = legacy.Groups[2].Value.Trim();
            argument = legacy.Groups[3].Value;
            return command.Length > 0;
        }

        var rest = line[m.Length..];

        // 制表符分隔：TAB 线程ID 空格 命令 TAB 参数
        if (rest.Contains('\t'))
        {
            // 时间戳后直接跟 TAB 时，split 的首元素为空，需要先去掉前导制表符
            rest = rest.TrimStart('\t');
            var parts = rest.Split('\t', 3);
            var middle = parts[0].Trim();
            var space = middle.IndexOf(' ');
            if (space > 0)
            {
                thread = middle[..space].Trim();
                command = middle[(space + 1)..].Trim();
            }
            else
            {
                command = middle;
            }
            argument = parts.Length > 1 ? string.Join('\t', parts.Skip(1)) : "";
            return command.Length > 0;
        }

        // 空格分隔：线程ID 命令 参数
        var trimmed = rest.Trim();
        var s1 = trimmed.IndexOf(' ');
        if (s1 < 0) return false;
        thread = trimmed[..s1];
        var after = trimmed[(s1 + 1)..].TrimStart();
        var s2 = after.IndexOf(' ');
        if (s2 < 0)
        {
            command = after;
            argument = "";
        }
        else
        {
            command = after[..s2];
            argument = after[(s2 + 1)..];
        }
        return command.Length > 0;
    }

    /// <summary>从 "app_reader@10.20.3.41 on app using TCP/IP" 拆出账号与客户端地址。</summary>
    internal static (string User, string Host) SplitUserHost(string? text)
    {
        if (string.IsNullOrWhiteSpace(text)) return ("", "");
        var value = text.Trim();
        var onIndex = value.IndexOf(" on ", StringComparison.OrdinalIgnoreCase);
        if (onIndex > 0) value = value[..onIndex];
        var at = value.IndexOf('@');
        if (at < 0) return (value, "");
        return (value[..at], value[(at + 1)..]);
    }

    /// <summary>从 Connect 行正文中提取 "on &lt;db&gt;" 的库名，没有则返回空串。</summary>
    internal static string SplitDatabase(string? text)
    {
        if (string.IsNullOrWhiteSpace(text)) return "";
        var value = text.Trim();
        var onIndex = value.IndexOf(" on ", StringComparison.OrdinalIgnoreCase);
        if (onIndex < 0) return "";
        var rest = value[(onIndex + 4)..].Trim();
        var end = rest.IndexOf(" using ", StringComparison.OrdinalIgnoreCase);
        return end < 0 ? rest : rest[..end].Trim();
    }
}
