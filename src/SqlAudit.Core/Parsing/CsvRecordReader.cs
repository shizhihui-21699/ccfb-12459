using System.Text;

namespace SqlAudit.Core.Parsing;

/// <summary>
/// 流式 CSV 记录读取器，遵循 RFC 4180 加 PostgreSQL csvlog 的实际约定：
/// 字段可被双引号包裹，包裹内 "" 表示一个字面双引号，包裹内可含逗号与换行。
/// PostgreSQL 用空字符串表示 NULL，这里原样保留，由调用方按列语义区分。
/// 使用字符级状态机实现，因此多行 SQL 字段不会被拆成多条记录。
/// </summary>
public sealed class CsvRecordReader
{
    private readonly TextReader _reader;
    private int _line = 1;

    public CsvRecordReader(TextReader reader) => _reader = reader;

    /// <summary>本记录起始行号（1 基），用于诊断定位。</summary>
    public int RecordStartLine { get; private set; } = 1;

    /// <summary>已读取的物理行数。</summary>
    public int LinesRead => _line - 1;

    /// <summary>读取下一条记录；流结束且无内容时返回 null。</summary>
    public List<string>? ReadRecord()
    {
        var fields = new List<string>(24);
        var field = new StringBuilder();
        var inQuotes = false;
        var started = false;
        var recordStart = _line;

        while (true)
        {
            var ch = _reader.Read();
            if (ch < 0)
            {
                if (!started && fields.Count == 0 && field.Length == 0) return null;
                fields.Add(field.ToString());
                RecordStartLine = recordStart;
                return fields;
            }

            started = true;
            var c = (char)ch;

            if (inQuotes)
            {
                if (c == '"')
                {
                    var next = _reader.Peek();
                    if (next == '"')
                    {
                        _reader.Read();
                        field.Append('"');
                    }
                    else
                    {
                        inQuotes = false;
                    }
                }
                else
                {
                    if (c == '\n') { _line++; }
                    field.Append(c);
                }
                continue;
            }

            switch (c)
            {
                case '"':
                    inQuotes = true;
                    break;
                case ',':
                    fields.Add(field.ToString());
                    field.Clear();
                    break;
                case '\r':
                    break;
                case '\n':
                    _line++;
                    fields.Add(field.ToString());
                    RecordStartLine = recordStart;
                    // 跳过完全空白的记录以外的情况：空行返回空字段列表由调用方过滤
                    return fields;
                default:
                    field.Append(c);
                    break;
            }
        }
    }
}
