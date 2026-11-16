using SqlAudit.Core.Model;

namespace SqlAudit.Core.Parsing;

/// <summary>解析器注册表 / 自动识别入口。</summary>
public sealed class AuditLogParserFactory
{
    private readonly Dictionary<AuditSource, IAuditLogParser> _parsers = new()
    {
        [AuditSource.MySqlAuditJson] = new MySqlAuditJsonParser(),
        [AuditSource.MySqlGeneralLog] = new MySqlGeneralLogParser(),
        [AuditSource.PostgreSqlCsvLog] = new PostgreSqlCsvLogParser(),
    };

    public IReadOnlyCollection<AuditSource> SupportedSources => _parsers.Keys;

    public IAuditLogParser Get(AuditSource source) =>
        _parsers.TryGetValue(source, out var parser)
            ? parser
            : throw new NotSupportedException($"不支持的日志来源: {source}");

    /// <summary>
    /// 自动识别格式。判定顺序很关键：MySQL general log 的经典行与“制表符格式”都可能
    /// 被 csvlog 的宽松判断误吃，因此先精确匹配，再兜底。
    /// </summary>
    public AuditSource Detect(ReadOnlySpan<char> sample)
    {
        var trimmed = sample;
        if (trimmed.Length > 0 && trimmed[0] == '﻿') trimmed = trimmed[1..];
        var text = trimmed.Length > 16384 ? trimmed[..16384].ToString() : trimmed.ToString();
        var head = text.TrimStart();

        if (head.StartsWith('{') || head.StartsWith('['))
        {
            if (_parsers[AuditSource.MySqlAuditJson].LooksLike(text))
                return AuditSource.MySqlAuditJson;
        }

        // 先判 MySQL general log：它的行首是时间戳 + TAB + 数字线程号，特征比 csvlog 更窄。
        // csvlog 的第二字段是用户名（非数字），借此区分。
        if (_parsers[AuditSource.MySqlGeneralLog].LooksLike(text))
            return AuditSource.MySqlGeneralLog;

        if (_parsers[AuditSource.PostgreSqlCsvLog].LooksLike(text))
            return AuditSource.PostgreSqlCsvLog;

        throw new InvalidDataException(
            "无法识别日志格式。支持 MySQL 审计插件 JSON、MySQL general log、PostgreSQL csvlog（可显式指定格式）");
    }

    public ParseResult Parse(TextReader reader, AuditSource? source, string? sourceFile)
    {
        if (source is null)
        {
            // 自动识别需要先窥探内容：读入前 32KB 后拼接回一个 reader
            var buffer = new char[32768];
            var read = reader.ReadBlock(buffer, 0, buffer.Length);
            var sample = new string(buffer, 0, read);
            var detected = Detect(sample);
            var replay = new PrefixedReader(sample, reader);
            var result = _parsers[detected].Parse(replay, sourceFile);
            result.DetectedSource = detected;
            return result;
        }

        return _parsers[source.Value].Parse(reader, sourceFile);
    }

    /// <summary>把已读取的前缀与剩余流拼接回一个 TextReader。</summary>
    private sealed class PrefixedReader : TextReader
    {
        private readonly string _prefix;
        private int _pos;
        private readonly TextReader _inner;

        public PrefixedReader(string prefix, TextReader inner)
        {
            _prefix = prefix;
            _inner = inner;
        }

        public override int Read()
        {
            if (_pos < _prefix.Length) return _prefix[_pos++];
            return _inner.Read();
        }

        public override int Peek()
        {
            if (_pos < _prefix.Length) return _prefix[_pos];
            return _inner.Peek();
        }

        public override int Read(char[] buffer, int index, int count)
        {
            var written = 0;
            while (written < count && _pos < _prefix.Length)
            {
                buffer[index + written] = _prefix[_pos++];
                written++;
            }
            if (written < count) written += _inner.Read(buffer, index + written, count - written);
            return written;
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing) _inner.Dispose();
            base.Dispose(disposing);
        }
    }
}
