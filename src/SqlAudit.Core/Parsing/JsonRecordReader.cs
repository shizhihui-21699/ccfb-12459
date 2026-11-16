using System.Text.Json;

namespace SqlAudit.Core.Parsing;

/// <summary>
/// JSON 记录枚举器，支持两种常见布局：
///   1. JSON Lines（每行一个完整对象）—— 逐行流式读取，内存占用与文件大小无关；
///   2. 顶层数组 [{...},{...}]，或包装对象 {"logs":[...]} —— 只能整体解析。
/// 判定方式：读入首条非空行。若该行本身即可解析为对象，则按 JSONL 流式处理；
/// 否则把首行（及回退缓冲）与剩余流拼接后整体解析。
/// </summary>
public static class JsonRecordReader
{
    public static IEnumerable<JsonRecord> Read(TextReader reader)
    {
        var buffered = new List<string>(2);
        string? line;
        var lineNo = 0;

        // 找到第一条非空行
        while ((line = reader.ReadLine()) is not null)
        {
            lineNo++;
            if (string.IsNullOrWhiteSpace(line)) continue;
            buffered.Add(line);
            break;
        }

        if (buffered.Count == 0) yield break;

        var first = buffered[0].TrimStart();
        if (first.StartsWith('{') && TryParseObject(buffered[0], out _))
        {
            // JSONL：逐行流式
            foreach (var record in ReadJsonLines(reader, buffered[0], lineNo))
                yield return record;
            yield break;
        }

        // 整体解析：首行 + 剩余
        var whole = string.Join('\n', buffered) + "\n" + reader.ReadToEnd();
        var parsed = ParseDocument(whole);
        if (parsed is null) yield break;

        foreach (var record in parsed.Records)
            yield return record;
        parsed.Document.Dispose();
    }

    private static IEnumerable<JsonRecord> ReadJsonLines(TextReader reader, string firstLine, int firstLineNo)
    {
        foreach (var record in TryParseLine(firstLine, firstLineNo))
            yield return record;

        string? line;
        var lineNo = firstLineNo;
        while ((line = reader.ReadLine()) is not null)
        {
            lineNo++;
            if (string.IsNullOrWhiteSpace(line)) continue;
            foreach (var record in TryParseLine(line, lineNo))
                yield return record;
        }
    }

    private static IEnumerable<JsonRecord> TryParseLine(string line, int lineNo)
    {
        JsonElement? cloned = null;
        try
        {
            using var doc = JsonDocument.Parse(line);
            if (doc.RootElement.ValueKind == JsonValueKind.Object)
                cloned = doc.RootElement.Clone();
        }
        catch (JsonException)
        {
            // 跳过无法解析的行
        }

        if (cloned is { } element)
            yield return new JsonRecord(element, lineNo, line);
    }

    private static bool TryParseObject(string line, out JsonElement element)
    {
        element = default;
        try
        {
            using var doc = JsonDocument.Parse(line);
            if (doc.RootElement.ValueKind != JsonValueKind.Object) return false;
            element = doc.RootElement.Clone();
            return true;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    private sealed record ParsedDocument(JsonDocument Document, List<JsonRecord> Records);

    private static ParsedDocument? ParseDocument(string text)
    {
        try
        {
            var doc = JsonDocument.Parse(text, new JsonDocumentOptions
            {
                AllowTrailingCommas = true,
                CommentHandling = JsonCommentHandling.Skip,
                MaxDepth = 64,
            });

            var records = new List<JsonRecord>();
            var root = doc.RootElement;

            var array = root.ValueKind == JsonValueKind.Array ? root : default;
            if (root.ValueKind == JsonValueKind.Object)
            {
                foreach (var prop in root.EnumerateObject())
                {
                    if (prop.Value.ValueKind == JsonValueKind.Array) { array = prop.Value; break; }
                }
            }

            if (array.ValueKind == JsonValueKind.Array)
            {
                var i = 0;
                foreach (var item in array.EnumerateArray())
                {
                    i++;
                    if (item.ValueKind == JsonValueKind.Object)
                        records.Add(new JsonRecord(item.Clone(), i, item.GetRawText()));
                }
            }
            else if (root.ValueKind == JsonValueKind.Object)
            {
                records.Add(new JsonRecord(root.Clone(), 1, root.GetRawText()));
            }

            return new ParsedDocument(doc, records);
        }
        catch (JsonException)
        {
            return null;
        }
    }
}

/// <summary>一条 JSON 记录及其在源文件中的位置。</summary>
public readonly record struct JsonRecord(JsonElement Element, int Line, string Raw);
