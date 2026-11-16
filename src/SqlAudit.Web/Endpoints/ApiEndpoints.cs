using SqlAudit.Core.Model;
using SqlAudit.Core.Parsing;
using SqlAudit.Web.Api;
using SqlAudit.Web.Services;
using SqlAudit.Web.Storage;

namespace SqlAudit.Web.Endpoints;

/// <summary>REST API 注册。所有端点前缀 /api，前端为同源静态资源。</summary>
public static class ApiEndpoints
{
    public static RouteGroupBuilder MapApi(this IEndpointRouteBuilder app)
    {
        var api = app.MapGroup("/api");

        api.MapGet("/health", () => Results.Ok(new { status = "ok", time = DateTimeOffset.UtcNow }));

        // ---- 概览 ----
        api.MapGet("/overview", async (IAuditRepository repo, CancellationToken ct) =>
        {
            var stats = await repo.GetOverviewAsync(ct);
            var batches = await repo.ListBatchesAsync(ct);
            var hitLookup = stats.RuleHits.ToDictionary(r => r.RuleId, r => r.Count, StringComparer.OrdinalIgnoreCase);

            return Results.Ok(new OverviewDto(
                stats.TotalEvents,
                stats.AlertedEvents,
                stats.CriticalEvents,
                batches.Count,
                stats.Accounts.Select(a => new FacetDto(a.Value, a.Count)).ToList(),
                stats.Databases.Select(d => new FacetDto(d.Value, d.Count)).ToList(),
                stats.Sources.Select(s => new FacetDto(s.Value, s.Count)).ToList(),
                stats.RuleHits.Select(r => new RuleHitDto(r.RuleId, r.Name, r.Count)).ToList(),
                stats.Timeline.Select(t => new DayDto(t.Day, t.Total, t.Alerts)).ToList(),
                stats.AccountDatabases
                    .Select(a => new AccountDatabaseDto(a.Account, a.Database, a.Count)).ToList(),
                stats.Earliest?.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'"),
                stats.Latest?.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'")));
        });

        // ---- 事件查询（支持账号/库/时间段/规则/严重度/文本/批次）----
        api.MapGet("/events", async (
            string? account, string? database, string? from, string? to,
            bool? alertsOnly, string? minSeverity, string? rules, string? source,
            string? text, long? batchId, int? limit, int? offset,
            IAuditRepository repo, CancellationToken ct) =>
        {
            var query = new EventQuery
            {
                Account = account,
                Database = database,
                From = ParseTime(from),
                To = ParseTime(to),
                AlertsOnly = alertsOnly ?? false,
                MinSeverity = ParseSeverity(minSeverity),
                RuleIds = string.IsNullOrWhiteSpace(rules)
                    ? null
                    : rules.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries),
                Source = AuditSourceExtensions.TryParseCode(source, out var src) ? src : null,
                Text = text,
                BatchId = batchId,
                Limit = limit ?? 50,
                Offset = offset ?? 0,
            };

            var page = await repo.QueryEventsAsync(query, ct);
            return Results.Ok(new PagedDto<EventDto>(
                page.Items.Select(i => DtoMapper.ToDto(i)).ToList(),
                page.Total, page.Limit, page.Offset));
        });

        api.MapGet("/events/{id:long}", async (long id, IAuditRepository repo, CancellationToken ct) =>
        {
            var item = await repo.GetEventAsync(id, ct);
            return item is null
                ? Results.NotFound(new { error = $"事件 {id} 不存在" })
                : Results.Ok(DtoMapper.ToDto(item, includeDetail: true));
        });

        // ---- 攻击链 ----
        api.MapGet("/chains", async (IAuditRepository repo, CancellationToken ct) =>
        {
            var chains = await repo.GetChainsAsync(ct);
            return Results.Ok(chains.Select(DtoMapper.ToDto).ToList());
        });

        // ---- 规则说明 ----
        api.MapGet("/rules", async (IAuditRepository repo, CancellationToken ct) =>
        {
            var stats = await repo.GetOverviewAsync(ct);
            var hits = stats.RuleHits.ToDictionary(r => r.RuleId, r => r.Count, StringComparer.OrdinalIgnoreCase);
            return Results.Ok(RuleCatalog.All
                .Select(r => DtoMapper.ToDto(r, hits.TryGetValue(r.Id, out var c) ? c : 0))
                .ToList());
        });

        // ---- 导入批次 ----
        api.MapGet("/batches", async (IAuditRepository repo, CancellationToken ct) =>
        {
            var batches = await repo.ListBatchesAsync(ct);
            var stats = new List<BatchDto>();
            foreach (var b in batches)
            {
                stats.Add(new BatchDto(
                    b.Id, b.FileName, b.FileSize,
                    b.Source.ToCode(), b.Source.ToLabel(),
                    b.SourceWasAutoDetected,
                    b.ImportedAt.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'"),
                    b.EventCount, b.AlertCount, 0, b.DiagnosticCount, b.Note));
            }
            return Results.Ok(stats);
        });

        api.MapPost("/import", async (
            HttpRequest request, ImportService importer, ILogger<Program> logger,
            CancellationToken ct) =>
        {
            if (!request.HasFormContentType)
                return Results.BadRequest(new { error = "请使用 multipart/form-data 上传日志文件" });

            var form = await request.ReadFormAsync(ct);
            var file = form.Files.GetFile("file");
            if (file is null || file.Length == 0)
                return Results.BadRequest(new { error = "缺少文件字段 file" });

            var safeName = Path.GetFileName(file.FileName);
            if (!IsAllowedExtension(safeName))
                return Results.BadRequest(new
                {
                    error = "不支持的文件类型。允许：.json .jsonl .log .csv .txt",
                });

            var sourceParam = form["source"].ToString();
            AuditSource? requested = null;
            if (!string.IsNullOrWhiteSpace(sourceParam) && sourceParam != "auto")
            {
                if (!AuditSourceExtensions.TryParseCode(sourceParam, out var parsed))
                    return Results.BadRequest(new { error = $"未知的日志格式: {sourceParam}" });
                requested = parsed;
            }

            try
            {
                await using var stream = file.OpenReadStream();
                var result = await importer.ImportAsync(stream, safeName, requested, form["note"], ct);
                return Results.Ok(result);
            }
            catch (InvalidDataException ex)
            {
                return Results.BadRequest(new { error = ex.Message });
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "导入 {File} 失败", safeName);
                return Results.Problem(
                    title: "导入失败",
                    detail: "解析日志时发生错误，请确认文件格式是否正确。",
                    statusCode: 500);
            }
        }).DisableAntiforgery();

        api.MapDelete("/batches/{id:long}", async (long id, IAuditRepository repo, CancellationToken ct) =>
            await repo.DeleteBatchAsync(id, ct)
                ? Results.Ok(new { deleted = id })
                : Results.NotFound(new { error = $"批次 {id} 不存在" }));

        // ---- 元数据 ----
        api.MapGet("/meta", () => Results.Ok(new
        {
            sources = new object[]
            {
                new { code = "auto", label = "自动识别" },
                new { code = AuditSource.MySqlAuditJson.ToCode(), label = AuditSource.MySqlAuditJson.ToLabel() },
                new { code = AuditSource.MySqlGeneralLog.ToCode(), label = AuditSource.MySqlGeneralLog.ToLabel() },
                new { code = AuditSource.PostgreSqlCsvLog.ToCode(), label = AuditSource.PostgreSqlCsvLog.ToLabel() },
            },
            severities = Enum.GetValues<Severity>()
                .Where(s => s > Severity.None)
                .Select(s => new { code = s.ToString().ToLowerInvariant(), label = s.ToLabel(), weight = (int)s }),
            maxUploadMb = ImportService.MaxFileBytes / 1024 / 1024,
        }));

        return api;
    }

    private static DateTimeOffset? ParseTime(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return null;
        if (DateTimeOffset.TryParse(value, out var dto)) return dto;
        return null;
    }

    private static Severity? ParseSeverity(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return null;
        return Enum.TryParse<Severity>(value, ignoreCase: true, out var s) ? s : null;
    }

    private static bool IsAllowedExtension(string fileName)
    {
        var ext = Path.GetExtension(fileName).ToLowerInvariant();
        return ext is ".json" or ".jsonl" or ".log" or ".csv" or ".txt" or "";
    }
}
