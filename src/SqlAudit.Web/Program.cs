using SqlAudit.Core.Detection;
using SqlAudit.Web.Endpoints;
using SqlAudit.Web.Services;
using SqlAudit.Web.Storage;

var builder = WebApplication.CreateBuilder(args);

// ---- 配置 ----
builder.Services.Configure<DetectionOptions>(
    builder.Configuration.GetSection("Detection"));

builder.Services.AddSingleton(sp =>
{
    var options = new DetectionOptions();
    builder.Configuration.GetSection("Detection").Bind(options);
    return options;
});

var dbPath = builder.Configuration["Storage:DatabasePath"]
             ?? Path.Combine("data", "sqlaudit.db");

// 仓储用延迟解析：数据库路径在服务解析时才读取配置。
// 这样 WebApplicationFactory 的 ConfigureAppConfiguration 覆盖（集成测试指定临时库）才能生效，
// 也允许运行期通过配置切换存储位置。
builder.Services.AddSingleton<IAuditRepository>(sp =>
{
    var configuration = sp.GetRequiredService<IConfiguration>();
    var root = sp.GetRequiredService<IHostEnvironment>().ContentRootPath;

    var configured = configuration["Storage:DatabasePath"];
    var path = string.IsNullOrWhiteSpace(configured) ? Path.Combine("data", "sqlaudit.db") : configured;
    if (!Path.IsPathRooted(path)) path = Path.Combine(root, path);

    return new SqliteAuditRepository(path);
});
builder.Services.AddSingleton<ImportService>();

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddProblemDetails();

// 上传大文件：限制在应用层（ImportService.MaxFileBytes），同时放宽 Kestrel 默认 30MB 限制
builder.Services.Configure<Microsoft.AspNetCore.Http.Features.FormOptions>(o =>
{
    o.MultipartBodyLengthLimit = ImportService.MaxFileBytes;
});

builder.WebHost.ConfigureKestrel(o =>
{
    o.Limits.MaxRequestBodySize = ImportService.MaxFileBytes + 1024 * 1024;
});

var app = builder.Build();

// ---- 启动时初始化数据库 ----
using (var scope = app.Services.CreateScope())
{
    var repo = scope.ServiceProvider.GetRequiredService<IAuditRepository>();
    await repo.InitializeAsync();
}

app.UseExceptionHandler();
app.UseStatusCodePages();

if (!app.Environment.IsDevelopment())
{
    app.UseHsts();
}

app.UseDefaultFiles();
app.UseStaticFiles(new StaticFileOptions
{
    // 前端为单页应用，静态资源不做缓存以便演示时实时生效
    OnPrepareResponse = ctx => ctx.Context.Response.Headers.CacheControl = "no-cache",
});

app.MapApi();

// SPA 兜底：非 /api 路径回落到 index.html
app.MapFallbackToFile("index.html");

app.Logger.LogInformation("SQL 审计分析平台已启动");

app.Run();

/// <summary>供集成测试定位入口程序集。</summary>
public partial class Program;
