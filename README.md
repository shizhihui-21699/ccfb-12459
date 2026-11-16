# SQL 审计分析平台

面向 DBA 的数据库审计日志分析平台。导入 MySQL 审计插件日志与 PostgreSQL csvlog，
用基于 SQL 词法分析的规则识别注入语句与数据外泄行为，并在网页端按**账号 / 数据库 / 时间段**筛选。
设计目标是解决「审计日志太多没人看得完」：把上万条正常流量压成几条按风险排序的告警，
而不是再生成一堆需要人肉翻阅的日志。

---

## 快速开始

```bash
# 1. 启动（.NET 8）
dotnet run --project src/SqlAudit.Web

# 2. 浏览器打开 http://localhost:5xxx（控制台会打印端口）
# 3. 在「导入日志」页上传文件，或直接使用仓库中生成好的样本
```

首次运行会自动在 `src/SqlAudit.Web/data/` 下创建 SQLite 数据库，无需手动建库。

### 生成示例日志

仓库未包含样本文件时（或想重新生成），运行生成器：

```bash
dotnet run --project tools/SqlAudit.SampleGen -- samples
```

该程序会写出三份日志到 `samples/`，并做一次端到端自检：
把文件用真实解析器读回、跑检测规则、逐个确认**每个埋点都被命中**、**正常流量零误报**。
自检失败会返回非零退出码，可直接用于 CI。

| 文件 | 格式 | 事件数 | 埋点 |
|---|---|---|---|
| `samples/mysql-audit.json` | MySQL 审计插件 JSON（JSON Lines） | 659 | 永真、UNION×2、时间盲注、可执行注释、堆叠 DROP、大结果集、凭据表、提权、OUTFILE |
| `samples/mysql-general.log` | MySQL general log（TAB 分隔 + 跨行） | 147 | 堆叠注入、时间盲注 |
| `samples/postgresql.csv` | PostgreSQL csvlog（23 列，含 auto_explain 计划） | 501 | pg_sleep 盲注、UNION 读 pg_shadow、COPY TO PROGRAM、ALTER ROLE SUPERUSER、全表导出 |

样本刻意包含了 **3 天正常业务流量**，其中埋了两类“陷阱”用于验证误报控制：
报表账号每天例行导出 8 万行（不应报异常）、业务代码里的 `WHERE 1=1 AND ...` 拼接（不应报注入）。

---

## 支持的日志格式与解析要点

### MySQL 审计插件（JSON）
支持 JSON Lines 与顶层数组两种布局，也兼容 `{"audit_record": {...}}` 包装。关键点：

- `query_time` 在该插件中以**微秒**计时，统一换算为毫秒。
- 只采信 `class` 为 `general` / `table_access` 且含 `sqltext` 的记录；连接、断连事件跳过。
- 字段名做了别名兼容（`sqltext`/`sql_text`/`query`、`rows_sent`/`rows`/`found_rows` 等）。

### MySQL general log
真实格式是 `时间戳 TAB 线程号 命令 TAB 语句`，语句可能跨多行（续行并入上一条）。关键点：

- general log 的 `Query` 行**不带账号**，只在 `Connect` 行出现。解析器按线程号记住最近一次
  `Connect` 的身份，回填到后续 `Query` 上，否则告警页的账号列会是空白。
- 兼容老版本 `YYMMDD HH:MM:SS` 时间格式。
- 该格式**不含返回行数与耗时**，因此「返回行数异常」规则在此来源上不会触发（格式客观限制，
  不是漏检）。需要行数信号请导出来自审计插件或 PG 的日志。

### PostgreSQL csvlog
按官方 23 列定义解析，使用字符级 CSV 状态机，因此**引号字段内的换行与逗号不会把一条记录拆散**
（多行 SQL 常见）。关键点：

- 标准 csvlog **没有“返回行数”列**。启用 `auto_explain`（`log_analyze=on`）后执行计划会写入
  `message`/`detail`，解析器从中提取根节点的 `actual ... rows=N` 作为真实返回行数。
- `connection_from` 形如 `10.30.2.21:54321`，会剥离端口；IPv6 的方括号形式保持原样。
- 耗时从 `duration: 1234.567 ms` 提取，`ERROR`/`FATAL` 记录标记为执行失败并保留 SQLSTATE。

### 编码
上传时探测 BOM（UTF-8 / UTF-16LE/BE），无 BOM 时先按 UTF-8 严格解码，失败回退 GB18030
（国内 DBA 环境常见）。

---

## 检测规则

所有规则在 **token 流**上做结构匹配，而不是正则匹配原文。这一点决定了正确性：

- 字符串里的 `;` 不会被当作语句分隔符 → 堆叠查询规则不会误报
  `WHERE note = 'a; DELETE FROM users'`
- 注释、`$$ ... $$` 美元引用、反引号标识符会被正确切分
- MySQL 的 `/*!50000 ... */` 与普通注释 `/* ... */` 是不同 token 类型

| ID | 规则 | 类别 | 判定逻辑 |
|---|---|---|---|
| R-001 | 永真条件 | SQL 注入 | 字面量之间的恒等比较（`'a'='a'`、`1=1`、`0x41='A'`、`1 BETWEEN 0 AND 2`），或 `OR TRUE/OR 1/OR 'x'`。**要求语句存在 WHERE/HAVING/ON**，因此 `SELECT 1=1` 不会被误判 |
| R-002 | 堆叠查询 | SQL 注入 | 分号后紧跟写操作/DDL/权限操作。`SELECT 1; SELECT 2` 仅提示；`; DROP TABLE` 为严重。存储过程体内的分号被排除 |
| R-003 | UNION 拼接注入 | SQL 注入 | 多特征加权打分（阈值 40）：全 NULL 占位列、读 `information_schema`/`pg_catalog`/`mysql.user`、调 `version()`/`@@version`、十六进制/`CHAR()` 构造字符串、紧邻注释闭合 |
| R-004 | 时间盲注 | SQL 注入 | `SLEEP`/`BENCHMARK`/`pg_sleep`/`pg_sleep_for`/`WAITFOR DELAY`/`DBMS_LOCK.SLEEP`，按延时秒数分级 |
| R-005 | 返回行数异常 | 数据外泄 | 绝对阈值 **或** 相对基线（详见下节） |
| R-006 | 授权变更 | 权限变更 | `GRANT`/`REVOKE`/`CREATE|ALTER|DROP USER|ROLE`/`SET ROLE`/`SET PASSWORD`；`ALL PRIVILEGES ON *.*`、`WITH GRANT OPTION`、`SUPERUSER` 升级为严重 |
| R-007 | 凭据表访问 | 敏感对象 | `mysql.user`、`information_schema.USER_PRIVILEGES`、`pg_shadow`、`pg_authid` 等；`LOAD_FILE()` |
| R-008 | 可执行注释混淆 | SQL 注入 | `/*! ... */`（仅 MySQL 方言）；注释体含 SQL 关键字时升级 |
| R-009 | 批量导出/落盘 | 数据外泄 | `INTO OUTFILE`/`DUMPFILE`、`COPY ... TO PROGRAM`、`lo_export`、`pg_read_file` |

### 误报控制（这是本项目的重点）

三类常见误报都做了针对性处理：

1. **`WHERE 1=1 AND ...`** —— 几乎所有 ORM / 手写拼接都这么写。规则识别出“首条件为 1=1 且
   后续紧跟 AND”时直接跳过。`AND 1=1` 作为中间条件仍会报，但只给**低危**
   （可用 `Detection:ReportAndTautology=false` 关闭）。
2. **业务 UNION 查询** —— 见到 UNION 就报会让报表系统天天告警。R-003 采用加权：纯
   `UNION ALL SELECT ... FROM t2` 得 0 分，不告警；只有叠加注入特征才越过阈值。
3. **报表账号的大批量导出** —— 固定阈值必然误报。R-005 用**基线自适应**。

### 返回行数异常：基线自适应

对每个 `(账号, 数据库)` 维护返回行数的分布（P50/P95/P99）：

- 样本 < `BaselineMinSamples`（默认 20）时只用绝对阈值（10 万行）
- 样本充足时：`本次行数 ≥ max(绝对阈值, P99 × 8)` 且 `≥ P99 × 2` 才告警

效果：报表账号每天导出 8 万行属于其自身分布，不告警；平时取几十行的账号突然取 41 万行，
立刻凸显。基线数据来自**本次导入的同一批事件**，因此建议一次导入覆盖若干天的日志。

阈值均可在 `appsettings.json` 的 `Detection` 节调整，或通过环境变量覆盖。

---

## 风险评分

单条事件的风险分（0–100）由命中的 findings 累加：

- 同一规则重复命中只计一次（避免 5 个 `OR 1=1` 把分数堆满）
- 不同规则叠加时，同类别第二条打 7 折，异类别全额
- 严重 70 / 高危 45 / 中危 20 / 低危 8 / 提示 2

排序与筛选都基于此分数，`maxSeverity` 用于分级过滤。

## 会话关联（攻击链）

单条注入探测往往看起来零散。**攻击链**视图把同一连接（`session_id`，缺失时退化为
`账号@客户端IP`）内 30 分钟窗口里的事件串起来，条件是命中 ≥ 2 条不同注入规则，或出现
严重级别事件。阶段（注入探测 → 信息收集 → 盲注拖延 → 权限变更 → 数据外泄）按**事件时间顺序**推断，
因此“先提权再导出”不会被显示成“先导出再提权”。

样本数据能还原出 5 条攻击链，例如：

```
app_reader @ 45.77.13.88  (7 条事件)
  03:14  OR 1=1 闭包              → 注入探测
  03:15  UNION SELECT NULL,...     → 信息收集
  03:15  UNION 读 information_schema
  03:15  AND (SELECT SLEEP(5))     → 盲注拖延
  03:15  /*!50000 */ + mysql.user
  03:16  ; DROP TABLE
  03:31  SELECT * FROM billing.invoices   → 数据外泄
```

---

## 网页功能

- **概览**：事件总数 / 告警数 / 严重数；按小时的告警时间分布（红色为告警）；规则命中排行、
  账号与数据库分布
- **告警与事件**：按账号、数据库、起止时间、最低严重度、规则、关键词（SQL 片段/客户端 IP）、
  批次筛选；分页；点击进入详情
- **事件详情**：命中规则的逐条说明、**SQL 原文中命中片段的高亮**（按 offset/length）、
  完整事件上下文与原始日志记录
- **攻击链**：按会话聚合的攻击链路，含阶段流转与时间线，点击可跳转到具体事件
- **检测规则**：规则清单与判定说明、本次数据的命中次数
- **导入日志**：拖拽上传、格式自动识别、导入报告（解析条数/告警数/诊断）、批次管理与删除

前端为无框架原生 ES2020，日志内容一律通过 `textContent` / 显式 DOM 构建渲染，
不把不可信的 SQL 注入 `innerHTML`。

---

## 架构

```
src/SqlAudit.Core/          领域核心（无 Web 依赖，可直接单元测试）
  Model/                    事件、finding、规则目录、严重级别
  Sql/                      词法分析器、语句切分、指纹归一化
  Parsing/                  三种格式解析器 + 自动识别 + CSV/时间工具
  Detection/Rules/          9 条规则（IStatementRule）
  Detection/BaselineIndex   返回行数基线
  Analysis/                 分析引擎、风险评分、会话关联

src/SqlAudit.Web/           Minimal API + 静态 SPA
  Storage/                  SQLite 仓储（WAL）
  Services/ImportService    编码探测 → 解析 → 指纹 → 分析 → 落库
  Api/Endpoints             REST（/api/overview, /events, /chains, /rules, /import, ...）
  wwwroot/                  index.html / styles.css / app.js

tools/SqlAudit.SampleGen/   样本生成器 + 端到端自检
tests/SqlAudit.Core.Tests/  148 个测试（词法/切分/解析/规则/基线/评分/关联）
tests/SqlAudit.Web.Tests/   27 个接口集成测试（真实 HTTP + 每用例独立 SQLite）
```

停止条件：走 SQLite 而不是内存，是因为审计数据量可达数十万行且重启不应丢失；
单机分析场景并发低，WAL 模式足够。

---

## 测试

```bash
dotnet test tests/SqlAudit.Core.Tests     # 148 passed
dotnet test tests/SqlAudit.Web.Tests      # 27 passed
```

测试覆盖的重点是**边界与误报**，不只是“能检出”：

- 词法：字符串内分号、MySQL 反斜杠转义 vs PG 字面反斜杠、`$$` 美元引用、
  嵌套块注释、`#` 注释、`5--3` 不是注释、未闭合引号不挂死
- 解析：CSV 引号内换行/逗号、引号转义、多行 general log、Connect 身份回填、
  auto_explain 行数提取、全 0 字节内容不抛异常
- 规则：每条规则都有正例与反例；`WHERE 1=1 AND`、纯业务 UNION、业务 `users` 表
  （区别于 `mysql.user`）都明确断言“不告警”
- 基线：例行报表导出不告警；突发全表导出告警
- 接口：SQL 注入载荷写入 SQLite 后表仍完好（参数化查询）
- 回归：曾因配置时序问题导致集成测试写入开发库，已修复并由
  “测试后开发库不存在”验证隔离

---

## 已知限制

- **general log 无行数/耗时**：R-005 在该来源上不生效（格式限制）
- **PG 行数依赖 auto_explain**：未启用 `log_analyze` 时无法得知真实返回行数
- **检测是启发式**：R-003 的加权阈值、R-004 的延时阈值都偏保守，宁可漏报不误报；
  生产使用前建议用自己环境的日志跑一遍，按 `Detection` 配置调整
- **时区**：日志中的朴素时间按 UTC 处理；若源库使用本地时区，筛选时间会有偏移
- 存储为单机 SQLite，未做多租户/权限控制；定位是 DBA 内部工具
