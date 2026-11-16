/* ============================================================
   SQL 审计分析平台 — 前端逻辑（无框架，原生 ES2020）
   数据全部来自同源 /api。渲染一律走 textContent / 显式 DOM 构建，
   避免把日志中的 SQL 直接注入 innerHTML（日志内容不可信）。
   ============================================================ */

(() => {
  'use strict';

  // ---------------- 基础工具 ----------------

  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

  /** 创建元素。children 可为字符串（按文本节点插入）或 Node。 */
  function el(tag, attrs = {}, children = []) {
    const node = document.createElement(tag);
    for (const [key, value] of Object.entries(attrs)) {
      if (value === null || value === undefined || value === false) continue;
      if (key === 'class') node.className = value;
      else if (key === 'text') node.textContent = value;
      else if (key === 'dataset') Object.assign(node.dataset, value);
      else if (key.startsWith('on') && typeof value === 'function') {
        node.addEventListener(key.slice(2).toLowerCase(), value);
      } else if (key === 'value') node.value = value;
      else if (value === true) node.setAttribute(key, '');
      else node.setAttribute(key, value);
    }
    const list = Array.isArray(children) ? children : [children];
    for (const child of list) {
      if (child === null || child === undefined || child === false) continue;
      node.appendChild(typeof child === 'string' || typeof child === 'number'
        ? document.createTextNode(String(child))
        : child);
    }
    return node;
  }

  const api = {
    async get(path) {
      const res = await fetch(path, { headers: { Accept: 'application/json' } });
      if (!res.ok) {
        let detail = `${res.status} ${res.statusText}`;
        try {
          const body = await res.json();
          if (body?.error) detail = body.error;
          else if (body?.detail) detail = body.detail;
        } catch { /* 非 JSON 错误体，保留状态码 */ }
        throw new Error(detail);
      }
      return res.json();
    },
    async postForm(path, formData) {
      const res = await fetch(path, { method: 'POST', body: formData });
      const body = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(body.error || body.detail || `${res.status} ${res.statusText}`);
      return body;
    },
    async del(path) {
      const res = await fetch(path, { method: 'DELETE' });
      if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
      return res.json();
    },
  };

  function debounce(fn, ms) {
    let timer = null;
    return (...args) => {
      clearTimeout(timer);
      timer = setTimeout(() => fn(...args), ms);
    };
  }

  const fmtNum = (n) => n === null || n === undefined ? '–' : Number(n).toLocaleString('zh-CN');
  const fmtBytes = (b) => {
    if (b === null || b === undefined) return '–';
    if (b < 1024) return `${b} B`;
    if (b < 1024 * 1024) return `${(b / 1024).toFixed(1)} KB`;
    return `${(b / 1024 / 1024).toFixed(1)} MB`;
  };
  const fmtDuration = (ms) => {
    if (ms === null || ms === undefined) return '–';
    if (ms < 1) return `${ms.toFixed(3)} ms`;
    if (ms < 1000) return `${ms.toFixed(1)} ms`;
    return `${(ms / 1000).toFixed(2)} s`;
  };
  /** 后端返回的是 UTC ISO 字符串，按本地时区显示。 */
  const fmtTime = (iso) => {
    if (!iso) return '–';
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return iso;
    const pad = (x) => String(x).padStart(2, '0');
    return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ` +
           `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
  };
  const fmtTimeShort = (iso) => {
    if (!iso) return '–';
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return iso;
    const pad = (x) => String(x).padStart(2, '0');
    return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
  };

  const SEV_LABEL = { critical: '严重', high: '高危', medium: '中危', low: '低危', info: '提示' };
  const SEV_ORDER = { info: 1, low: 2, medium: 3, high: 4, critical: 5 };

  let toastTimer = null;
  function toast(message, isError = false) {
    const node = $('#toast');
    node.textContent = message;
    node.classList.toggle('is-error', isError);
    node.classList.remove('is-hidden');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => node.classList.add('is-hidden'), isError ? 5000 : 2800);
  }

  // ---------------- 全局状态 ----------------

  const state = {
    view: 'dashboard',
    overview: null,
    rules: [],
    chains: [],
    events: { items: [], total: 0, limit: 50, offset: 0 },
    filters: {},
    drawerEventId: null,
  };

  // ---------------- 视图切换 ----------------

  function switchView(view) {
    state.view = view;
    $$('.tab').forEach((t) => t.classList.toggle('is-active', t.dataset.view === view));
    $$('.view').forEach((v) => v.classList.toggle('is-hidden', v.id !== `view-${view}`));
    closeDrawer();
    if (view === 'dashboard') loadOverview();
    if (view === 'events') loadEvents(0);
    if (view === 'chains') loadChains();
    if (view === 'rules') renderRules();
    if (view === 'import') loadBatches();
  }

  // ---------------- 健康检查 ----------------

  async function checkHealth() {
    const dot = $('#health-dot');
    const text = $('#health-text');
    try {
      await api.get('/api/health');
      dot.classList.add('is-ok');
      dot.classList.remove('is-down');
      text.textContent = '服务正常';
    } catch {
      dot.classList.add('is-down');
      dot.classList.remove('is-ok');
      text.textContent = '服务不可用';
    }
  }

  // ---------------- 概览 ----------------

  async function loadOverview() {
    try {
      const data = await api.get('/api/overview');
      state.overview = data;
      renderOverview(data);
      populateFacets(data);
    } catch (err) {
      toast(`加载概览失败：${err.message}`, true);
    }
  }

  function renderOverview(data) {
    $('#m-total').textContent = fmtNum(data.totalEvents);
    $('#m-alerts').textContent = fmtNum(data.alertedEvents);
    $('#m-critical').textContent = fmtNum(data.criticalEvents);
    $('#m-batches').textContent = fmtNum(data.batchCount);

    renderTimeline(data.timeline || []);

    const maxRule = Math.max(1, ...(data.ruleHits || []).map((r) => r.count));
    const ruleHost = $('#rule-hits');
    ruleHost.replaceChildren();
    if (!data.ruleHits || data.ruleHits.length === 0) {
      ruleHost.appendChild(el('span', { class: 'bar-empty', text: '暂无规则命中' }));
    } else {
      for (const rule of data.ruleHits) {
        ruleHost.appendChild(barRow(rule.name, `${rule.ruleId}`, rule.count, maxRule,
          rule.ruleId === 'R-001' || rule.ruleId === 'R-002' ? 'critical' : 'high'));
      }
    }

    renderFacetBars($('#account-facets'), data.accounts || [], '暂无账号数据');
    renderFacetBars($('#db-facets'), data.databases || [], '暂无数据库数据');
  }

  function barRow(name, sub, count, max, tone) {
    const pct = Math.max(2, Math.round((count / max) * 100));
    return el('div', { class: 'bar-row' }, [
      el('div', { class: 'bar-row-head' }, [
        el('span', { class: 'bar-name', title: name }, [
          name,
          sub ? el('span', { class: 'event-meta', text: `  ${sub}` }) : null,
        ]),
        el('span', { class: 'bar-count', text: fmtNum(count) }),
      ]),
      el('div', { class: 'bar-track' }, [
        el('div', { class: `bar-fill bar-fill--${tone || 'default'}`, style: `width:${pct}%` }),
      ]),
    ]);
  }

  function renderFacetBars(host, facets, emptyText) {
    host.replaceChildren();
    if (facets.length === 0) {
      host.appendChild(el('span', { class: 'bar-empty', text: emptyText }));
      return;
    }
    const max = Math.max(...facets.map((f) => f.count));
    for (const facet of facets.slice(0, 8)) {
      host.appendChild(barRow(facet.value, '', facet.count, max));
    }
  }

  function renderTimeline(timeline) {
    const host = $('#timeline');
    host.replaceChildren();
    if (timeline.length === 0) {
      host.appendChild(el('span', { class: 'bar-empty', text: '暂无数据' }));
      return;
    }

    const max = Math.max(1, ...timeline.map((d) => d.total));
    const chart = el('div', { class: 'timeline' });

    for (const bucket of timeline) {
      const totalH = Math.max(3, Math.round((bucket.total / max) * 100));
      // 告警叠加层高度按告警数占该桶总量的比例，最少 3% 以便可见
      const alertPct = bucket.alerts === 0 ? 0 : Math.max(3, (bucket.alerts / bucket.total) * 100);

      const bar = el('div', { class: 'tl-total', style: `height:${totalH}%` });
      if (alertPct > 0) {
        bar.appendChild(el('div', { class: 'tl-alert', style: `height:${alertPct}%` }));
      }

      chart.appendChild(el('div', {
        class: 'tl-col',
        title: `${formatBucketLabel(bucket.day)}\n全部事件 ${fmtNum(bucket.total)}\n告警 ${fmtNum(bucket.alerts)}`,
      }, [bar]));
    }

    host.appendChild(chart);
    host.appendChild(el('div', { class: 'tl-labels' }, [
      el('span', { text: formatBucketLabel(timeline[0].day) }),
      el('span', { text: `${timeline.length} 个时段` }),
      el('span', { text: formatBucketLabel(timeline[timeline.length - 1].day) }),
    ]));
  }

  /** "2026-11-14T03:00" → "11-14 03:00" */
  function formatBucketLabel(bucket) {
    if (!bucket) return '';
    const [date, time] = bucket.split('T');
    const md = date ? date.slice(5) : '';
    return time ? `${md} ${time}` : md;
  }

  function populateFacets(data) {
    fillSelect($('#f-account'), data.accounts.map((a) => a.value), '全部账号');
    fillSelect($('#f-database'), data.databases.map((d) => d.value), '全部数据库');
  }

  function fillSelect(select, values, placeholder) {
    const current = select.value;
    select.replaceChildren(el('option', { value: '', text: placeholder }));
    for (const v of values) select.appendChild(el('option', { value: v, text: v }));
    if (values.includes(current)) select.value = current;
  }

  // ---------------- 事件 ----------------

  function readFilters() {
    return {
      account: $('#f-account').value || undefined,
      database: $('#f-database').value || undefined,
      from: $('#f-from').value || undefined,
      to: $('#f-to').value || undefined,
      minSeverity: $('#f-severity').value || undefined,
      rules: $('#f-rules').value || undefined,
      text: $('#f-text').value.trim() || undefined,
      alertsOnly: $('#f-alerts-only').checked,
    };
  }

  function buildEventQuery(offset) {
    const f = state.filters;
    const params = new URLSearchParams();
    if (f.account) params.set('account', f.account);
    if (f.database) params.set('database', f.database);
    // datetime-local 给出的是本地时间，转成 UTC ISO 再传给后端
    if (f.from) params.set('from', new Date(f.from).toISOString());
    if (f.to) params.set('to', new Date(f.to).toISOString());
    if (f.minSeverity) params.set('minSeverity', f.minSeverity);
    if (f.rules) params.set('rules', f.rules);
    if (f.text) params.set('text', f.text);
    if (f.alertsOnly) params.set('alertsOnly', 'true');
    params.set('limit', '50');
    params.set('offset', String(offset));
    return `/api/events?${params.toString()}`;
  }

  async function loadEvents(offset = 0) {
    const list = $('#event-list');
    list.replaceChildren(el('div', { class: 'empty' }, [el('span', { class: 'spinner' }), ' 加载中…']));
    try {
      const data = await api.get(buildEventQuery(offset));
      state.events = data;
      renderEvents(data);
    } catch (err) {
      list.replaceChildren(el('div', { class: 'empty', text: `加载失败：${err.message}` }));
      toast(`加载事件失败：${err.message}`, true);
    }
  }

  function renderEvents(page) {
    const list = $('#event-list');
    list.replaceChildren();

    const start = page.total === 0 ? 0 : page.offset + 1;
    const end = Math.min(page.offset + page.items.length, page.total);
    $('#result-summary').textContent =
      page.total === 0 ? '没有匹配的事件' : `显示第 ${fmtNum(start)}–${fmtNum(end)} 条，共 ${fmtNum(page.total)} 条`;

    const totalPages = Math.max(1, Math.ceil(page.total / page.limit));
    const currentPage = Math.floor(page.offset / page.limit) + 1;
    $('#page-label').textContent = `${currentPage} / ${totalPages}`;
    $('#page-prev').disabled = page.offset <= 0;
    $('#page-next').disabled = page.offset + page.limit >= page.total;

    if (page.items.length === 0) {
      list.appendChild(el('div', { class: 'empty', text: '没有匹配的事件。试试放宽筛选条件，或取消“仅显示告警”。' }));
      return;
    }

    for (const item of page.items) {
      list.appendChild(eventCard(item));
    }
  }

  function eventCard(item) {
    const sev = item.maxSeverity;
    const sqlBlock = el('div', { class: 'event-sql' }, [item.statement || '（无 SQL，连接/管理事件）']);

    const card = el('article', {
      class: 'event-card',
      dataset: { sev, id: item.id },
      onclick: (evt) => {
        // 点击 SQL 块先展开/收起，而不是打开详情
        if (evt.target.closest('.event-sql') && item.statement && item.statement.length > 160) {
          sqlBlock.classList.toggle('is-expanded');
          return;
        }
        openEvent(item.id);
      },
    }, [
      el('div', { class: 'event-sev' }),
      el('div', { class: 'event-main' }, [
        el('div', { class: 'event-top' }, [
          el('span', { class: 'sev-tag', dataset: { sev }, text: SEV_LABEL[sev] || sev }),
          el('span', { class: 'event-ts', text: fmtTime(item.timestamp) }),
          el('span', { class: 'event-account', text: item.account || '（未知账号）' }),
          el('span', { class: 'event-meta', text: `@ ${item.clientHost || '未知来源'}` }),
          item.database ? el('span', { class: 'event-meta', text: `· ${item.database}` }) : null,
          el('span', { class: 'event-meta', text: `· ${item.sourceLabel}` }),
        ]),
        sqlBlock,
        item.ruleIds && item.ruleIds.length > 0
          ? el('div', { class: 'event-reasons' },
              item.ruleIds.map((id) => el('span', {
                class: `rule-chip rule-chip--${sev}`,
                text: ruleDisplayName(id),
              })))
          : null,
      ]),
      el('div', { class: 'event-side' }, [
        el('span', { class: 'risk-badge', dataset: { sev }, text: item.riskScore > 0 ? String(item.riskScore) : '—' }),
        el('span', { class: 'side-stat', text: '风险分' }),
        item.rowsReturned !== null && item.rowsReturned !== undefined
          ? el('span', { class: 'side-stat', text: `返回 ${fmtNum(item.rowsReturned)} 行` })
          : null,
        item.durationMs !== null && item.durationMs !== undefined
          ? el('span', { class: 'side-stat', text: fmtDuration(item.durationMs) })
          : null,
      ]),
    ]);

    if (!item.succeeded) card.querySelector('.event-top')
      .appendChild(el('span', { class: 'sev-tag', dataset: { sev: 'medium' }, text: `执行失败 ${item.errorCode || ''}` }));

    return card;
  }

  function ruleDisplayName(ruleId) {
    const rule = state.rules.find((r) => r.id === ruleId);
    return rule ? `${rule.id} ${rule.nameZh}` : ruleId;
  }

  // ---------------- 详情抽屉 ----------------

  async function openEvent(id) {
    state.drawerEventId = id;
    const drawer = $('#drawer');
    const body = $('#drawer-body');
    body.replaceChildren(el('div', { class: 'empty' }, [el('span', { class: 'spinner' }), ' 加载中…']));
    $('#drawer-title').textContent = `事件 #${id}`;
    drawer.classList.remove('is-hidden');
    $('#scrim').classList.remove('is-hidden');

    try {
      const item = await api.get(`/api/events/${id}`);
      renderDetail(item);
    } catch (err) {
      body.replaceChildren(el('div', { class: 'empty', text: `加载失败：${err.message}` }));
    }
  }

  function renderDetail(item) {
    const body = $('#drawer-body');
    body.replaceChildren();
    $('#drawer-title').textContent = `事件 #${item.id} · ${SEV_LABEL[item.maxSeverity] || ''}`;

    // 结论
    body.appendChild(el('section', { class: 'detail-section' }, [
      el('h3', { text: '判定结论' }),
      el('div', { class: 'kv-grid' }, [
        el('dt', { text: '风险分' }),
        el('dd', {}, [
          el('span', { class: 'risk-badge', dataset: { sev: item.maxSeverity }, text: String(item.riskScore) }),
          el('span', { text: `　${item.maxSeverityLabel}` }),
        ]),
        el('dt', { text: '命中类别' }),
        el('dd', { text: (item.categories || []).join('、') || '无' }),
      ]),
    ]));

    // 命中规则
    if (item.findings && item.findings.length > 0) {
      const findingsHost = el('section', { class: 'detail-section' }, [
        el('h3', { text: `命中规则（${item.findings.length}）` }),
      ]);
      for (const f of item.findings) {
        findingsHost.appendChild(el('div', { class: 'finding-item', dataset: { sev: f.severity } }, [
          el('div', { class: 'finding-head' }, [
            el('span', { class: 'rule-id-badge', text: f.ruleId }),
            el('span', { class: 'rule-name', text: f.ruleNameZh }),
            el('span', { class: 'sev-tag', dataset: { sev: f.severity }, text: f.severityLabel }),
          ]),
          el('div', { class: 'finding-msg', text: f.message }),
          f.evidence ? el('div', { class: 'finding-evidence', text: f.evidence }) : null,
        ]));
      }
      body.appendChild(findingsHost);
    }

    // SQL（带命中位置高亮）
    body.appendChild(el('section', { class: 'detail-section' }, [
      el('h3', { text: 'SQL 语句' }),
      buildSqlBlock(item),
    ]));

    // 上下文
    const kv = el('div', { class: 'kv-grid' });
    const add = (k, v) => {
      if (v === null || v === undefined || v === '') return;
      kv.appendChild(el('dt', { text: k }));
      kv.appendChild(el('dd', { text: String(v) }));
    };
    add('时间', fmtTime(item.timestamp));
    add('来源格式', item.sourceLabel);
    add('账号', item.account);
    add('客户端', item.clientHost);
    add('数据库', item.database);
    add('会话 / 线程', item.sessionId);
    add('实例', item.serverHost);
    add('命令标签', item.commandTag);
    add('返回行数', item.rowsReturned !== null ? fmtNum(item.rowsReturned) : null);
    add('影响行数', item.rowsAffected !== null ? fmtNum(item.rowsAffected) : null);
    add('耗时', item.durationMs !== null ? fmtDuration(item.durationMs) : null);
    add('执行结果', item.succeeded ? '成功' : `失败${item.errorCode ? `（${item.errorCode}）` : ''}`);
    add('源文件', item.sourceFile ? `${item.sourceFile}:${item.sourceLine}` : null);

    body.appendChild(el('section', { class: 'detail-section' }, [
      el('h3', { text: '事件上下文' }),
      kv,
    ]));

    if (item.rawRecord) {
      body.appendChild(el('section', { class: 'detail-section' }, [
        el('h3', { text: '原始日志记录' }),
        el('div', { class: 'sql-block', text: item.rawRecord }),
      ]));
    }
  }

  /** 按 finding 的 offset/length 高亮 SQL 中命中的片段。 */
  function buildSqlBlock(item) {
    const sql = item.statement || '';
    const block = el('div', { class: 'sql-block' });

    const ranges = (item.findings || [])
      .filter((f) => Number.isInteger(f.offset) && f.length > 0)
      .map((f) => [f.offset, f.offset + f.length])
      .sort((a, b) => a[0] - b[0]);

    // 合并重叠区间（同一条 SQL 可能被多个规则命中同一段）
    const merged = [];
    for (const [start, end] of ranges) {
      const last = merged[merged.length - 1];
      if (last && start <= last[1]) last[1] = Math.max(last[1], end);
      else merged.push([start, end]);
    }

    let cursor = 0;
    for (const [start, end] of merged) {
      const s = Math.max(0, Math.min(start, sql.length));
      const e = Math.max(s, Math.min(end, sql.length));
      if (s > cursor) block.appendChild(document.createTextNode(sql.slice(cursor, s)));
      if (e > s) block.appendChild(el('mark', { text: sql.slice(s, e) }));
      cursor = e;
    }
    if (cursor < sql.length) block.appendChild(document.createTextNode(sql.slice(cursor)));
    if (sql.length === 0) block.textContent = '（无 SQL）';
    return block;
  }

  function closeDrawer() {
    state.drawerEventId = null;
    $('#drawer').classList.add('is-hidden');
    $('#scrim').classList.add('is-hidden');
  }

  // ---------------- 攻击链 ----------------

  async function loadChains() {
    const host = $('#chain-list');
    host.replaceChildren(el('div', { class: 'empty' }, [el('span', { class: 'spinner' }), ' 加载中…']));
    try {
      const chains = await api.get('/api/chains');
      state.chains = chains;
      renderChains(chains);
    } catch (err) {
      host.replaceChildren(el('div', { class: 'empty', text: `加载失败：${err.message}` }));
    }
  }

  function renderChains(chains) {
    const host = $('#chain-list');
    host.replaceChildren();

    if (chains.length === 0) {
      host.appendChild(el('div', { class: 'empty', text: '未发现满足条件的攻击链。单条注入信号的聚合需要同一会话内至少两条不同注入规则命中，或出现严重级别事件。' }));
      return;
    }

    for (const chain of chains) {
      const stages = chain.stages || [];
      const stageFlow = el('div', { class: 'stage-flow' });
      stages.forEach((stage, idx) => {
        if (idx > 0) stageFlow.appendChild(el('span', { class: 'stage-arrow', text: '→' }));
        stageFlow.appendChild(el('span', { class: 'stage-pill', text: stage }));
      });

      host.appendChild(el('article', { class: 'chain-card', dataset: { sev: chain.maxSeverity } }, [
        el('div', { class: 'chain-head' }, [
          el('span', { class: 'chain-title', text: `${chain.account || '未知账号'} @ ${chain.clientHost || '未知来源'}` }),
          el('span', { class: 'sev-tag', dataset: { sev: chain.maxSeverity }, text: chain.maxSeverityLabel }),
          el('span', { class: 'chain-sub', text: `${fmtTime(chain.firstSeen)} → ${fmtTimeShort(chain.lastSeen)}` }),
          el('span', { class: 'chain-sub', text: `${chain.eventCount} 条事件 · 最高风险分 ${chain.maxRiskScore}` }),
          chain.database ? el('span', { class: 'chain-sub', text: `库 ${chain.database}` }) : null,
        ]),
        stages.length > 0 ? stageFlow : null,
        el('div', { class: 'chain-timeline' },
          chain.events.map((evt) => el('div', {
            class: 'chain-step',
            onclick: () => openEvent(evt.id),
            title: evt.statement,
          }, [
            el('span', { class: 'chain-step-time', text: fmtTimeShort(evt.timestamp) }),
            el('span', { class: 'chain-step-sql', text: evt.statement }),
            el('span', { class: 'chain-step-score', text: String(evt.riskScore) }),
          ]))),
      ]));
    }
  }

  // ---------------- 规则 ----------------

  async function loadRules() {
    try {
      state.rules = await api.get('/api/rules');
      const select = $('#f-rules');
      const current = select.value;
      select.replaceChildren(el('option', { value: '', text: '全部规则' }));
      for (const rule of state.rules) {
        select.appendChild(el('option', { value: rule.id, text: `${rule.id} ${rule.nameZh}` }));
      }
      select.value = current;
      if (state.view === 'rules') renderRules();
    } catch (err) {
      toast(`加载规则失败：${err.message}`, true);
    }
  }

  function renderRules() {
    const host = $('#rule-list');
    host.replaceChildren();

    if (state.rules.length === 0) {
      host.appendChild(el('div', { class: 'empty', text: '规则尚未加载。' }));
      return;
    }

    for (const rule of state.rules) {
      const desc = el('div', { class: 'rule-desc', text: rule.description });
      desc.style.display = 'none';

      const head = el('div', {
        class: 'rule-head',
        onclick: () => { desc.style.display = desc.style.display === 'none' ? '' : 'none'; },
      }, [
        el('span', { class: 'rule-id-badge', text: rule.id }),
        el('span', { class: 'rule-name', text: rule.nameZh }),
        el('span', { class: 'sev-tag', dataset: { sev: rule.defaultSeverity }, text: rule.defaultSeverityLabel }),
        el('span', { class: 'rule-category', text: rule.category }),
        el('span', { class: 'rule-hits', text: `本次数据命中 ${fmtNum(rule.hitCount)} 次` }),
      ]);

      host.appendChild(el('article', { class: 'rule-card' }, [head, desc]));
    }
  }

  // ---------------- 导入 ----------------

  let selectedFile = null;

  function setupImport() {
    const dropzone = $('#dropzone');
    const input = $('#file-input');
    const submit = $('#import-submit');

    const setFile = (file) => {
      selectedFile = file;
      if (file) {
        $('#dropzone-text').textContent = file.name;
        $('#dropzone-hint').textContent = `${fmtBytes(file.size)} · 点击可重新选择`;
        submit.disabled = false;
      } else {
        $('#dropzone-text').textContent = '点击选择或拖拽日志文件到此处';
        $('#dropzone-hint').textContent = '单个文件最大 256 MB';
        submit.disabled = true;
      }
    };

    input.addEventListener('change', () => setFile(input.files?.[0] || null));

    ['dragenter', 'dragover'].forEach((evt) =>
      dropzone.addEventListener(evt, (e) => {
        e.preventDefault();
        dropzone.classList.add('is-over');
      }));
    ['dragleave', 'drop'].forEach((evt) =>
      dropzone.addEventListener(evt, (e) => {
        e.preventDefault();
        dropzone.classList.remove('is-over');
      }));
    dropzone.addEventListener('drop', (e) => {
      const file = e.dataTransfer?.files?.[0];
      if (file) {
        input.files = e.dataTransfer.files;
        setFile(file);
      }
    });

    $('#import-form').addEventListener('submit', async (e) => {
      e.preventDefault();
      if (!selectedFile) return;

      submit.disabled = true;
      submit.textContent = '导入中…';
      const resultHost = $('#import-result');
      resultHost.replaceChildren(el('div', { class: 'import-report' }, [
        el('span', { class: 'spinner' }), ' 正在解析并分析，大文件可能需要数十秒…',
      ]));

      try {
        const formData = new FormData();
        formData.append('file', selectedFile);
        formData.append('source', $('#import-source').value);
        const note = $('#import-note').value.trim();
        if (note) formData.append('note', note);

        const result = await api.postForm('/api/import', formData);
        renderImportResult(result);
        toast(`导入成功：${fmtNum(result.parsedEvents)} 条事件，${fmtNum(result.alertedEvents)} 条告警`);
        setFile(null);
        input.value = '';
        $('#import-note').value = '';
        await Promise.all([loadBatches(), loadRules(), loadOverview()]);
      } catch (err) {
        resultHost.replaceChildren(el('div', { class: 'import-report is-error', text: `导入失败：${err.message}` }));
        toast(`导入失败：${err.message}`, true);
      } finally {
        submit.disabled = !selectedFile;
        submit.textContent = '开始导入';
      }
    });
  }

  function renderImportResult(result) {
    const host = $('#import-result');
    const rows = el('dl', {}, [
      el('dt', { text: '识别格式' }),
      el('dd', { text: result.sourceLabel + (result.autoDetected ? '（自动识别）' : '') }),
      el('dt', { text: '解析事件' }),
      el('dd', { text: fmtNum(result.parsedEvents) }),
      el('dt', { text: '告警事件' }),
      el('dd', { text: fmtNum(result.alertedEvents) }),
      el('dt', { text: '严重事件' }),
      el('dd', { text: fmtNum(result.criticalEvents) }),
      el('dt', { text: '解析诊断' }),
      el('dd', { text: fmtNum(result.diagnosticCount) }),
      el('dt', { text: '耗时' }),
      el('dd', { text: fmtDuration(result.elapsedMs) }),
    ]);

    const children = [el('div', { text: `✓ 已导入批次 #${result.batchId}` }), rows];

    if (result.diagnostics && result.diagnostics.length > 0) {
      children.push(el('div', { style: 'margin-top:10px;color:var(--fg-muted);font-size:12px' }, [
        el('div', { text: `前 ${Math.min(result.diagnostics.length, 8)} 条解析诊断：` }),
        ...result.diagnostics.slice(0, 8).map((d) =>
          el('div', { style: 'font-family:var(--mono);font-size:11.5px', text: `第 ${d.line} 行：${d.message}` })),
      ]));
    }

    host.replaceChildren(el('div', { class: 'import-report' }, children));
  }

  async function loadBatches() {
    const host = $('#batch-list');
    try {
      const batches = await api.get('/api/batches');
      host.replaceChildren();
      if (batches.length === 0) {
        host.appendChild(el('div', { class: 'empty', text: '还没有导入任何日志。' }));
        return;
      }
      for (const b of batches) {
        host.appendChild(el('div', { class: 'batch-row' }, [
          el('span', { class: 'batch-name', text: b.fileName }),
          el('span', { class: 'batch-meta', text: b.sourceLabel }),
          b.autoDetected ? el('span', { class: 'batch-meta', text: '自动识别' }) : null,
          b.note ? el('span', { class: 'batch-meta', text: b.note }) : null,
          el('span', { class: 'batch-count', text: `${fmtNum(b.eventCount)} 事件 / ` }),
          el('span', { class: 'batch-count', text: `${fmtNum(b.alertCount)} 告警` }),
          el('span', { class: 'batch-meta', text: fmtBytes(b.fileSize) }),
          el('span', { class: 'batch-meta', text: fmtTime(b.importedAt) }),
          el('div', { class: 'batch-actions' }, [
            el('button', {
              class: 'btn btn--sm',
              text: '查看',
              onclick: () => {
                switchView('events');
                // 查看该批次：重置其它筛选，改按批次查询
                resetFilters();
                loadEventsByBatch(b.id, b.fileName);
              },
            }),
            el('button', {
              class: 'btn btn--sm btn--danger',
              text: '删除',
              onclick: () => deleteBatch(b.id, b.fileName),
            }),
          ]),
        ]));
      }
    } catch (err) {
      host.replaceChildren(el('div', { class: 'empty', text: `加载批次失败：${err.message}` }));
    }
  }

  async function deleteBatch(id, fileName) {
    if (!window.confirm(`确定删除批次 #${id}「${fileName}」及其全部事件吗？此操作不可撤销。`)) return;
    try {
      await api.del(`/api/batches/${id}`);
      toast(`已删除批次 #${id}`);
      await Promise.all([loadBatches(), loadOverview(), loadRules()]);
    } catch (err) {
      toast(`删除失败：${err.message}`, true);
    }
  }

  /** 按批次筛选事件（复用事件视图，但不写到筛选表单里，避免误导）。 */
  async function loadEventsByBatch(batchId, fileName) {
    const list = $('#event-list');
    list.replaceChildren(el('div', { class: 'empty' }, [el('span', { class: 'spinner' }), ' 加载中…']));
    try {
      const data = await api.get(`/api/events?batchId=${batchId}&limit=50&offset=0`);
      state.events = data;
      renderEvents(data);
      $('#result-summary').textContent =
        `批次 #${batchId}「${fileName}」：共 ${fmtNum(data.total)} 条事件`;
    } catch (err) {
      list.replaceChildren(el('div', { class: 'empty', text: `加载失败：${err.message}` }));
    }
  }

  // ---------------- 事件筛选交互 ----------------

  function resetFilters() {
    $('#filters').reset();
    $('#f-alerts-only').checked = true;
    state.filters = readFilters();
  }

  function setupEventFilters() {
    $('#filters').addEventListener('submit', (e) => {
      e.preventDefault();
      state.filters = readFilters();
      loadEvents(0);
    });

    $('#f-reset').addEventListener('click', () => {
      resetFilters();
      loadEvents(0);
    });

    $('#page-prev').addEventListener('click', () =>
      loadEvents(Math.max(0, state.events.offset - state.events.limit)));
    $('#page-next').addEventListener('click', () =>
      loadEvents(state.events.offset + state.events.limit));

    // 下拉变化即时查询，文本框回车或防抖查询
    ['#f-account', '#f-database', '#f-severity', '#f-rules', '#f-alerts-only'].forEach((sel) => {
      $(sel).addEventListener('change', () => {
        state.filters = readFilters();
        loadEvents(0);
      });
    });

    const debouncedSearch = debounce(() => {
      state.filters = readFilters();
      loadEvents(0);
    }, 420);
    $('#f-text').addEventListener('input', debouncedSearch);
  }

  // ---------------- 启动 ----------------

  function setupGlobal() {
    $$('.tab').forEach((tab) =>
      tab.addEventListener('click', () => switchView(tab.dataset.view)));

    $('#drawer-close').addEventListener('click', closeDrawer);
    $('#scrim').addEventListener('click', closeDrawer);
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') closeDrawer();
    });

    // 顶部状态每 30 秒刷新一次
    setInterval(checkHealth, 30000);
  }

  async function boot() {
    setupGlobal();
    setupEventFilters();
    setupImport();
    state.filters = readFilters();

    await checkHealth();
    await Promise.all([loadOverview(), loadRules()]);
  }

  document.addEventListener('DOMContentLoaded', boot);
})();
