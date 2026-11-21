// Fancy Stats — приём событий от приложений и страница статистики.
// Привязки: DB (D1 fancy-stats) и STATS_PASSWORD (пароль страницы).
// APP_TOKEN вшит в приложения, поэтому не секрет — храним прямо здесь.
// Приложения: vpn — Fancy VPN, bomzh — Бомж Файтинг.
// Страницы: /?app=vpn, /?app=bomzh, журнал ошибок /?app=vpn&view=errors (&type=…&dev=…)
const APP_TOKEN = "PosWdWkApno5R2NX8FIixb7lNNODT5Ty";

const DAY = 86400000;
const ERROR_DAYS = 30; // журнал ошибок хранится 30 дней
const EVENTS = {
  launch: "launches",
  banner_ok: "banner_shown",
  banner_fail: "banner_fail",
  reward_ok: "reward_shown",
  reward_fail: "reward_fail",
  connect_ok: "connects",
};
const APPS = { vpn: "Fancy VPN", bomzh: "Бомж Файтинг" };

// Типы ошибок: [название, относится к VPN]
const ERROR_TYPES = {
  register: ["Регистрация на сервере", true],
  connect: ["Не удалось подключиться", true],
  no_traffic: ["Сервер не отвечает", true],
  vpn_denied: ["Нет разрешения VPN", true],
  ad_reward: ["Ролик", false],
  ad_banner: ["Баннер", false],
};
const SERVERS = { "de-fra": "Франкфурт", "us-nyc": "Нью-Йорк" };

const SCHEMA = [
  `CREATE TABLE IF NOT EXISTS devices (
  app TEXT NOT NULL, id TEXT NOT NULL, version TEXT DEFAULT '',
  first_seen INTEGER DEFAULT 0, last_seen INTEGER DEFAULT 0,
  trial_until INTEGER DEFAULT 0, premium INTEGER DEFAULT 0,
  launches INTEGER DEFAULT 0, banner_shown INTEGER DEFAULT 0, banner_fail INTEGER DEFAULT 0,
  reward_shown INTEGER DEFAULT 0, reward_fail INTEGER DEFAULT 0,
  PRIMARY KEY (app, id))`,
  `CREATE TABLE IF NOT EXISTS errors (
  n INTEGER PRIMARY KEY AUTOINCREMENT, app TEXT NOT NULL, dev TEXT NOT NULL, t INTEGER NOT NULL,
  version TEXT DEFAULT '', type TEXT NOT NULL, server TEXT DEFAULT '', detail TEXT DEFAULT '',
  model TEXT DEFAULT '', android TEXT DEFAULT '')`,
  `CREATE INDEX IF NOT EXISTS errors_app_t ON errors (app, t)`,
];

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    if (req.method === "POST" && url.pathname === "/e") return collect(req, env);
    if (req.method === "GET" && url.pathname === "/") return stats(req, env, url);
    return new Response("not found", { status: 404 });
  },
};

let schemaReady = false;
async function ensureSchema(env) {
  if (schemaReady) return;
  for (const s of SCHEMA) await env.DB.prepare(s).run();
  // Новая колонка «Подключения» (у старой таблицы её нет)
  try { await env.DB.prepare("ALTER TABLE devices ADD COLUMN connects INTEGER DEFAULT 0").run(); } catch {}
  schemaReady = true;
}

const str = (v, n) => String(v ?? "").slice(0, n);

async function collect(req, env) {
  if (req.headers.get("X-App-Token") !== APP_TOKEN) return new Response("forbidden", { status: 403 });
  let b;
  try { b = await req.json(); } catch { return new Response("bad json", { status: 400 }); }
  const app = String(b.app || "");
  const id = String(b.id || "");
  const ping = b.ev === "ping";        // только обновить строку (покупка, версия), без счётчиков
  const isError = b.ev === "error";    // только в журнал ошибок
  const col = EVENTS[b.ev];
  if (!APPS[app] || !/^[0-9a-f]{64}$/.test(id) || (!col && !ping && !isError)) return new Response("bad", { status: 400 });
  await ensureSchema(env);
  const now = Date.now();
  const version = str(b.v, 20);
  const late = !!b.late; // ошибка, досланная при следующем запуске
  const stmts = [];

  if (b.err && ERROR_TYPES[b.err]) {
    const t = late ? Math.max(now - ERROR_DAYS * DAY, Math.min(Number(b.t) || now, now)) : now;
    stmts.push(env.DB.prepare(
      `INSERT INTO errors (app,dev,t,version,type,server,detail,model,android) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)`
    ).bind(app, id, t, version, b.err, str(b.server, 20), str(b.detail, 300), str(b.model, 60), str(b.android, 20)));
  }

  // Досланная ошибка — уже прошлое, строку телефона и счётчики не трогаем
  if (!isError && !late) {
    const trial = Math.max(0, Math.min(Number(b.trial_until) || 0, now + 365 * DAY));
    const premium = b.premium ? 1 : 0;
    const sql = ping
      ? `INSERT INTO devices (app,id,version,first_seen,last_seen,trial_until,premium)
         VALUES (?1,?2,?3,?4,?4,?5,?6)
         ON CONFLICT(app,id) DO UPDATE SET version=?3,last_seen=?4,trial_until=?5,premium=?6`
      : `INSERT INTO devices (app,id,version,first_seen,last_seen,trial_until,premium,${col})
         VALUES (?1,?2,?3,?4,?4,?5,?6,1)
         ON CONFLICT(app,id) DO UPDATE SET version=?3,last_seen=?4,trial_until=?5,premium=?6,${col}=${col}+1`;
    stmts.push(env.DB.prepare(sql).bind(app, id, version, now, trial, premium));
  }

  // Изредка чистим ошибки старше 30 дней
  if (Math.random() < 0.05) {
    stmts.push(env.DB.prepare("DELETE FROM errors WHERE t < ?1").bind(now - ERROR_DAYS * DAY));
  }
  if (stmts.length) await env.DB.batch(stmts);
  return new Response("ok");
}

function authorized(req, env) {
  const h = req.headers.get("Authorization") || "";
  if (!h.startsWith("Basic ") || !env.STATS_PASSWORD) return false;
  let decoded = "";
  try { decoded = atob(h.slice(6)); } catch { return false; }
  const pass = decoded.slice(decoded.indexOf(":") + 1);
  return pass === env.STATS_PASSWORD;
}

const esc = (s) => String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));

function ago(ms, now) {
  const m = Math.floor((now - ms) / 60000);
  if (m < 1) return "только что";
  if (m < 60) return `${m} мин назад`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h} ч назад`;
  return `${Math.floor(h / 24)} дн назад`;
}

// Время по Кызылорде (UTC+5): «21 ноя, 04:12»
const MONTHS = ["янв", "фев", "мар", "апр", "мая", "июн", "июл", "авг", "сен", "окт", "ноя", "дек"];
function when(ms) {
  const d = new Date(ms + 5 * 3600000);
  const p = (x) => String(x).padStart(2, "0");
  return `${d.getUTCDate()} ${MONTHS[d.getUTCMonth()]}, ${p(d.getUTCHours())}:${p(d.getUTCMinutes())}`;
}

// Колонки таблицы для каждого приложения: [заголовок, функция ячейки, числовая?]
const num = (k, bad) => (r) => `<td class="n ${bad && r[k] ? "bad" : ""}">${r[k] || 0}</td>`;
const COMMON_HEAD = [
  ["Код телефона", (r) => `<td class="mono">${esc(r.id.slice(0, 6))}</td>`],
  ["Версия", (r) => `<td>${esc(r.version)}</td>`],
  ["Последняя активность", (r, now) => `<td title="${new Date(r.last_seen).toISOString()}">${ago(r.last_seen, now)}</td>`],
];
const COLUMNS = {
  vpn: [
    ...COMMON_HEAD,
    ["Дней без рекламы", (r, now) => {
      const left = r.trial_until > now ? Math.ceil((r.trial_until - now) / DAY) : 0;
      const t = r.premium ? "—" : left > 0 ? left : "Смотрит рекламу";
      return `<td class="${left > 0 ? "" : "ad"}">${t}</td>`;
    }],
    ["Premium", (r) => `<td>${r.premium ? "★ да" : ""}</td>`],
    ["Запуски", num("launches"), 1],
    ["Подключения", num("connects"), 1],
    ["Ошибки VPN (30 дн)", (r) => r._vpnErr
      ? `<td class="n"><a class="bad" href="?app=vpn&view=errors&dev=${esc(r.id.slice(0, 6))}">${r._vpnErr}</a></td>`
      : `<td class="n">0</td>`, 1],
    ["Баннеры", num("banner_shown"), 1],
    ["Ошибки баннеров", num("banner_fail", true), 1],
    ["Ролики", num("reward_shown"), 1],
    ["Ошибки роликов", num("reward_fail", true), 1],
  ],
  bomzh: [
    ...COMMON_HEAD,
    ["Купил игру", (r) => `<td>${r.premium ? "★ да" : ""}</td>`],
    ["Запуски", num("launches"), 1],
    ["Ролики", num("reward_shown"), 1],
    ["Ошибки роликов", num("reward_fail", true), 1],
  ],
};

const STYLE = `
:root{--bg:#f6f6f8;--card:#fff;--text:#1a1a1f;--muted:#6b6b76;--line:#e4e4ea;--bad:#c62828;--ad:#7a4fd6;--link:#2a62d6;--chip:#ececf2}
@media (prefers-color-scheme:dark){:root{--bg:#121216;--card:#1c1c22;--text:#ececf1;--muted:#9a9aa6;--line:#2c2c35;--bad:#ff6b6b;--ad:#b38cff;--link:#7fa8ff;--chip:#2a2a33}}
body{margin:0;background:var(--bg);color:var(--text);font:14px/1.4 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
main{max-width:1280px;margin:0 auto;padding:16px}
h1{font-size:20px;margin:4px 0 12px}
nav{margin-bottom:10px;color:var(--muted)} nav a,td a{color:var(--link)} td a.bad{color:var(--bad)}
.kpi{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:12px}
.kpi div{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:8px 12px}
.kpi b{display:block;font-size:20px}.kpi span{color:var(--muted);font-size:12px}
.chips{display:flex;flex-wrap:wrap;gap:6px;margin-bottom:12px}
.chips a{padding:4px 10px;border-radius:999px;background:var(--chip);color:var(--text);text-decoration:none;font-size:13px}
.chips a.on{background:var(--link);color:#fff}
.wrap{overflow-x:auto;background:var(--card);border:1px solid var(--line);border-radius:10px}
table{border-collapse:collapse;width:100%}
th,td{padding:7px 10px;border-bottom:1px solid var(--line);text-align:left;white-space:nowrap}
td.wrapcell{white-space:normal;min-width:260px;max-width:460px;word-break:break-word}
th{font-size:12px;color:var(--muted);font-weight:600;position:sticky;top:0;background:var(--card)}
td.n,th.n{text-align:right;font-variant-numeric:tabular-nums}
.mono{font-family:ui-monospace,Menlo,Consolas,monospace}
.bad{color:var(--bad);font-weight:600}.ad{color:var(--ad)}
.muted{color:var(--muted);font-size:12px;margin-top:8px}`;

function page(title, nav, body) {
  return new Response(`<!doctype html><html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(title)}</title><style>${STYLE}</style></head><body><main>
<nav>${nav}</nav>${body}</main></body></html>`,
    { headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" } });
}

function navLinks(app, view) {
  const items = [["vpn", "", "Fancy VPN"], ["vpn", "errors", "Ошибки VPN"], ["bomzh", "", "Бомж Файтинг"]];
  return items.map(([a, v, name]) => {
    const on = a === app && v === view;
    const href = `?app=${a}${v ? `&view=${v}` : ""}`;
    return on ? `<b>${esc(name)}</b>` : `<a href="${href}">${esc(name)}</a>`;
  }).join(" · ");
}

async function stats(req, env, url) {
  if (!authorized(req, env)) {
    return new Response("Нужен пароль", {
      status: 401,
      headers: { "WWW-Authenticate": 'Basic realm="Fancy Stats", charset="UTF-8"' },
    });
  }
  await ensureSchema(env);
  const app = APPS[url.searchParams.get("app")] ? url.searchParams.get("app") : "vpn";
  if (url.searchParams.get("view") === "errors") return errorsPage(env, url, app);

  const { results } = await env.DB.prepare(
    "SELECT * FROM devices WHERE app=?1 ORDER BY last_seen DESC LIMIT 5000"
  ).bind(app).all();
  const now = Date.now();

  if (app === "vpn") {
    const vpnTypes = Object.keys(ERROR_TYPES).filter((k) => ERROR_TYPES[k][1]);
    const { results: ec } = await env.DB.prepare(
      `SELECT dev, COUNT(*) c FROM errors WHERE app=?1 AND t>=?2 AND type IN (${vpnTypes.map((_, i) => `?${i + 3}`).join(",")}) GROUP BY dev`
    ).bind(app, now - ERROR_DAYS * DAY, ...vpnTypes).all();
    const byDev = Object.fromEntries(ec.map((e) => [e.dev, e.c]));
    for (const r of results) r._vpnErr = byDev[r.id] || 0;
  }

  const sum = (k) => results.reduce((a, r) => a + (r[k] || 0), 0);
  const active1 = results.filter((r) => now - r.last_seen < DAY).length;
  const active7 = results.filter((r) => now - r.last_seen < 7 * DAY).length;
  const cols = COLUMNS[app];

  const kpi = [
    [results.length, "телефонов всего"],
    [active1, "активны за сутки"],
    [active7, "активны за 7 дней"],
    [sum("launches"), "запусков"],
  ];
  if (app === "vpn") {
    kpi.push([sum("connects"), "подключений"], [sum("_vpnErr"), "ошибок VPN за 30 дн"],
      [sum("banner_shown"), "баннеров показано"], [sum("reward_shown"), "роликов показано"],
      [sum("banner_fail") + sum("reward_fail"), "ошибок рекламы"]);
  } else {
    kpi.push([results.filter((r) => r.premium).length, "купили игру"], [sum("reward_shown"), "роликов показано"],
      [sum("reward_fail"), "ошибок роликов"]);
  }

  const head = cols.map(([t, , n]) => `<th${n ? ' class="n"' : ""}>${t}</th>`).join("");
  const rows = results.map((r) => `<tr>${cols.map(([, f]) => f(r, now)).join("")}</tr>`).join("");

  return page(`Статистика — ${APPS[app]}`, navLinks(app, ""), `
<h1>${esc(APPS[app])} — статистика по телефонам</h1>
<div class="kpi">${kpi.map(([v, t]) => `<div><b>${v}</b><span>${t}</span></div>`).join("")}</div>
<div class="wrap"><table style="min-width:${cols.length * 95}px">
<thead><tr>${head}</tr></thead>
<tbody>${rows || `<tr><td colspan="${cols.length}">Пока нет данных</td></tr>`}</tbody></table></div>
<p class="muted">Счётчики — за всё время, ошибки VPN — за 30 дней. Код телефона — первые 6 символов зашифрованного ID, настоящий ID не хранится.</p>`);
}

async function errorsPage(env, url, app) {
  const now = Date.now();
  const type = ERROR_TYPES[url.searchParams.get("type")] ? url.searchParams.get("type") : "";
  const group = ["vpn", "ads"].includes(url.searchParams.get("type")) ? url.searchParams.get("type") : "";
  const dev = /^[0-9a-f]{6}$/.test(url.searchParams.get("dev") || "") ? url.searchParams.get("dev") : "";

  const where = ["app=?1", "t>=?2"];
  const args = [app, now - ERROR_DAYS * DAY];
  if (type) { where.push(`type=?${args.length + 1}`); args.push(type); }
  if (group) {
    const ks = Object.keys(ERROR_TYPES).filter((k) => ERROR_TYPES[k][1] === (group === "vpn"));
    where.push(`type IN (${ks.map((_, i) => `?${args.length + 1 + i}`).join(",")})`);
    args.push(...ks);
  }
  if (dev) { where.push(`substr(dev,1,6)=?${args.length + 1}`); args.push(dev); }

  const { results } = await env.DB.prepare(
    `SELECT * FROM errors WHERE ${where.join(" AND ")} ORDER BY t DESC LIMIT 1000`
  ).bind(...args).all();
  const { results: counts } = await env.DB.prepare(
    `SELECT type, COUNT(*) c FROM errors WHERE app=?1 AND t>=?2 GROUP BY type`
  ).bind(app, now - ERROR_DAYS * DAY).all();
  const byType = Object.fromEntries(counts.map((c) => [c.type, c.c]));
  const total = counts.reduce((a, c) => a + c.c, 0);
  const groupSum = (vpn) => Object.keys(ERROR_TYPES).filter((k) => ERROR_TYPES[k][1] === vpn).reduce((a, k) => a + (byType[k] || 0), 0);

  const link = (t, label, on) => {
    const q = new URLSearchParams({ app, view: "errors" });
    if (t) q.set("type", t);
    if (dev) q.set("dev", dev);
    return `<a class="${on ? "on" : ""}" href="?${q}">${esc(label)}</a>`;
  };
  const chips = [
    link("", `Все · ${total}`, !type && !group),
    link("vpn", `Только VPN · ${groupSum(true)}`, group === "vpn"),
    link("ads", `Только реклама · ${groupSum(false)}`, group === "ads"),
    ...Object.entries(ERROR_TYPES).map(([k, [name]]) => link(k, `${name} · ${byType[k] || 0}`, type === k)),
  ].join("");

  const rows = results.map((e) => {
    const devCode = e.dev.slice(0, 6);
    const q = new URLSearchParams({ app, view: "errors", dev: devCode });
    if (type) q.set("type", type); else if (group) q.set("type", group);
    const [name, isVpn] = ERROR_TYPES[e.type] || [e.type, false];
    return `<tr>
      <td title="${new Date(e.t).toISOString()}">${when(e.t)}</td>
      <td class="mono"><a href="?${q}">${esc(devCode)}</a></td>
      <td>${esc(e.version)}</td>
      <td class="${isVpn ? "bad" : ""}">${esc(name)}</td>
      <td>${esc(SERVERS[e.server] || e.server)}</td>
      <td class="wrapcell mono">${esc(e.detail)}</td>
      <td>${esc(e.model)}${e.android ? `, Android ${esc(e.android)}` : ""}</td>
    </tr>`;
  }).join("");

  const devNote = dev
    ? `<p>Телефон <span class="mono"><b>${esc(dev)}</b></span> · <a href="?app=${app}&view=errors${type ? `&type=${type}` : group ? `&type=${group}` : ""}">показать все телефоны</a></p>`
    : "";

  return page(`Ошибки — ${APPS[app]}`, navLinks(app, "errors"), `
<h1>${esc(APPS[app])} — журнал ошибок</h1>
<div class="chips">${chips}</div>${devNote}
<div class="wrap"><table style="min-width:980px">
<thead><tr><th>Время (UTC+5)</th><th>Код телефона</th><th>Версия</th><th>Тип</th><th>Сервер</th><th>Подробности</th><th>Модель и Android</th></tr></thead>
<tbody>${rows || '<tr><td colspan="7">Ошибок нет</td></tr>'}</tbody></table></div>
<p class="muted">Ошибки хранятся ${ERROR_DAYS} дней. Нажмите на код телефона, чтобы увидеть только его ошибки. Ошибки, которые не удалось отправить сразу (например, VPN не пропускал трафик), приходят при следующем запуске приложения.</p>`);
}
