// Arihant Medicos — phone app.
// Reads the newest "[ARIHANT-ERP]" email in the Arihant Gmail account (read-only Google sign-in), unlocks its
// attachment with the phone data password (PBKDF2-SHA256 + AES-256-GCM, gzip inside — same as the ERP), and shows
// everything from it. The locked file is kept on the phone, so the app also works offline.
const GMAIL_SCOPE = 'https://www.googleapis.com/auth/gmail.readonly';
// Arihant's Google sign-in key (OAuth Client ID, project arihant-erp). Not a secret: it only works from this app's
// address and for the test users added in Google Cloud. Settings can override it on a phone.
const DEFAULT_CLIENT_ID = '593179465354-r7d1rf9b1v5orbqk2v1fa5891dp9rb62.apps.googleusercontent.com';
const QUERY = 'subject:"ARIHANT-ERP" filename:amz';
const LS = { file: 'am_file', meta: 'am_meta', pw: 'am_pw', client: 'am_client_id', hint: 'am_login_hint', purch: 'am_due_purchase' };
const ls = { get(k) { try { return localStorage.getItem(k); } catch { return null; } }, set(k, v) { try { localStorage.setItem(k, v); } catch (e) { toast('Phone storage is full: ' + e.message); } }, del(k) { try { localStorage.removeItem(k); } catch { /* ignore */ } } };
const S = { data: null, pw: null, token: null, tokenExp: 0, idx: null };
const $ = (s, r = document) => r.querySelector(s);
const esc = v => String(v ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const money = v => '₹' + Number(v || 0).toLocaleString('en-IN', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
const short = v => { const n = Number(v || 0), a = Math.abs(n); return a >= 1e7 ? '₹' + (n / 1e7).toFixed(2) + ' Cr' : a >= 1e5 ? '₹' + (n / 1e5).toFixed(2) + ' L' : '₹' + Math.round(n).toLocaleString('en-IN'); };
const num = v => Number(v || 0).toLocaleString('en-IN', { maximumFractionDigits: 2 });
const dmy = d => (d ? String(d).slice(0, 10).split('-').reverse().join('/') : '');
const app = () => $('#app');
function toast(m) { const t = document.createElement('div'); t.textContent = m; Object.assign(t.style, { position: 'fixed', left: '50%', bottom: '70px', transform: 'translateX(-50%)', background: '#1d2433', color: '#fff', padding: '9px 14px', borderRadius: '8px', zIndex: 99, maxWidth: '90vw', fontSize: '13px' }); document.body.appendChild(t); setTimeout(() => t.remove(), 4000); }

// ───────────── unlocking the file (same scheme as the ERP: server/services/phone_report.js) ─────────────
const b64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
async function unlock(text, pw) {
  if (!window.crypto?.subtle) throw new Error('This page must be opened over https (or on this computer) to unlock the data.');
  let e; try { e = JSON.parse(text); } catch { throw new Error('This is not an Arihant data file'); }
  if (e.app !== 'arihant-erp') throw new Error('This is not an Arihant data file');
  const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(pw), 'PBKDF2', false, ['deriveKey']);
  const key = await crypto.subtle.deriveKey({ name: 'PBKDF2', salt: b64(e.salt), iterations: e.iter, hash: 'SHA-256' }, base, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
  let plain;
  try { plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64(e.iv) }, key, b64(e.data)); } catch { throw new Error('Wrong password'); }
  const stream = new Blob([plain]).stream().pipeThrough(new DecompressionStream('gzip'));
  return JSON.parse(await new Response(stream).text());
}

// ───────────── Gmail (read-only) ─────────────
function loadGsi() {
  if (window.google?.accounts?.oauth2) return Promise.resolve();
  return new Promise((res, rej) => { const s = document.createElement('script'); s.src = 'https://accounts.google.com/gsi/client'; s.async = true; s.onload = res; s.onerror = () => rej(new Error('Could not reach Google — check the internet')); document.head.appendChild(s); });
}
async function token() {
  if (S.token && Date.now() < S.tokenExp - 60000) return S.token;
  const client = ls.get(LS.client) || DEFAULT_CLIENT_ID;
  if (!client) { location.hash = '#/settings'; throw new Error('Enter the Google Client ID in Settings first'); }
  await loadGsi();
  return new Promise((res, rej) => {
    const tc = google.accounts.oauth2.initTokenClient({
      client_id: client, scope: GMAIL_SCOPE, login_hint: ls.get(LS.hint) || undefined,
      callback: r => { if (r.error) return rej(new Error(r.error_description || r.error)); S.token = r.access_token; S.tokenExp = Date.now() + (Number(r.expires_in) || 3600) * 1000; res(S.token); },
      error_callback: e => rej(new Error(e?.type === 'popup_closed' ? 'Sign-in window was closed' : e?.message || 'Sign-in failed'))
    });
    tc.requestAccessToken({ prompt: '' });
  });
}
async function gmail(path, retry = true) {
  const t = await token();
  const r = await fetch('https://gmail.googleapis.com/gmail/v1/users/me/' + path, { headers: { Authorization: 'Bearer ' + t } });
  if (r.status === 401 && retry) { S.token = null; return gmail(path, false); }
  if (!r.ok) throw new Error('Gmail: ' + ((await r.json().catch(() => ({}))).error?.message || r.status));
  return r.json();
}
const header = (m, n) => m.payload?.headers?.find(h => h.name.toLowerCase() === n)?.value || '';
function findAttachment(part) { if (part.filename && /\.amz$/i.test(part.filename) && part.body?.attachmentId) return part; for (const p of part.parts || []) { const f = findAttachment(p); if (f) return f; } return null; }
async function messageFile(id) {
  const m = await gmail(`messages/${id}?format=full`);
  const a = findAttachment(m.payload);
  if (!a) throw new Error('No data file in this email');
  const att = await gmail(`messages/${id}/attachments/${a.body.attachmentId}`);
  const bin = atob(att.data.replace(/-/g, '+').replace(/_/g, '/'));
  return { text: decodeURIComponent(escape(bin)), meta: { subject: header(m, 'subject'), date: header(m, 'date'), id, source: 'gmail' } };
}
async function listReports(q = '', max = 20) {
  const r = await gmail(`messages?maxResults=${max}&q=${encodeURIComponent(QUERY + (q ? ' ' + q : ''))}`);
  const out = [];
  for (const x of r.messages || []) { const m = await gmail(`messages/${x.id}?format=metadata&metadataHeaders=Subject&metadataHeaders=Date`); out.push({ id: x.id, subject: header(m, 'subject'), date: header(m, 'date') }); }
  return out;
}
async function getLatest() {
  const list = await listReports('', 1);
  if (!list.length) throw new Error('No Arihant data email found in this Gmail account yet');
  return messageFile(list[0].id);
}

// ───────────── loading data ─────────────
async function useFile(text, meta, pw) {
  const data = await unlock(text, pw);
  S.data = data; S.pw = pw; S.idx = index(data);
  ls.set(LS.file, text); ls.set(LS.meta, JSON.stringify(meta || {}));
  return data;
}
async function refreshFromGmail(btn) {
  if (btn) { btn.disabled = true; btn.textContent = 'Getting…'; }
  try {
    const f = await getLatest();
    const pw = S.pw || ls.get(LS.pw);
    if (!pw) { ls.set(LS.file, f.text); ls.set(LS.meta, JSON.stringify(f.meta)); return passwordScreen(); }
    await useFile(f.text, f.meta, pw);
    toast('Latest data loaded: ' + f.meta.subject.replace('[ARIHANT-ERP] ', ''));
    route();
  } catch (e) { toast(e.message); if (btn) { btn.disabled = false; btn.textContent = '⟳'; } }
}
function index(d) {
  const by = (rows, k = 'p') => rows.reduce((m, r) => { (m.get(r[k]) || m.set(r[k], []).get(r[k])).push(r); return m; }, new Map());
  const p = new Map(d.parties.map(x => [x.id, x]));
  const prod = new Map((d.prod || []).map(x => [x.i, x]));
  const lByBill = new Map(), lByProd = new Map();
  for (const l of d.lines || []) { (lByBill.get(l[0]) || lByBill.set(l[0], []).get(l[0])).push(l); if (l[3]) (lByProd.get(l[3]) || lByProd.set(l[3], []).get(l[3])).push(l); }
  const daySales = new Map(), dayRec = new Map();
  for (const b of d.bills) daySales.set(b.d, (daySales.get(b.d) || 0) + b.a);
  for (const r of d.receipts) dayRec.set(r.d, (dayRec.get(r.d) || 0) + r.a);
  return { p, open: by(d.open), bills: by(d.bills), rec: by(d.receipts), pur: by(d.purchases), pay: by(d.payments), led: by(d.ledger), ledOpen: new Map(d.ledger_open.map(x => [x.p, x.b])),
    prod, lByBill, lByProd, daySales, dayRec };
}
// bill line: [bill id, date, party, product id, qty, free, rate, amount, net value (after discount, before GST), name (when not in the product list)]
const pname = l => (l[3] ? S.idx.prod.get(l[3])?.n || 'Item ' + l[3] : l[9] || 'Item');
// [10] = purchase cost of the line, the same figure the ERP's profit uses (null / missing = no cost known)
const hasLineCost = () => (S.data.lines || []).some(l => l.length > 10);
// cost of one unit: landing cost (purchase value ÷ all units received, free too), else the last purchase rate
const unitCost = p => (p ? p.lc || p.lr || 0 : 0);
const addD = (d, n) => { const x = new Date(d + 'T00:00:00Z'); x.setUTCDate(x.getUTCDate() + n); return x.toISOString().slice(0, 10); };
const daysBetween = (a, b) => Math.round((Date.parse(b + 'T00:00:00Z') - Date.parse(a + 'T00:00:00Z')) / 864e5);
const pct = (a, b) => (b > 0.5 ? Math.round((a - b) / b * 100) : null);
const pctTag = v => (v === null || v === undefined ? '' : `<span class="${v >= 0 ? 'green' : 'red'}">${v >= 0 ? '▲' : '▼'}${Math.abs(v)}%</span>`);
const hasLines = () => Array.isArray(S.data.lines);
const NOLINES = '<div class="alert">Product details need the latest ERP version on the shop PC (it adds bill lines to the data email). Bills and collections still show.</div>';
const tabsHtml = (list, tab) => `<div class="tabs">${list.map(([k, l]) => `<button data-tab="${k}" class="${tab === k ? 'on' : ''}">${l}</button>`).join('')}</div>`;
const wireTabs = (base, extra = '') => document.querySelectorAll('[data-tab]').forEach(b => (b.onclick = () => { location.hash = `${base}?tab=${b.dataset.tab}${extra}`; }));
// periods for analysis; prev = the same length just before (a month: last month, same dates)
const SPANS = [['7', '7 days'], ['30', '30 days'], ['month', 'This month'], ['90', '90 days'], ['fy', 'This FY']];
function span(k, m = null) {
  const d = S.data, t = d.today;
  if (k === 'custom' && m) { const from = m + '-01', end = addD(addD(from, 32).slice(0, 8) + '01', -1); return { k, from, to: end < t ? end : t, pfrom: null, pto: null, label: new Date(from).toLocaleDateString('en-IN', { month: 'long', year: 'numeric' }), days: daysBetween(from, end < t ? end : t) + 1 }; }
  if (k === 'month') { const from = d.month_start, pm = addD(from, -1).slice(0, 8) + '01'; const n = daysBetween(from, t); const pto = addD(pm, n) < from ? addD(pm, n) : addD(from, -1); return { k, from, to: t, pfrom: pm, pto, label: 'this month', days: n + 1 }; }
  if (k === 'fy') return { k, from: d.fy_start, to: t, pfrom: null, pto: null, label: 'this FY', days: daysBetween(d.fy_start, t) + 1 };
  const n = Number(k) || 30, from = addD(t, -(n - 1));
  return { k, from, to: t, pfrom: addD(from, -n), pto: addD(from, -1), label: `last ${n} days`, days: n };
}
const spanChips = (base, k, extra = '') => `<div class="chips">${SPANS.map(([x, l]) => `<a class="chip ${k === x ? 'on' : ''}" href="${base}${base.includes('?') ? '&' : '?'}s=${x}${extra}">${l}</a>`).join('')}</div>`;
// product-wise totals of the lines in a period: qty, free, value, bills, parties, approximate margin
function prodAgg(from, to, keep = null) {
  const m = new Map();
  for (const l of S.data.lines || []) {
    if (l[1] < from || l[1] > to || (keep && !keep(l))) continue;
    const k = l[3] || 'n:' + l[9];
    let x = m.get(k);
    if (!x) { const pr = l[3] ? S.idx.prod.get(l[3]) : null; x = { k, id: l[3], name: pname(l), co: pr?.co || '', pk: pr?.pk || '', q: 0, f: 0, a: 0, sale: 0, cost: 0, known: 0, bills: new Set(), parties: new Set() }; m.set(k, x); }
    x.q += l[4]; x.f += l[5]; x.a += l[7]; x.bills.add(l[0]); x.parties.add(l[2]);
    // margin: net sale value (after discount, before GST) − landing cost × every unit given (free units too)
    const uc = l[3] ? unitCost(S.idx.prod.get(l[3])) : 0;
    if (uc) { x.sale += l[8] ?? l[6] * l[4]; x.cost += uc * (l[4] + l[5]); x.known++; }
  }
  return [...m.values()].map(x => ({ ...x, nb: x.bills.size, np: x.parties.size, mg: x.known ? x.sale - x.cost : null, mgp: x.known && x.sale ? Math.round((x.sale - x.cost) / x.sale * 1000) / 10 : null }));
}
const mgTxt = x => (x.mg === null ? '' : `<span class="${x.mg < 0 ? 'red' : 'muted'}">margin ~${short(x.mg)}${x.mgp !== null ? ` (${x.mgp}%)` : ''}</span>`);
// small bar chart: [{label, v}]
const bars = (rows, f = short) => { const max = Math.max(1, ...rows.map(r => r.v)); return `<div class="bars">${rows.map(r => `<div class="bar" title="${esc(r.label)}: ${esc(f(r.v))}"><i style="height:${Math.max(2, Math.round(r.v / max * 100))}%"></i><span>${esc(r.label)}</span></div>`).join('')}</div>`; };

// ───────────── layout ─────────────
const NAV = [['#/home', '🏠', 'Home'], ['#/sales', '🧾', 'Sales'], ['#/collect', '💰', 'Collect'], ['#/due', '📋', 'Dues'], ['#/order', '🛒', 'Order'], ['#/stock', '💊', 'Stock']];
function frame(title, body, active) {
  const d = S.data, meta = JSON.parse(ls.get(LS.meta) || '{}');
  const ageH = d ? (Date.now() - new Date(String(d.generated_at).replace(' ', 'T')).getTime()) / 3600000 : 0;
  app().innerHTML = `<div class="top"><h1>${esc(title)}</h1><button data-refresh title="Get the latest data from Gmail">⟳</button><a class="topbtn" href="#/more" title="Parties, tracks, purchases, reports, settings">☰</a></div>
    ${d ? `<div class="asof ${ageH > 13 ? 'old' : ''}"><span>Data as of <b>${dmy(d.generated_at)} ${esc(String(d.generated_at).slice(11, 16))}</b>${d.fawin?.last_sync ? ` · FAWin sync ${esc(String(d.fawin.last_sync).slice(11, 16))}` : ''}</span><span>${meta.source === 'file' ? 'from file' : 'Gmail'}</span></div>` : ''}
    <main>${body}</main><nav class="nav">${NAV.map(([h, i, l]) => `<a href="${h}" class="${h === active ? 'on' : ''}"><span class="i">${i}</span>${l}</a>`).join('')}</nav>`;
  $('[data-refresh]').onclick = e => refreshFromGmail(e.target);
  window.scrollTo(0, 0);
}
const kpi = (l, v, s = '', c = '') => `<div class="kpi ${c}"><div class="l">${esc(l)}</div><div class="v">${v}</div>${s ? `<div class="s">${s}</div>` : ''}</div>`;
const sum = (rows, f = r => r.a) => rows.reduce((s, r) => s + (Number(f(r)) || 0), 0);
const modeKind = m => (/cash/i.test(m || '') ? 'cash' : /upi|g\s*pay|phone\s*pe|paytm/i.test(m || '') ? 'upi' : 'bank');
const DOC = { 3: 'Journal', 4: 'Bank entry', 6: 'Cash receipt', 11: 'Purchase', 12: 'Bill', 13: 'Purchase return', 14: 'Sales return', 16: 'Credit note', 18: 'Challan', 20: 'Expiry return', 22: 'Purchase order' };
function more(listEl, rows, render, step = 60) {
  let n = 0;
  const draw = () => { listEl.insertAdjacentHTML('beforeend', rows.slice(n, n + step).map(render).join('')); n += step; btn.classList.toggle('hidden', n >= rows.length); };
  const btn = document.createElement('div'); btn.className = 'more'; btn.innerHTML = `<button class="btn ghost sm">Show more</button>`;
  listEl.after(btn); btn.onclick = draw; listEl.innerHTML = ''; draw();
}

// ───────────── screens ─────────────
function home() {
  const d = S.data, I = S.idx, t = d.today, ms = d.month_start;
  const tb = d.bills.filter(b => b.d === t), tr = d.receipts.filter(r => r.d === t);
  const modes = tr.reduce((m, r) => { m[modeKind(r.m)] += r.a; return m; }, { cash: 0, bank: 0, upi: 0 });
  const lw = addD(t, -7), yd = addD(t, -1);
  const salesLw = I.daySales.get(lw) || 0, recLw = I.dayRec.get(lw) || 0;
  // month to date against last month on the same dates; projected month end at the current daily rate
  const M = span('month');
  const mtd = sum(d.bills.filter(b => b.d >= M.from)), lmtd = sum(d.bills.filter(b => b.d >= M.pfrom && b.d <= M.pto));
  const mcol = sum(d.receipts.filter(r => r.d >= M.from));
  const dim = new Date(Date.UTC(+t.slice(0, 4), +t.slice(5, 7), 0)).getUTCDate();
  const proj = M.days ? mtd / M.days * dim : 0;
  const recv = sum(d.open.filter(o => o.k === 's'), o => o.b), pay = sum(d.open.filter(o => o.k === 'p'), o => o.b);
  const over90 = sum(d.open.filter(o => o.k === 's' && o.age > 90), o => o.b);
  const expd = d.expiry.filter(x => x.dl < 0 && x.dl >= -365), oldExp = d.expiry.filter(x => x.dl < -365), near = d.expiry.filter(x => x.dl >= 0 && x.dl <= 90);
  const edToday = d.edits.filter(e => String(e.at).startsWith(t));
  const ck = d.fawin?.check, runs = d.fawin?.runs_today || [];
  // last 30 days of sales
  const days = Array.from({ length: 30 }, (_, k) => addD(t, k - 29)).map(x => ({ label: x.slice(8), v: I.daySales.get(x) || 0 }));
  // products
  let prodHtml = NOLINES, ins = [];
  if (hasLines()) {
    const pm = prodAgg(M.from, t).sort((a, b) => b.a - a.a);
    const pPrev = new Map(prodAgg(M.pfrom, M.pto).map(x => [x.k, x.a]));
    const co = [...pm.reduce((m, x) => m.set(x.co || '(no company)', (m.get(x.co || '(no company)') || 0) + x.a), new Map())].sort((a, b) => b[1] - a[1]).slice(0, 5);
    const ptoday = prodAgg(t, t).sort((a, b) => b.a - a.a).slice(0, 5);
    const mg = pm.filter(x => x.mg !== null), mgSale = sum(mg, x => x.sale), mgVal = sum(mg, x => x.mg);
    const rising = pm.filter(x => x.a > 5000 && (pPrev.get(x.k) || 0) >= 3000).map(x => ({ ...x, ch: pct(x.a, pPrev.get(x.k) || 0) })).filter(x => x.ch !== null).sort((a, b) => b.ch - a.ch);
    prodHtml = `<div class="kpis">${kpi('Products sold (month)', num(pm.length), `${num(sum(pm, x => x.q))} qty + ${num(sum(pm, x => x.f))} free`)}${kpi('Approx. margin (month)', mgSale ? short(mgVal) : '—', mgSale ? `${(mgVal / mgSale * 100).toFixed(1)}% · net sale − landing cost (free goods counted)` : '', 'g')}</div>
      ${ptoday.length ? `<h4>Today's top products</h4>${ptoday.map(x => prodRow(x)).join('')}` : ''}
      <h4>Top products this month</h4>${pm.slice(0, 8).map(x => prodRow(x, pctTag(pct(x.a, pPrev.get(x.k) || 0)))).join('')}
      <h4>Top companies this month</h4>${co.map(([n, v]) => `<a class="row" href="#/sales?tab=products&s=month&co=${encodeURIComponent(n)}"><span class="m">${esc(n)}</span><span class="r">${short(v)}</span></a>`).join('')}
      <div class="actions" style="margin-top:8px"><a class="btn ghost sm" href="#/sales?tab=products&s=month">All products →</a><a class="btn ghost sm" href="#/sales?tab=companies&s=month">Companies →</a></div>`;
    // insights
    if (pm[0]) ins.push(`Best seller this month: <a href="#/product/${pm[0].id}"><b>${esc(pm[0].name)}</b></a> ${short(pm[0].a)}`);
    if (rising[0] && rising[0].ch > 20) ins.push(`Growing fast: <a href="#/product/${rising[0].id}"><b>${esc(rising[0].name)}</b></a> ${pctTag(rising[0].ch)} vs last month`);
    const sold30 = new Set(prodAgg(addD(t, -29), t).filter(x => x.id).map(x => x.id));
    const outSelling = (d.prod || []).filter(p => p.q <= 0 && sold30.has(p.i)).length;
    if (outSelling) ins.push(`<a href="#/stock?tab=out"><b>${outSelling} products</b></a> sold in the last 30 days are <b class="red">out of stock</b> — <a href="#/order">make an order</a>`);
    const stopped = stoppedBuying().length;
    if (stopped) ins.push(`<a href="#/sales?tab=parties&s=30"><b>${stopped} regular customers</b></a> have not bought in the last 30 days`);
  }
  if (mtd && mcol / mtd < 0.7) ins.push(`Collections this month are only <b>${Math.round(mcol / mtd * 100)}%</b> of sales — <a href="#/collect?tab=follow">follow-up list</a>`);
  if (over90 > 0.5) ins.push(`<a href="#/due?age=90%2B"><b>${short(over90)}</b></a> is due for more than 90 days`);
  frame('Arihant Medicos', `
    ${runs.some(r => r.status !== 'ok') ? `<div class="alert r">⚠ A FAWin sync failed today: ${esc(runs.filter(r => r.status !== 'ok').map(r => String(r.started_at).slice(11, 16) + ' ' + (r.error || '')).join('; ').slice(0, 200))}</div>` : ''}
    ${ck && !ck.matched ? `<div class="alert r">⚠ Outstanding differs from FAWin: ERP ${money(ck.erp_receivable)} vs FAWin ${money(ck.fawin_receivable)}</div>` : ''}
    <div class="card"><h3>Today <span>${dmy(t)}</span></h3><div class="kpis">
      ${kpi('Sales', `<a href="#/sales?day=${t}">${short(sum(tb))}</a>`, `${tb.length} bills · ${pctTag(pct(sum(tb), salesLw))} vs last ${new Date(lw).toLocaleDateString('en-IN', { weekday: 'short' })}`, 'g')}
      ${kpi('Collection', `<a href="#/collect?s=today">${short(sum(tr))}</a>`, `cash ${short(modes.cash)} · bank ${short(modes.bank)} · UPI ${short(modes.upi)}`, 'g')}
      ${hasProfit() ? kpi('Profit', `<a href="#/profit?tab=bill&day=${t}">${pfTxt(pf(tb.filter(b => b.s !== undefined)))}</a>`, 'today, before GST', 'g') : ''}
      ${kpi('Purchases', short(sum(d.purchases.filter(x => x.d === t))), `yesterday's sales ${short(I.daySales.get(yd) || 0)}`)}${kpi('Payments made', short(sum(d.payments.filter(x => x.d === t))), `collection last ${new Date(lw).toLocaleDateString('en-IN', { weekday: 'short' })} ${short(recLw)}`)}</div></div>
    ${ins.length ? `<div class="card"><h3>Insights</h3><ul class="ins">${ins.map(x => `<li>${x}</li>`).join('')}</ul></div>` : ''}
    <div class="card"><h3>This month <span>${pctTag(pct(mtd, lmtd))} vs last month (same dates)</span></h3><div class="kpis">
      ${kpi('Sales so far', short(mtd), `last month same dates ${short(lmtd)}`, 'g')}${kpi('Projected month end', short(proj), `at ${short(M.days ? mtd / M.days : 0)} a day`)}
      ${hasProfit() ? kpi('Profit this month', `<a href="#/profit?tab=day">${pfTxt(pf(d.bills.filter(b => b.d >= M.from && b.s !== undefined)))}</a>`, 'sale value − purchase cost', 'g') : ''}
      ${kpi('Collected', short(mcol), mtd ? `${Math.round(mcol / mtd * 100)}% of sales` : '', mtd && mcol / mtd < 0.7 ? 'a' : 'g')}${kpi('This FY', short(sum(d.bills)), `collected ${short(sum(d.receipts))}`)}</div>
      <h4>Daily sales, last 30 days</h4>${bars(days)}</div>
    <div class="card"><h3>Product sales</h3>${prodHtml}</div>
    <div class="card"><h3>Money</h3><div class="kpis">
      ${kpi('Outstanding', `<a href="#/due">${short(recv)}</a>`, `${d.open.filter(o => o.k === 's').length} bills · over 90 days ${short(over90)}`, 'r')}${kpi('Payable', `<a href="#/purchases">${short(pay)}</a>`, 'FAWin open purchase bills', 'a')}</div></div>
    <div class="card"><h3>Tracks <a href="#/tracks">all →</a></h3>${trackTable(true)}</div>
    <div class="card"><h3>Alerts</h3>
      <a class="row" href="#/edits"><span class="m"><b>Changes in FAWin today</b><small>edited or deleted bills, with who did it</small></span><span class="r ${edToday.length ? 'amber' : ''}">${edToday.length}</span></a>
      <a class="row" href="#/stock?tab=expiry"><span class="m"><b>Expired in the last year</b><small>${expd.length} batches${oldExp.length ? ` · ${oldExp.length} older batches (probably leftovers) not counted` : ''}</small></span><span class="r red">${short(sum(expd, x => x.v))}</span></a>
      <a class="row" href="#/stock?tab=expiry"><span class="m"><b>Expiring within 90 days</b><small>${near.length} batches</small></span><span class="r amber">${short(sum(near, x => x.v))}</span></a></div>
    <div class="card"><h3>Sync today</h3>${runs.length ? runs.map(r => `<div class="row"><span class="m">${esc(String(r.started_at).slice(11, 16))} ${esc(r.trigger)}</span><span class="r ${r.status === 'ok' ? 'green' : 'red'}">${r.status === 'ok' ? '✓ OK' : esc(r.status)}</span></div>`).join('') : '<div class="muted">No sync yet today</div>'}</div>`, '#/home');
}
const prodRow = (x, extra = '') => `<a class="row" href="${x.id ? '#/product/' + x.id : '#/sales?tab=products'}"><span class="m"><b>${esc(x.name)}</b><small>${num(x.q)}${x.f ? ' + ' + num(x.f) + ' free' : ''} · ${x.nb} bills · ${x.np} parties ${mgTxt(x)}</small></span><span class="r">${short(x.a)}<div class="small">${extra}</div></span></a>`;
// customers who bought regularly (3+ bills in the 90 days before) but nothing in the last 30 days
// ───────────── profit (the ERP's figure per bill: s = sale value before GST, c = purchase cost of the batches sold) ─────────────
const hasProfit = () => S.data.bills.some(b => b.s !== undefined);
const pf = list => { const sale = sum(list, b => b.s || 0), cost = sum(list, b => b.c || 0); return { sale, cost, profit: sale - cost, pct: sale ? (sale - cost) / sale * 100 : null, n: list.length }; };
const pfTxt = x => `<b class="${x.profit < 0 ? 'red' : 'green'}">${short(x.profit)}</b>${x.pct !== null ? ` <span class="muted small">${x.pct.toFixed(1)}%</span>` : ''}`;
function profit(q) {
  const d = S.data, tab = q.tab || 'day';
  const T = [['bill', 'Bill-wise'], ['day', 'Day-wise'], ['month', 'Month-wise'], ['product', 'Product-wise']];
  if (!hasProfit()) { frame('Profit', NOLINES, '#/more'); return; }
  const withP = d.bills.filter(b => b.s !== undefined);
  const note = '<div class="muted small" style="margin:6px 2px">Profit = sale value before GST (after scheme and discount) − purchase cost of the batches sold, free goods counted. The same figure as the ERP\'s profit reports.</div>';
  if (tab === 'product') {
    // which product (or company) made how much: net sale value − purchase cost of each line, as in the ERP
    if (!hasLineCost()) { frame('Profit', tabsHtml(T, tab) + NOLINES, '#/more'); return wireTabs('#/profit'); }
    const P = span(q.s || 'month', q.m), by = q.by === 'company' ? 'company' : 'product';
    const m = new Map(); let noCost = 0;
    for (const l of d.lines) {
      if (l[1] < P.from || l[1] > P.to) continue;
      if (l[10] === null || l[10] === undefined) { noCost++; continue; }
      const pr = l[3] ? S.idx.prod.get(l[3]) : null;
      if (q.co && (pr?.co || '(no company)') !== q.co) continue;
      const k = by === 'company' ? pr?.co || '(no company)' : l[3] || 'n:' + l[9];
      const x = m.get(k) || m.set(k, { k, id: by === 'product' ? l[3] : null, name: by === 'company' ? k : pname(l), co: pr?.co || '', sale: 0, cost: 0, q: 0, f: 0, bills: new Set(), n: 0 }).get(k);
      x.sale += l[8]; x.cost += l[10]; x.q += l[4]; x.f += l[5]; x.bills.add(l[0]); x.n++;
    }
    const all = [...m.values()].map(x => ({ ...x, profit: x.sale - x.cost, pct: x.sale ? (x.sale - x.cost) / x.sale * 100 : null, nb: x.bills.size }));
    const so = q.sort || 'high';
    const extra = `&s=${P.k}${q.m ? '&m=' + q.m : ''}&by=${by}${q.co ? '&co=' + encodeURIComponent(q.co) : ''}`;
    frame('Profit', `${tabsHtml(T, tab)}${spanChips('#/profit?tab=product', P.k, `&by=${by}${q.co ? '&co=' + encodeURIComponent(q.co) : ''}`)}
      <div class="chips">${[['product', 'By product'], ['company', 'By company']].map(([k, l]) => `<a class="chip ${by === k ? 'on' : ''}" href="#/profit?tab=product&s=${P.k}&by=${k}">${l}</a>`).join('')}${q.co ? `<a class="chip on" href="#/profit?tab=product&s=${P.k}&by=product">✕ ${esc(q.co)}</a>` : ''}</div>
      <div class="filters"><input data-q placeholder="Find ${by}"><select data-sort>${[['high', 'Most profit first'], ['loss', 'Loss / least profit first'], ['pct', 'Highest margin %'], ['lowpct', 'Lowest margin %'], ['sale', 'Highest sale']].map(([k, l]) => `<option value="${k}" ${so === k ? 'selected' : ''}>${l}</option>`).join('')}</select></div>
      <div class="kpis" data-k style="margin-bottom:8px"></div><div class="card"><h3 data-h></h3><div class="list" data-list></div></div>
      <div class="muted small" style="margin:6px 2px">Profit = sale value before GST (after scheme and discount) − purchase cost of the batches sold, free goods counted — the same figure as the ERP's profit reports, so the products add up to the bill-wise total.${noCost ? ` ${noCost} lines with no purchase cost are left out.` : ''}</div>`, '#/more');
    wireTabs('#/profit');
    const draw = () => {
      const t = $('[data-q]').value.trim().toLowerCase(), o = $('[data-sort]').value;
      const rows = all.filter(x => !t || (x.name + ' ' + x.co).toLowerCase().includes(t));
      const key = { high: (a, b) => b.profit - a.profit, loss: (a, b) => a.profit - b.profit, pct: (a, b) => (b.pct ?? -1e9) - (a.pct ?? -1e9), lowpct: (a, b) => (a.pct ?? 1e9) - (b.pct ?? 1e9), sale: (a, b) => b.sale - a.sale }[o];
      rows.sort(key);
      const tot = pf([]); tot.sale = sum(rows, x => x.sale); tot.cost = sum(rows, x => x.cost); tot.profit = tot.sale - tot.cost; tot.pct = tot.sale ? tot.profit / tot.sale * 100 : null;
      const loss = rows.filter(x => x.profit < 0);
      $('[data-k]').innerHTML = `${kpi('Profit', pfTxt(tot), `${rows.length} ${by === 'company' ? 'companies' : 'products'} · ${P.label}`, tot.profit < 0 ? 'r' : 'g')}${kpi('Sale value', short(tot.sale), 'before GST')}
        ${kpi('Sold at a loss', num(loss.length), loss.length ? short(sum(loss, x => x.profit)) : '', loss.length ? 'r' : '')}${kpi('Best', rows.length ? short(Math.max(...rows.map(x => x.profit))) : '—', rows.length ? esc([...rows].sort((a, b) => b.profit - a.profit)[0].name) : '')}`;
      $('[data-h]').innerHTML = `<span>${rows.length} ${by === 'company' ? 'companies' : 'products'}</span><span>${dmy(P.from)} – ${dmy(P.to)}</span>`;
      more($('[data-list]'), rows, x => `<a class="row" href="${by === 'company' ? `#/profit?tab=product&s=${P.k}&by=product&co=${encodeURIComponent(x.k)}` : x.id ? '#/product/' + x.id : '#/profit?tab=product'}"><span class="m"><b>${esc(x.name)}</b><small>${by === 'company' ? '' : esc(x.co) + ' · '}${num(x.q)}${x.f ? ' + ' + num(x.f) + ' free' : ''} · ${x.nb} bills · sale ${short(x.sale)}</small></span><span class="r">${pfTxt(x)}</span></a>`);
      history.replaceState(null, '', `#/profit?tab=product${extra.replace(/&sort=[^&]*/, '')}&sort=${o}`);
    };
    $('[data-q]').oninput = draw; $('[data-sort]').onchange = draw; draw();
    return;
  }
  if (tab === 'bill') {
    let day = q.day || d.today;
    if (!q.day && !withP.some(b => b.d === day)) day = [...new Set(withP.map(b => b.d))].sort().pop() || day;
    const rows = withP.filter(b => b.d === day).map(b => ({ ...b, x: pf([b]) }));
    const so = q.sort || 'low';
    rows.sort(so === 'high' ? (a, b) => b.x.profit - a.x.profit : so === 'pct' ? (a, b) => (a.x.pct ?? 0) - (b.x.pct ?? 0) : (a, b) => a.x.profit - b.x.profit);
    const tot = pf(rows);
    frame('Profit', `${tabsHtml(T, tab)}${dayPicker('#/profit', day, '&tab=bill&sort=' + so)}
      <div class="kpis" style="margin-bottom:8px">${kpi('Profit', pfTxt(tot), `${rows.length} bills`, tot.profit < 0 ? 'r' : 'g')}${kpi('Sale value', short(tot.sale), 'before GST')}${kpi('Cost', short(tot.cost))}${kpi('Loss bills', num(rows.filter(r => r.x.profit < 0).length), '', 'r')}</div>
      <div class="chips">${[['low', 'Lowest profit first'], ['high', 'Highest profit first'], ['pct', 'Lowest %']].map(([k, l]) => `<a class="chip ${so === k ? 'on' : ''}" href="#/profit?tab=bill&day=${day}&sort=${k}">${l}</a>`).join('')}</div>
      <div class="card"><div class="list">${rows.map(b => { const p = S.idx.p.get(b.p); return `<a class="row" href="#/sales?day=${b.d}&q=${encodeURIComponent(b.n)}"><span class="m"><b>${esc(p?.name || '')}</b><small>Bill ${esc(b.n)} · sale ${short(b.s)} · cost ${short(b.c)}</small></span><span class="r">${pfTxt(b.x)}</span></a>`; }).join('') || '<div class="muted">No bills with products on this day</div>'}</div></div>${note}`, '#/more');
    wireTabs('#/profit');
    $('[data-day]').onchange = e => { location.hash = `#/profit?tab=bill&day=${e.target.value}&sort=${so}`; };
    return;
  }
  if (tab === 'day') {
    const P = span(q.s || 'month', q.m);
    const days = [...withP.filter(b => b.d >= P.from && b.d <= P.to).reduce((m, b) => m.set(b.d, (m.get(b.d) || []).concat(b)), new Map())].sort((a, b) => (a[0] < b[0] ? 1 : -1)).map(([dd, l]) => ({ d: dd, x: pf(l) }));
    const tot = pf(withP.filter(b => b.d >= P.from && b.d <= P.to));
    frame('Profit', `${tabsHtml(T, tab)}${spanChips('#/profit?tab=day', P.k)}
      <div class="kpis" style="margin-bottom:8px">${kpi('Profit', pfTxt(tot), `${tot.n} bills · ${P.label}`, tot.profit < 0 ? 'r' : 'g')}${kpi('Sale value', short(tot.sale), 'before GST')}${kpi('Average a day', short(days.length ? tot.profit / days.length : 0), `${days.length} billing days`)}${kpi('Best day', days.length ? short(Math.max(...days.map(x => x.x.profit))) : '—')}</div>
      ${days.length > 1 ? `<div class="card"><h3>Profit by day</h3>${bars([...days].reverse().map(x => ({ label: x.d.slice(8), v: Math.max(0, x.x.profit) })))}</div>` : ''}
      <div class="card"><div class="list">${days.map(x => `<a class="row" href="#/profit?tab=bill&day=${x.d}"><span class="m"><b>${new Date(x.d).toLocaleDateString('en-IN', { weekday: 'short', day: '2-digit', month: 'short' })}</b><small>${x.x.n} bills · sale ${short(x.x.sale)}</small></span><span class="r">${pfTxt(x.x)}</span></a>`).join('') || '<div class="muted">No bills</div>'}</div></div>${note}`, '#/more');
    return wireTabs('#/profit', `&s=${P.k}`);
  }
  const months = [...withP.reduce((m, b) => m.set(b.d.slice(0, 7), (m.get(b.d.slice(0, 7)) || []).concat(b)), new Map())].sort().map(([k, l]) => ({ k, x: pf(l) }));
  const tot = pf(withP);
  frame('Profit', `${tabsHtml(T, tab)}
    <div class="kpis" style="margin-bottom:8px">${kpi('Profit this FY', pfTxt(tot), `${tot.n} bills`, tot.profit < 0 ? 'r' : 'g')}${kpi('Sale value', short(tot.sale), 'before GST')}</div>
    ${months.length ? `<div class="card"><h3>Profit by month</h3>${bars(months.map(m => ({ label: m.k.slice(5), v: Math.max(0, m.x.profit) })))}</div>` : ''}
    <div class="card"><div class="tw"><table><thead><tr><th>Month</th><th class="n">Bills</th><th class="n">Sale</th><th class="n">Cost</th><th class="n">Profit</th><th class="n">%</th></tr></thead>
      <tbody>${months.map(m => `<tr><td><a href="#/profit?tab=day&s=custom&m=${m.k}">${new Date(m.k + '-01').toLocaleDateString('en-IN', { month: 'short', year: 'numeric' })}</a></td><td class="n">${m.x.n}</td><td class="n">${short(m.x.sale)}</td><td class="n">${short(m.x.cost)}</td><td class="n ${m.x.profit < 0 ? 'red' : ''}">${short(m.x.profit)}</td><td class="n">${m.x.pct === null ? '' : m.x.pct.toFixed(1)}</td></tr>`).join('')}</tbody>
      <tfoot><tr><td>FY</td><td class="n">${tot.n}</td><td class="n">${short(tot.sale)}</td><td class="n">${short(tot.cost)}</td><td class="n">${short(tot.profit)}</td><td class="n">${tot.pct === null ? '' : tot.pct.toFixed(1)}</td></tr></tfoot></table></div></div>${note}`, '#/more');
  wireTabs('#/profit');
}
function stoppedBuying() {
  const d = S.data, t = d.today, c30 = addD(t, -29), c120 = addD(t, -119);
  const recent = new Set(), before = new Map();
  for (const b of d.bills) { if (b.d >= c30) recent.add(b.p); else if (b.d >= c120) before.set(b.p, (before.get(b.p) || []).concat(b)); }
  return [...before].filter(([p, l]) => !recent.has(p) && l.length >= 3).map(([p, l]) => ({ p: S.idx.p.get(p), n: l.length, a: sum(l), last: l[l.length - 1].d })).filter(x => x.p).sort((a, b) => b.a - a.a);
}
function trackStats() {
  const d = S.data, ms = d.month_start, m = new Map();
  const get = name => m.get(name || '(no track)') || m.set(name || '(no track)', { name: name || '(no track)', parties: 0, due: 0, salesM: 0, salesY: 0, colM: 0, colY: 0 }).get(name || '(no track)');
  for (const p of d.parties) if (p.c) get(p.track).parties++;
  for (const o of d.open) if (o.k === 's') get(S.idx.p.get(o.p)?.track).due += o.b;
  for (const b of d.bills) { const g = get(S.idx.p.get(b.p)?.track); g.salesY += b.a; if (b.d >= ms) g.salesM += b.a; }
  for (const r of d.receipts) { const g = get(S.idx.p.get(r.p)?.track); g.colY += r.a; if (r.d >= ms) g.colM += r.a; }
  return [...m.values()].sort((a, b) => b.due - a.due);
}
function trackTable(top) {
  const rows = trackStats().filter(r => r.parties || r.due);
  const shown = top ? rows.slice(0, 6) : rows;
  return `<div class="tw"><table><thead><tr><th>Track</th><th class="n">Parties</th><th class="n">Due</th><th class="n">Sales (month)</th><th class="n">Collected (month)</th>${top ? '' : '<th class="n">Sales FY</th><th class="n">Collected FY</th>'}</tr></thead>
    <tbody>${shown.map(r => `<tr><td><a href="#/due?track=${encodeURIComponent(r.name)}">${esc(r.name)}</a></td><td class="n">${r.parties}</td><td class="n">${short(r.due)}</td><td class="n">${short(r.salesM)}</td><td class="n">${short(r.colM)}</td>${top ? '' : `<td class="n">${short(r.salesY)}</td><td class="n">${short(r.colY)}</td>`}</tr>`).join('')}</tbody>
    ${top ? '' : `<tfoot><tr><td>Total</td><td class="n">${sum(rows, r => r.parties)}</td><td class="n">${short(sum(rows, r => r.due))}</td><td class="n">${short(sum(rows, r => r.salesM))}</td><td class="n">${short(sum(rows, r => r.colM))}</td><td class="n">${short(sum(rows, r => r.salesY))}</td><td class="n">${short(sum(rows, r => r.colY))}</td></tr></tfoot>`}</table></div>`;
}
function tracks() { frame('Tracks', `<div class="card"><h3>Track-wise <span>tap a track for its due list</span></h3>${trackTable(false)}</div>`, '#/more'); }

function parties(q) {
  const d = S.data;
  const tr = [...new Set(d.parties.map(p => p.track).filter(Boolean))].sort();
  frame('Parties', `<div class="filters"><input data-q placeholder="Name, code, phone, GSTIN, town" value="${esc(q.q || '')}"><select data-t><option value="">All tracks</option>${tr.map(t => `<option ${q.track === t ? 'selected' : ''}>${esc(t)}</option>`).join('')}</select>
    <select data-k><option value="">Customers &amp; suppliers</option><option value="c" ${q.k === 'c' ? 'selected' : ''}>Customers</option><option value="s" ${q.k === 's' ? 'selected' : ''}>Suppliers</option><option value="due" ${q.k === 'due' ? 'selected' : ''}>Owing money</option></select></div>
    <div class="card"><div class="list" data-list></div></div>`, '#/parties');
  const draw = () => {
    const s = $('[data-q]').value.trim().toLowerCase(), t = $('[data-t]').value, k = $('[data-k]').value;
    const digits = s.replace(/\D/g, '');
    const rows = d.parties.filter(p => (!t || p.track === t) && (!k || (k === 'c' ? p.c : k === 's' ? p.s : p.due > 0.5))
      && (!s || (p.name + ' ' + p.code + ' ' + p.city + ' ' + p.gstin).toLowerCase().includes(s) || (digits.length >= 4 && (p.mobile + p.wa).replace(/\D/g, '').includes(digits))))
      .sort((a, b) => b.due - a.due || a.name.localeCompare(b.name));
    more($('[data-list]'), rows, p => `<a class="row" href="#/party/${p.id}"><span class="m"><b>${esc(p.name)}</b><small>${esc([p.track, p.city, p.mobile].filter(Boolean).join(' · '))}</small></span><span class="r">${p.due > 0.5 ? `<b class="red">${short(p.due)}</b>` : ''}${p.pay > 0.5 ? `<div class="amber small">pay ${short(p.pay)}</div>` : ''}</span></a>`);
    history.replaceState(null, '', '#/parties?' + new URLSearchParams(Object.entries({ q: $('[data-q]').value, track: t, k }).filter(([, v]) => v)).toString());
  };
  $('[data-q]').oninput = draw; $('[data-t]').onchange = draw; $('[data-k]').onchange = draw;
  draw();
}
function dueMessage(p, bills) {
  const total = sum(bills, b => b.b);
  return [`Dear *${p.name}*,`, '', `Your outstanding with us as on ${dmy(S.data.today)}:`, '',
    bills.map((b, i) => [`*${i + 1}) Bill No : ${b.n}*`, `   📅 Date : ${dmy(b.d)}`, `   💰 Bill Amount : ${money(b.a)}`, `   📌 Pending : *${money(b.b)}*`, `   ⏳ Age : ${b.age} days`].join('\n')).join('\n\n'),
    '', '━━━━━━━━━━━━', `*Total Due : ${money(total)}*`, '', 'Kindly arrange the payment. Please ignore if already paid.', `*${S.data.company || 'Arihant Medicos'}*`].join('\n');
}
const waLink = (p, text) => `https://wa.me/${p.wa || ''}?text=${encodeURIComponent(text)}`;
function party(id, q) {
  const I = S.idx, p = I.p.get(Number(id));
  if (!p) return frame('Party', '<div class="alert r">Party not found in this data</div>', '#/parties');
  const open = (I.open.get(p.id) || []).filter(o => o.k === 's'), openP = (I.open.get(p.id) || []).filter(o => o.k === 'p');
  const tab = q.tab || 'due';
  frame(p.name, `<div class="card"><div class="big">${esc(p.name)}</div><div class="muted">${esc([p.code, p.track, p.city].filter(Boolean).join(' · '))}</div>
      <div style="margin:6px 0">${p.mobile ? `📞 <a href="tel:${esc(p.mobile)}">${esc(p.mobile)}</a>` : '<span class="muted">no phone</span>'}${p.gstin ? ` · GSTIN ${esc(p.gstin)}` : ''}${p.cd ? ` · ${p.cd} days credit` : ''}${p.cl ? ` · limit ${short(p.cl)}` : ''}</div>
      <div>${p.abc ? `<span class="tag b">Sales ${esc(p.abc)}</span> ` : ''}${p.pc ? `<span class="tag ${p.pc === 'Risky' ? 'r' : p.pc === 'Slow' ? 'a' : 'g'}">${esc(p.pc)} payer</span> ` : ''}${p.lb ? `<span class="tag">last bill ${dmy(p.lb)}</span> ` : ''}${p.lr ? `<span class="tag">last payment ${dmy(p.lr)}</span>` : ''}</div>
      <div class="kpis" style="margin-top:8px">${kpi('Due (sales bills)', money(p.due), `${open.length} bills`, 'r')}${p.pay > 0.5 || openP.length ? kpi('Purchase bills open', money(p.pay), `${openP.length} bills`, 'a') : ''}</div>
      ${open.length ? `<div class="actions" style="margin-top:8px"><a class="btn wa" target="_blank" rel="noopener" href="${esc(waLink(p, dueMessage(p, open)))}">📲 Send due list on WhatsApp</a>${p.wa ? '' : '<span class="muted small">no WhatsApp number in the ERP: WhatsApp will ask whom to send to</span>'}</div>` : ''}</div>
    <div class="tabs">${[['due', 'Due bills'], ['ledger', 'Ledger'], ['bills', 'Bills'], ['prod', 'Products'], ['rec', 'Payments'], ...(p.s || openP.length ? [['pur', 'Purchases']] : [])].map(([k, l]) => `<button data-tab="${k}" class="${tab === k ? 'on' : ''}">${l}</button>`).join('')}</div><div class="card" data-body></div>`, '#/parties');
  document.querySelectorAll('[data-tab]').forEach(b => (b.onclick = () => { location.hash = `#/party/${p.id}?tab=${b.dataset.tab}`; }));
  const body = $('[data-body]');
  if (tab === 'due') body.innerHTML = billTable(open, 'Sales bills due') + (openP.length ? '<div style="height:10px"></div>' + billTable(openP, 'Purchase bills open (we owe)') : '');
  if (tab === 'ledger') {
    const ob = I.ledOpen.get(p.id) || 0; let bal = ob;
    const rows = (I.led.get(p.id) || []).map(e => { bal += e.dr - e.cr; return { ...e, bal }; });
    body.innerHTML = `<div class="tw"><table><thead><tr><th>Date</th><th>Particulars</th><th class="n">Debit</th><th class="n">Credit</th><th class="n">Balance</th></tr></thead><tbody>
      <tr><td>${dmy(S.data.fy_start)}</td><td>Opening balance</td><td></td><td></td><td class="n">${money(Math.abs(ob))} ${ob >= 0 ? 'Dr' : 'Cr'}</td></tr>
      ${rows.map(e => `<tr><td>${dmy(e.d)}</td><td>${esc(e.x || e.t + ' ' + (e.n || ''))}</td><td class="n">${e.dr ? money(e.dr) : ''}</td><td class="n">${e.cr ? money(e.cr) : ''}</td><td class="n">${money(Math.abs(e.bal))} ${e.bal >= 0 ? 'Dr' : 'Cr'}</td></tr>`).join('')}</tbody>
      <tfoot><tr><td></td><td>Closing</td><td class="n">${money(sum(rows, e => e.dr))}</td><td class="n">${money(sum(rows, e => e.cr))}</td><td class="n">${money(Math.abs(bal))} ${bal >= 0 ? 'Dr' : 'Cr'}</td></tr></tfoot></table></div>`;
  }
  if (tab === 'bills') { const rows = [...(I.bills.get(p.id) || [])].reverse(); body.innerHTML = `<div class="tw"><table><thead><tr><th>Date</th><th>Bill</th><th class="n">Amount</th><th class="n">Disc.</th><th>By</th></tr></thead><tbody>${rows.map(b => `<tr><td>${dmy(b.d)}</td><td>${esc(b.n)}</td><td class="n">${money(b.a)}</td><td class="n">${b.disc ? money(b.disc) : ''}</td><td class="muted">${esc(user(b.u))}</td></tr>`).join('')}</tbody><tfoot><tr><td></td><td>${rows.length} bills</td><td class="n">${money(sum(rows))}</td><td></td><td></td></tr></tfoot></table></div>`; }
  if (tab === 'prod') {
    // what this party buys: 90 days against the 90 before, and items they used to buy but not lately
    if (!hasLines()) { body.innerHTML = NOLINES; return; }
    const t = S.data.today, mine = l => l[2] === p.id;
    const now = prodAgg(addD(t, -89), t, mine).sort((a, b) => b.a - a.a), before = prodAgg(addD(t, -179), addD(t, -90), mine);
    const nowK = new Set(now.map(x => x.k)), lost = before.filter(x => !nowK.has(x.k)).sort((a, b) => b.a - a.a);
    const months = [...(I.bills.get(p.id) || []).reduce((m, b) => m.set(b.d.slice(0, 7), (m.get(b.d.slice(0, 7)) || 0) + b.a), new Map())].sort().map(([k, v]) => ({ label: k.slice(5), v }));
    body.innerHTML = `${months.length ? `<h3>Purchases from us by month (FY)</h3>${bars(months)}` : ''}<h3>Products, last 90 days <span>${short(sum(now, x => x.a))}</span></h3>${now.map(x => prodRow(x)).join('') || '<div class="muted">No product bills in 90 days</div>'}
      ${lost.length ? `<h3 style="margin-top:10px">Bought earlier, not in the last 90 days</h3>${lost.slice(0, 20).map(x => prodRow(x)).join('')}` : ''}`;
  }
  if (tab === 'rec') { const rows = [...(I.rec.get(p.id) || [])].reverse(); body.innerHTML = `<div class="tw"><table><thead><tr><th>Date</th><th>Mode</th><th class="n">Amount</th><th>Settled bills</th></tr></thead><tbody>${rows.map(r => `<tr><td>${dmy(r.d)}</td><td>${esc(r.m)}</td><td class="n">${money(r.a)}</td><td class="muted small">${r.st.map(([n, a]) => `${esc(n)}: ${money(a)}`).join(', ') || 'on account'}</td></tr>`).join('')}</tbody><tfoot><tr><td></td><td>${rows.length}</td><td class="n">${money(sum(rows))}</td><td></td></tr></tfoot></table></div>`; }
  if (tab === 'pur') { const rows = [...(I.pur.get(p.id) || [])].reverse(), pays = [...(I.pay.get(p.id) || [])].reverse(); body.innerHTML = `<h3>Purchase bills (FY)</h3><div class="tw"><table><thead><tr><th>Date</th><th>Bill</th><th class="n">Amount</th></tr></thead><tbody>${rows.map(b => `<tr><td>${dmy(b.d)}</td><td>${esc(b.n)}</td><td class="n">${money(b.a)}</td></tr>`).join('')}</tbody></table></div><h3 style="margin-top:10px">Payments made (FY)</h3><div class="tw"><table><tbody>${pays.map(r => `<tr><td>${dmy(r.d)}</td><td>${esc(r.m)}</td><td class="n">${money(r.a)}</td></tr>`).join('') || '<tr><td class="muted">none</td></tr>'}</tbody></table></div>`; }
}
const user = u => (u ? S.data.users?.[u] || `User ${u}` : '');
function billTable(rows, title) {
  if (!rows.length) return `<div class="muted">${esc(title)}: none</div>`;
  return `<h3>${esc(title)}</h3><div class="tw"><table><thead><tr><th>Date</th><th>Bill</th><th class="n">Amount</th><th class="n">Pending</th><th class="n">Age</th></tr></thead><tbody>
    ${rows.map(b => `<tr><td>${dmy(b.d)}</td><td>${esc(b.n)}</td><td class="n">${money(b.a)}</td><td class="n"><b>${money(b.b)}</b></td><td class="n ${b.age > 90 ? 'red' : b.age > 60 ? 'amber' : ''}">${b.age} d</td></tr>`).join('')}</tbody>
    <tfoot><tr><td></td><td>${rows.length} bills</td><td></td><td class="n">${money(sum(rows, b => b.b))}</td><td></td></tr></tfoot></table></div>`;
}
const AGES = { '': [0, 1e9], '0-30': [0, 30], '31-60': [31, 60], '61-90': [61, 90], '90+': [91, 1e9] };
function due(q) {
  const d = S.data, I = S.idx;
  const tr = [...new Set(d.parties.map(p => p.track).filter(Boolean))].sort();
  const purch = (q.pur ?? ls.get(LS.purch) ?? '1') === '1';
  frame('Due list', `<div class="filters"><select data-t><option value="">All tracks</option>${tr.map(t => `<option ${q.track === t ? 'selected' : ''}>${esc(t)}</option>`).join('')}</select>
      <select data-a>${Object.keys(AGES).map(k => `<option value="${k}" ${String(q.age || '') === k ? 'selected' : ''}>${k ? 'Oldest bill ' + k + ' days' : 'Any age'}</option>`).join('')}</select>
      <input data-min inputmode="numeric" placeholder="Min ₹" value="${esc(q.min || '')}"><input data-q placeholder="Party" value="${esc(q.q || '')}"></div>
    <label class="muted small" style="display:block;margin-bottom:8px"><input type="checkbox" data-pur ${purch ? 'checked' : ''}> Show purchase bills too (parties we also buy from, as in FAWin's due list)</label>
    ${q.track ? '' : `<details class="card"><summary><b>Track-wise totals</b> <span class="muted">tap a track</span></summary>${trackTable(false)}</details>`}
    <div class="filters"><select data-sort><option value="due">Highest due first</option><option value="old">Oldest bill first</option><option value="name">Name A–Z</option></select></div>
    <div class="card"><h3><span data-count></span><span data-total></span></h3><div class="list" data-list></div></div>`, '#/due');
  const draw = () => {
    const t = $('[data-t]').value, age = AGES[$('[data-a]').value], min = Number($('[data-min]').value) || 0, s = $('[data-q]').value.trim().toLowerCase(), pp = $('[data-pur]').checked;
    ls.set(LS.purch, pp ? '1' : '0');
    const rows = [];
    for (const [pid, list] of I.open) {
      const p = I.p.get(pid); if (!p) continue;
      if (t && p.track !== t) continue;
      if (s && !p.name.toLowerCase().includes(s)) continue;
      const sales = list.filter(o => o.k === 's'), purs = pp && p.c ? list.filter(o => o.k === 'p') : [];
      if (!sales.length && !purs.length) continue;
      const total = sum(sales, o => o.b), oldest = Math.max(0, ...sales.map(o => o.age));
      if (total < min || !(oldest >= age[0] && oldest <= age[1])) continue;
      rows.push({ p, sales, purs, total, ptotal: sum(purs, o => o.b), oldest });
    }
    const so = $('[data-sort]').value;
    rows.sort(so === 'old' ? (a, b) => b.oldest - a.oldest : so === 'name' ? (a, b) => a.p.name.localeCompare(b.p.name) : (a, b) => b.total - a.total);
    $('[data-count]').textContent = `${rows.length} parties`; $('[data-total]').textContent = short(sum(rows, r => r.total));
    more($('[data-list]'), rows, r => `<div class="row"><a class="m" href="#/party/${r.p.id}"><b>${esc(r.p.name)}</b><small>${esc([r.p.track, r.p.city].filter(Boolean).join(' · '))} · ${r.sales.length} bills · oldest <span class="${r.oldest > 90 ? 'red' : ''}">${r.oldest} d</span>${r.purs.length ? ` · <span class="amber">purchase ${short(r.ptotal)} (${r.purs.length})</span>` : ''}</small></a>
      <span class="r"><b class="red">${short(r.total)}</b><div>${r.sales.length ? `<a target="_blank" rel="noopener" href="${esc(waLink(r.p, dueMessage(r.p, r.sales)))}">📲 WhatsApp</a>` : ''}</div></span></div>`);
    history.replaceState(null, '', '#/due?' + new URLSearchParams(Object.entries({ track: t, age: $('[data-a]').value, min: $('[data-min]').value, q: $('[data-q]').value }).filter(([, v]) => v)).toString());
  };
  for (const sel of ['[data-t]', '[data-a]', '[data-pur]', '[data-sort]']) $(sel).onchange = draw;
  $('[data-min]').oninput = draw; $('[data-q]').oninput = draw;
  draw();
}
function periodRows(rows, q, key = 'd') {
  const d = S.data, p = q.p || 'today';
  const from = p === 'today' ? d.today : p === 'month' ? d.month_start : p === 'fy' ? d.fy_start : q.from || d.fy_start;
  const to = p === 'custom' ? q.to || d.today : d.today;
  return { p, from, to, rows: rows.filter(r => r[key] >= from && r[key] <= to) };
}
const periodChips = (base, q, p) => `<div class="chips">${[['today', 'Today'], ['month', 'This month'], ['fy', 'This FY']].map(([k, l]) => `<a class="chip ${p === k ? 'on' : ''}" href="${base}?p=${k}${q.q ? '&q=' + encodeURIComponent(q.q) : ''}">${l}</a>`).join('')}</div>`;
function dayPicker(base, day, extra = '') {
  const t = S.data.today;
  return `<div class="daypick"><a class="btn ghost sm" href="${base}?day=${addD(day, -1)}${extra}">◀</a><input type="date" data-day value="${day}" max="${t}"><a class="btn ghost sm ${day >= t ? 'dis' : ''}" href="${base}?day=${addD(day, 1)}${extra}">▶</a>${day !== t ? `<a class="btn ghost sm" href="${base}?day=${t}${extra}">Today</a>` : ''}</div>`;
}
function sales(q) {
  const d = S.data, I = S.idx, tab = q.tab || 'day';
  const T = [['day', 'Day-wise bills'], ['products', 'Products'], ['companies', 'Companies'], ['parties', 'Parties']];
  if (tab === 'day') {
    // the chosen day, or the latest day with bills
    let day = q.day || d.today;
    if (!q.day && !I.daySales.has(day)) day = [...I.daySales.keys()].filter(x => x <= d.today).sort().pop() || day;
    const rows = d.bills.filter(b => b.d === day).sort((a, b) => b.id - a.id);
    const s = (q.q || '').toLowerCase();
    const shown = rows.filter(b => !s || b.n.toLowerCase().includes(s) || (I.p.get(b.p)?.name || '').toLowerCase().includes(s) || (I.lByBill.get(b.id) || []).some(l => pname(l).toLowerCase().includes(s)));
    const pd = hasLines() ? prodAgg(day, day).sort((a, b) => b.a - a.a) : [];
    const byUser = rows.reduce((m, b) => { const k = user(b.u) || '—'; m[k] = (m[k] || 0) + b.a; return m; }, {});
    frame('Sales', `${tabsHtml(T, tab)}${dayPicker('#/sales', day)}
      <div class="kpis" style="margin-bottom:8px">${kpi(new Date(day).toLocaleDateString('en-IN', { weekday: 'long' }), short(sum(rows)), `${rows.length} bills · avg ${short(rows.length ? sum(rows) / rows.length : 0)}`, 'g')}
        ${kpi('Same day last week', short(I.daySales.get(addD(day, -7)) || 0), pctTag(pct(sum(rows), I.daySales.get(addD(day, -7)) || 0)))}${kpi('Discount + scheme', short(sum(rows, b => (b.disc || 0) + (b.sch || 0))))}${kpi('Products', num(pd.length), `${num(sum(pd, x => x.q))} qty + ${num(sum(pd, x => x.f))} free`)}</div>
      ${pd.length ? `<details class="card"><summary><b>Products sold this day</b> <span class="muted">${pd.length}</span></summary>${pd.map(x => prodRow(x)).join('')}</details>` : ''}
      ${Object.keys(byUser).length > 1 ? `<details class="card"><summary><b>By FAWin user</b></summary>${Object.entries(byUser).sort((a, b) => b[1] - a[1]).map(([k, v]) => `<div class="row"><span class="m">${esc(k)}</span><span class="r">${short(v)}</span></div>`).join('')}</details>` : ''}
      <div class="filters"><input data-q placeholder="Search bill no., party or product" value="${esc(q.q || '')}"></div>
      <div class="card"><h3><span>${shown.length} bills</span><span>tap a bill to see its products</span></h3><div class="list" data-list></div></div>`, '#/sales');
    wireTabs('#/sales');
    $('[data-day]').onchange = e => { location.hash = `#/sales?day=${e.target.value}`; };
    $('[data-q]').onchange = e => { location.hash = `#/sales?day=${day}&q=${encodeURIComponent(e.target.value)}`; };
    more($('[data-list]'), shown, b => billDetails(b), 40);
    return;
  }
  if (!hasLines() && tab !== 'parties') { frame('Sales', tabsHtml(T, tab) + NOLINES, '#/sales'); return wireTabs('#/sales'); }
  const P = span(q.s || '30');
  const keep = q.co ? (l => (S.idx.prod.get(l[3])?.co || '(no company)') === q.co) : null;
  if (tab === 'products') {
    const prev = new Map(P.pfrom ? prodAgg(P.pfrom, P.pto, keep).map(x => [x.k, x.a]) : []);
    const all = prodAgg(P.from, P.to, keep);
    const cos = [...new Set((S.data.prod || []).map(x => x.co).filter(Boolean))].sort();
    frame('Sales', `${tabsHtml(T, tab)}${spanChips('#/sales?tab=products', P.k, q.co ? '&co=' + encodeURIComponent(q.co) : '')}
      <div class="filters"><input data-q placeholder="Product" value="${esc(q.q || '')}"><select data-co><option value="">All companies</option>${cos.map(c => `<option ${q.co === c ? 'selected' : ''}>${esc(c)}</option>`).join('')}</select>
        <select data-sort>${[['a', 'Highest value'], ['q', 'Highest quantity'], ['mg', 'Highest margin'], ['mgp', 'Lowest margin %'], ['ch', 'Growing fastest'], ['dn', 'Falling most']].map(([k, l]) => `<option value="${k}" ${q.sort === k ? 'selected' : ''}>${l}</option>`).join('')}</select></div>
      <div class="kpis" data-k style="margin-bottom:8px"></div><div class="card"><h3 data-h></h3><div class="list" data-list></div></div>`, '#/sales');
    wireTabs('#/sales', `&s=${P.k}`);
    const draw = () => {
      const s = $('[data-q]').value.trim().toLowerCase(), so = $('[data-sort]').value;
      const rows = all.filter(x => !s || (x.name + ' ' + x.co).toLowerCase().includes(s)).map(x => ({ ...x, ch: pct(x.a, prev.get(x.k) || 0) }));
      const key = { a: x => -x.a, q: x => -(x.q + x.f), mg: x => -(x.mg ?? -1e12), mgp: x => (x.mgp ?? 1e9), ch: x => -(x.ch ?? -1e9), dn: x => (x.ch ?? 1e9) }[so];
      rows.sort((a, b) => key(a) - key(b));
      const mg = rows.filter(x => x.mg !== null);
      $('[data-k]').innerHTML = `${kpi('Sales', short(sum(rows, x => x.a)), `${rows.length} products · ${P.label}`, 'g')}${kpi('Quantity', num(sum(rows, x => x.q)), `+ ${num(sum(rows, x => x.f))} free`)}${kpi('Approx. margin', mg.length ? short(sum(mg, x => x.mg)) : '—', mg.length ? (sum(mg, x => x.mg) / Math.max(1, sum(mg, x => x.sale)) * 100).toFixed(1) + '%' : '')}${kpi('vs previous', P.pfrom ? pctTag(pct(sum(rows, x => x.a), sum([...prev.values()]))) : '—', P.pfrom ? `${dmy(P.pfrom)} – ${dmy(P.pto)}` : '')}`;
      $('[data-h]').innerHTML = `<span>${rows.length} products</span><span>${dmy(P.from)} – ${dmy(P.to)}</span>`;
      more($('[data-list]'), rows, x => prodRow(x, P.pfrom ? pctTag(x.ch) : ''));
    };
    $('[data-q]').oninput = draw; $('[data-sort]').onchange = draw;
    $('[data-co]').onchange = e => { location.hash = `#/sales?tab=products&s=${P.k}${e.target.value ? '&co=' + encodeURIComponent(e.target.value) : ''}`; };
    draw();
    return;
  }
  if (tab === 'companies') {
    const agg = list => list.reduce((m, x) => { const k = x.co || '(no company)'; const c = m.get(k) || m.set(k, { k, a: 0, q: 0, n: 0, mg: 0, sale: 0 }).get(k); c.a += x.a; c.q += x.q + x.f; c.n++; if (x.mg !== null) { c.mg += x.mg; c.sale += x.sale; } return m; }, new Map());
    const now = [...agg(prodAgg(P.from, P.to)).values()].sort((a, b) => b.a - a.a);
    const prev = P.pfrom ? agg(prodAgg(P.pfrom, P.pto)) : new Map();
    frame('Sales', `${tabsHtml(T, tab)}${spanChips('#/sales?tab=companies', P.k)}
      <div class="card"><h3><span>${now.length} companies</span><span>${short(sum(now, x => x.a))}</span></h3>${now.map(c => `<a class="row" href="#/sales?tab=products&s=${P.k}&co=${encodeURIComponent(c.k)}"><span class="m"><b>${esc(c.k)}</b><small>${c.n} products · ${num(c.q)} qty${c.sale ? ` · margin ~${(c.mg / c.sale * 100).toFixed(1)}%` : ''}</small></span><span class="r">${short(c.a)}<div class="small">${P.pfrom ? pctTag(pct(c.a, prev.get(c.k)?.a || 0)) : ''}</div></span></a>`).join('')}</div>`, '#/sales');
    wireTabs('#/sales', `&s=${P.k}`);
    return;
  }
  // parties: top buyers in the period, change against the period before, and regular customers who stopped buying
  const inP = (from, to) => d.bills.filter(b => b.d >= from && b.d <= to).reduce((m, b) => m.set(b.p, (m.get(b.p) || 0) + b.a), new Map());
  const now = inP(P.from, P.to), prev = P.pfrom ? inP(P.pfrom, P.pto) : new Map();
  const rows = [...now].map(([p, a]) => ({ p: I.p.get(p), a, ch: pct(a, prev.get(p) || 0) })).filter(x => x.p).sort((a, b) => b.a - a.a);
  const dropped = P.pfrom ? [...prev].filter(([p, a]) => !now.has(p) && a > 1000).map(([p, a]) => ({ p: I.p.get(p), a })).filter(x => x.p).sort((a, b) => b.a - a.a) : [];
  const stopped = stoppedBuying();
  frame('Sales', `${tabsHtml(T, tab)}${spanChips('#/sales?tab=parties', P.k)}
    ${stopped.length ? `<details class="card" open><summary><b class="red">Stopped buying</b> <span class="muted">${stopped.length} regular customers, no bill in 30 days</span></summary>${stopped.map(x => `<a class="row" href="#/party/${x.p.id}?tab=bills"><span class="m"><b>${esc(x.p.name)}</b><small>${esc(x.p.track || '')} · ${x.n} bills before · last ${dmy(x.last)}</small></span><span class="r">${short(x.a)}</span></a>`).join('')}</details>` : ''}
    ${dropped.length ? `<details class="card"><summary><b class="amber">Bought in the previous period, not in this one</b> <span class="muted">${dropped.length}</span></summary>${dropped.slice(0, 50).map(x => `<a class="row" href="#/party/${x.p.id}?tab=bills"><span class="m"><b>${esc(x.p.name)}</b><small>${esc(x.p.track || '')}</small></span><span class="r">${short(x.a)}</span></a>`).join('')}</details>` : ''}
    <div class="card"><h3><span>${rows.length} parties bought · ${P.label}</span><span>${short(sum(rows))}</span></h3><div class="list" data-list></div></div>`, '#/sales');
  wireTabs('#/sales', `&s=${P.k}`);
  more($('[data-list]'), rows, x => `<a class="row" href="#/party/${x.p.id}?tab=bills"><span class="m"><b>${esc(x.p.name)}</b><small>${esc([x.p.track, x.p.city].filter(Boolean).join(' · '))}${x.p.abc ? ' · ' + esc(x.p.abc) : ''}</small></span><span class="r">${short(x.a)}<div class="small">${P.pfrom ? pctTag(x.ch) : ''}</div></span></a>`);
}
function billDetails(b) {
  const p = S.idx.p.get(b.p), ls2 = S.idx.lByBill.get(b.id) || [];
  return `<details class="bill"><summary class="row"><span class="m"><b>${esc(p?.name || '')}</b><small>Bill ${esc(b.n)} · ${dmy(b.d)}${b.u ? ' · ' + esc(user(b.u)) : ''}${ls2.length ? ` · ${ls2.length} items` : ''}</small></span><span class="r">${money(b.a)}</span></summary>
    ${ls2.length ? `<div class="tw"><table><thead><tr><th>Product</th><th class="n">Qty</th><th class="n">Rate</th><th class="n">Amount</th></tr></thead><tbody>${ls2.map(l => `<tr><td>${l[3] ? `<a href="#/product/${l[3]}">${esc(pname(l))}</a>` : esc(pname(l))}</td><td class="n">${num(l[4])}${l[5] ? '+' + num(l[5]) : ''}</td><td class="n">${num(l[6])}</td><td class="n">${money(l[7])}</td></tr>`).join('')}</tbody></table></div>` : `<div class="muted small">${hasLines() ? 'No product lines for this bill' : 'Product lines need the latest ERP version'}</div>`}
    ${b.disc || b.sch ? `<div class="muted small">Discount ${money(b.disc)} · scheme ${money(b.sch)}</div>` : ''}<div class="actions" style="margin:6px 0"><a class="btn ghost sm" href="#/party/${b.p}?tab=bills">Party →</a></div></details>`;
}
// one product: stock, cover, last purchase, monthly sales, top buyers, recent bills
function product(id) {
  const d = S.data, I = S.idx, p = I.prod.get(Number(id));
  if (!p) return frame('Product', '<div class="alert r">Product not found in this data</div>', '#/sales');
  const ls2 = I.lByProd.get(p.i) || [], t = d.today;
  const sold = n => sum(ls2.filter(l => l[1] >= addD(t, -(n - 1))), l => l[4] + l[5]);
  const s30 = sold(30), s60 = sold(60), s90 = sold(90), avg = s90 / 90, cover = avg ? p.q / avg : null;
  const months = [...ls2.reduce((m, l) => m.set(l[1].slice(0, 7), (m.get(l[1].slice(0, 7)) || 0) + l[4] + l[5]), new Map())].sort().map(([k, v]) => ({ label: k.slice(5), v }));
  const buyers = [...ls2.filter(l => l[1] >= addD(t, -89)).reduce((m, l) => { const x = m.get(l[2]) || m.set(l[2], { q: 0, a: 0, n: 0 }).get(l[2]); x.q += l[4] + l[5]; x.a += l[7]; x.n++; return m; }, new Map())].map(([pid, x]) => ({ p: I.p.get(pid), ...x })).filter(x => x.p).sort((a, b) => b.a - a.a);
  const sup = p.ls ? I.p.get(p.ls) : null;
  const net = sum(ls2, l => l[8] ?? l[6] * l[4]), units = sum(ls2, l => l[4] + l[5]);
  const avgRate = units ? net / units : 0, uc = unitCost(p);
  frame(p.n, `<div class="card"><div class="big">${esc(p.n)}</div><div class="muted">${esc([p.pk, p.co].filter(Boolean).join(' · '))}${p.sc ? ` · <span class="tag r">Schedule ${esc(p.sc)}</span>` : ''}</div>
      <div class="kpis" style="margin-top:8px">${kpi('Stock', num(p.q), uc ? `value ~${short(Math.max(p.q, 0) * uc)}` : '', p.q <= 0 ? 'r' : '')}${kpi('Sold', num(s30), `30 days · ${num(s60)} in 60 · ${num(s90)} in 90`, 'g')}
        ${kpi('Stock lasts', cover === null ? '—' : cover < 1 ? 'under 1 day' : Math.round(cover) + ' days', `at ${num(avg)} a day (90-day average)`, cover !== null && cover < 15 ? 'r' : cover !== null && cover > 120 ? 'a' : '')}
        ${kpi('Last purchase', p.lr ? money(p.lr) : '—', sup ? `${esc(sup.name)}${p.ld ? ' · ' + dmy(p.ld) : ''}${p.lf ? ' · scheme ' + esc(p.lf) : ''}` : 'no purchase in the ERP data')}
        ${kpi('Net sale per unit', avgRate ? money(avgRate) : '—', 'after discount & free goods, before GST')}${kpi('Landing cost per unit', uc ? money(uc) : '—', uc && avgRate ? `margin ~${((avgRate - uc) / avgRate * 100).toFixed(1)}%${p.lc ? ' · free goods received counted' : ''}` : '', uc && avgRate < uc ? 'r' : '')}
        ${kpi('MRP', p.mrp ? money(p.mrp) : '—')}
        ${(() => { const c = ls2.filter(l => l[10] !== null && l[10] !== undefined); if (!c.length) return ''; const fy = c.filter(l => l[1] >= d.fy_start), x = pf([]); x.sale = sum(fy, l => l[8]); x.cost = sum(fy, l => l[10]); x.profit = x.sale - x.cost; x.pct = x.sale ? x.profit / x.sale * 100 : null; return kpi('Profit this FY', `<a href="#/profit?tab=product&s=fy">${pfTxt(x)}</a>`, `on ${short(x.sale)} sale, free goods counted`, x.profit < 0 ? 'r' : 'g'); })()}</div>
      ${(() => { const set = poSet(), r = poRow(p, set), ss = saleScheme(p.i); return `<div style="margin-top:8px">${p.lf ? `<span class="tag g">scheme received ${esc(p.lf)}</span> ` : ''}${ss ? `<span class="tag b">scheme given ${esc(ss)}</span> ` : ''}<span class="tag">regular sale ~${num(Math.round(r.monthly))}/month</span>${r.need ? ` <span class="tag a">suggested order ${r.need}</span>` : ''}</div>
        ${r.D.odd.length ? `<div class="alert" style="margin-top:6px">⚠ One-off big order${r.D.odd.length > 1 ? 's' : ''} in the last ${set.basis} days, left out of the regular sale: ${oddTxt(r).replace('one-off: ', '')}</div>` : ''}
        ${r.bigBuy ? `<div class="alert" style="margin-top:6px">⚠ Last purchase was ${num(r.bigBuy)} on ${dmy(p.ld)} — about ${Math.round(r.bigBuy / Math.max(r.monthly, 0.1))} months of regular sale. Probably bought for a party's order.</div>` : ''}`; })()}
      <div class="actions" style="margin-top:8px"><a class="btn" href="#/order?add=${p.i}">🛒 Add to purchase order</a>${sup ? `<a class="btn ghost" href="#/party/${sup.id}?tab=pur">Supplier →</a>` : ''}</div></div>
    ${months.length ? `<div class="card"><h3>Quantity sold by month</h3>${bars(months, num)}</div>` : ''}
    <div class="card"><h3><span>Top buyers (90 days)</span><span>${buyers.length} parties</span></h3>${buyers.slice(0, 15).map(x => `<a class="row" href="#/party/${x.p.id}?tab=bills"><span class="m"><b>${esc(x.p.name)}</b><small>${num(x.q)} qty · ${x.n} bills</small></span><span class="r">${short(x.a)}</span></a>`).join('') || '<div class="muted">No sales in 90 days</div>'}</div>
    <div class="card"><h3>Recent bills</h3><div class="tw"><table><thead><tr><th>Date</th><th>Party</th><th class="n">Qty</th><th class="n">Rate</th><th class="n">Amount</th></tr></thead><tbody>${[...ls2].reverse().slice(0, 30).map(l => `<tr><td>${dmy(l[1])}</td><td><a href="#/party/${l[2]}?tab=bills">${esc(I.p.get(l[2])?.name || '')}</a></td><td class="n">${num(l[4])}${l[5] ? '+' + num(l[5]) : ''}</td><td class="n">${num(l[6])}</td><td class="n">${money(l[7])}</td></tr>`).join('')}</tbody></table></div></div>`, '#/sales');
}
// ───────────── collection ─────────────
const CSPANS = [['today', 'Today'], ['7', '7 days'], ['30', '30 days'], ['month', 'This month'], ['fy', 'This FY']];
function collect(q) {
  const d = S.data, I = S.idx, tab = q.tab || 'day';
  const T = [['day', 'Day-wise'], ['parties', 'By party'], ['follow', 'Follow-up'], ...(d.track_cash ? [['track', 'Track cash']] : [])];
  const k = q.s || (tab === 'parties' ? '30' : 'today');
  const P = k === 'today' ? { k, from: d.today, to: d.today, label: 'today' } : span(k);
  const chips = `<div class="chips">${CSPANS.map(([x, l]) => `<a class="chip ${k === x ? 'on' : ''}" href="#/collect?tab=${tab}&s=${x}">${l}</a>`).join('')}</div>`;
  if (tab === 'day') {
    const rows = d.receipts.filter(r => r.d >= P.from && r.d <= P.to).sort((a, b) => (b.d > a.d ? 1 : b.d < a.d ? -1 : b.id - a.id));
    const m = rows.reduce((x, r) => { x[modeKind(r.m)] += r.a; return x; }, { cash: 0, bank: 0, upi: 0 });
    const days = [...rows.reduce((mm, r) => mm.set(r.d, (mm.get(r.d) || []).concat(r)), new Map())];
    frame('Collection', `${tabsHtml(T, tab)}${chips}
      <div class="kpis" style="margin-bottom:8px">${kpi('Collected', short(sum(rows)), `${rows.length} receipts · ${new Set(rows.map(r => r.p)).size} parties · ${P.label}`, 'g')}${kpi('Cash', short(m.cash))}${kpi('Bank', short(m.bank))}${kpi('UPI', short(m.upi))}</div>
      ${days.map(([day, list]) => { const mm = list.reduce((x, r) => { x[modeKind(r.m)] += r.a; return x; }, { cash: 0, bank: 0, upi: 0 }); return `<details class="card" ${days.length <= 3 ? 'open' : ''}><summary class="row"><span class="m"><b>${new Date(day).toLocaleDateString('en-IN', { weekday: 'short', day: '2-digit', month: 'short' })}</b><small>${list.length} receipts · cash ${short(mm.cash)} · bank ${short(mm.bank)} · UPI ${short(mm.upi)}</small></span><span class="r"><b>${short(sum(list))}</b></span></summary>
        ${list.map(r => { const pp = I.p.get(r.p); return `<a class="row" href="#/party/${r.p}?tab=rec"><span class="m"><b>${esc(pp?.name || '')}</b><small>${esc(r.m || '')}${pp?.track ? ' · ' + esc(pp.track) : ''}${r.st.length ? ' · bills ' + r.st.map(([n, a]) => `${esc(n)} ${short(a)}`).join(', ') : ' · on account'}</small></span><span class="r">${money(r.a)}</span></a>`; }).join('')}</details>`; }).join('') || '<div class="card muted">No collection in this period</div>'}`, '#/collect');
    return wireTabs('#/collect', `&s=${k}`);
  }
  if (tab === 'parties') {
    const g = new Map();
    for (const r of d.receipts) if (r.d >= P.from && r.d <= P.to) { const x = g.get(r.p) || g.set(r.p, { a: 0, n: 0, last: '' }).get(r.p); x.a += r.a; x.n++; if (r.d > x.last) x.last = r.d; }
    const sales = d.bills.filter(b => b.d >= P.from && b.d <= P.to).reduce((m, b) => m.set(b.p, (m.get(b.p) || 0) + b.a), new Map());
    const rows = [...g].map(([pid, x]) => ({ p: I.p.get(pid), ...x, s: sales.get(pid) || 0 })).filter(x => x.p).sort((a, b) => b.a - a.a);
    frame('Collection', `${tabsHtml(T, tab)}${chips}
      <div class="alert b">Collected from each party in the period, against what they bought in it. Payer type (Prompt / Average / Slow / Risky) is from average days to pay.</div>
      <div class="card"><h3><span>${rows.length} parties paid · ${P.label}</span><span>${short(sum(rows))}</span></h3><div class="list" data-list></div></div>`, '#/collect');
    wireTabs('#/collect', `&s=${k}`);
    more($('[data-list]'), rows, x => `<a class="row" href="#/party/${x.p.id}?tab=rec"><span class="m"><b>${esc(x.p.name)}</b><small>${x.n} receipts · last ${dmy(x.last)} · bought ${short(x.s)}${x.p.pc ? ` · <span class="tag ${x.p.pc === 'Risky' ? 'r' : x.p.pc === 'Slow' ? 'a' : 'g'}">${esc(x.p.pc)}</span>` : ''}</small></span><span class="r"><b>${short(x.a)}</b><div class="small ${x.p.due > 0.5 ? 'red' : 'muted'}">due ${short(x.p.due)}</div></span></a>`);
    return;
  }
  if (tab === 'track') {
    // cash brought in by a track as one amount (entered in the ERP); FAWin's party-wise cash receipts are allotted to it
    const rows = d.track_cash || [];
    const sus = sum(rows.filter(c => c.st !== 'cancelled'), c => c.sus);
    const ST = { matched: ['g', '✔ matched'], short: ['a', 'short'], over: ['r', 'over'], waiting: ['', 'waiting for FAWin'] };
    frame('Collection', `${tabsHtml(T, tab)}<div class="kpis" style="margin-bottom:8px">${kpi('Still in suspense', short(sus), 'cash received, not yet found in FAWin receipts', Math.abs(sus) > 1 ? 'r' : 'g')}${kpi('Collections (60 days)', num(rows.length), `${rows.filter(c => c.st !== 'matched').length} not matched`)}</div>
      <div class="card"><div class="list">${rows.map(c => `<div class="row"><span class="m"><b>${esc(c.t)}</b><small>${dmy(c.d)}${c.by ? ' · ' + esc(c.by) : ''} · ${short(c.a)} received · ${short(c.got)} in ${c.n} FAWin receipts</small></span><span class="r"><span class="tag ${ST[c.st]?.[0] || ''}">${ST[c.st]?.[1] || esc(c.st)}</span><div class="small ${Math.abs(c.sus) > 1 ? 'red' : 'muted'}">${Math.abs(c.sus) > 1 ? (c.sus > 0 ? short(c.sus) + ' to find' : short(-c.sus) + ' over') : ''}</div></span></div>`).join('') || '<div class="muted">No track cash collections in the last 60 days</div>'}</div></div>
      <div class="muted small" style="margin:6px 2px">Entered in the ERP (Cash & bank → Track cash). Party receipts of the track's parties entered in FAWin within 2 days are matched to it after each sync.</div>`, '#/collect');
    return wireTabs('#/collect');
  }
  // follow-up: parties with dues who have not paid for a while
  const gap = Number(q.gap || 30);
  const rows = d.parties.filter(p => p.c && p.due > 0.5 && (!p.lr || daysBetween(p.lr, d.today) >= gap)).map(p => {
    const open = (I.open.get(p.id) || []).filter(o => o.k === 's');
    return { p, open, oldest: Math.max(0, ...open.map(o => o.age)), since: p.lr ? daysBetween(p.lr, d.today) : null };
  }).sort((a, b) => b.p.due - a.p.due);
  const tr = [...new Set(rows.map(r => r.p.track).filter(Boolean))].sort();
  frame('Collection', `${tabsHtml(T, tab)}<div class="chips">${[15, 30, 45, 60, 90].map(x => `<a class="chip ${gap === x ? 'on' : ''}" href="#/collect?tab=follow&gap=${x}${q.track ? '&track=' + encodeURIComponent(q.track) : ''}">No payment ${x}+ days</a>`).join('')}</div>
    <div class="filters"><select data-t><option value="">All tracks</option>${tr.map(t => `<option ${q.track === t ? 'selected' : ''}>${esc(t)}</option>`).join('')}</select></div>
    <div class="card"><h3 data-h></h3><div class="list" data-list></div></div>`, '#/collect');
  wireTabs('#/collect');
  const draw = () => {
    const t = $('[data-t]').value, list = rows.filter(r => !t || r.p.track === t);
    $('[data-h]').innerHTML = `<span>${list.length} parties to call</span><span>${short(sum(list, r => r.p.due))}</span>`;
    more($('[data-list]'), list, r => `<div class="row"><a class="m" href="#/party/${r.p.id}"><b>${esc(r.p.name)}</b><small>${esc(r.p.track || '')} · ${r.since === null ? 'no payment this year' : `last paid ${dmy(r.p.lr)} (${r.since} d)`} · oldest bill ${r.oldest} d${r.p.mobile ? ' · 📞 ' + esc(r.p.mobile) : ''}</small></a>
      <span class="r"><b class="red">${short(r.p.due)}</b><div>${r.open.length ? `<a target="_blank" rel="noopener" href="${esc(waLink(r.p, dueMessage(r.p, r.open)))}">📲 Due list</a>` : ''}</div></span></div>`);
  };
  $('[data-t]').onchange = draw; draw();
}

// ───────────── purchase order (company-wise) ─────────────
// Suggested quantity = regular daily sale over the basis period × days of stock wanted − stock now.
// "Regular" leaves out one-off big orders: a bill with at least 4 times the usual quantity of that product that is
// also over a third of everything sold of it in the period (a party asked for a big lot once). Free goods count as
// sold (they leave the shelf). Quantities are kept on this phone until the order is marked sent.
const PO = { cart: 'am_po_cart', set: 'am_po_set', sent: 'am_po_sent' };
const poSet = () => ({ basis: 90, cover: 30, oneoff: false, scheme: true, ...JSON.parse(ls.get(PO.set) || '{}') });
const poCart = () => JSON.parse(ls.get(PO.cart) || '{}');
function demand(pid, from) {
  const per = new Map();
  for (const l of S.idx.lByProd.get(pid) || []) if (l[1] >= from) { const x = per.get(l[0]) || per.set(l[0], { d: l[1], p: l[2], u: 0 }).get(l[0]); x.u += l[4] + l[5]; }
  const bills = [...per.values()], T = sum(bills, b => b.u);
  if (!bills.length) return { T: 0, reg: 0, odd: [], n: 0 };
  const us = bills.map(b => b.u).sort((a, b) => a - b), med = bills.length === 2 ? us[0] : us[Math.floor(us.length / 2)];
  const odd = bills.length === 1 ? (T >= 10 ? bills : []) : bills.filter(b => b.u >= 4 * Math.max(med, 1) && b.u >= T / 3 && b.u >= 10);
  return { T, reg: T - sum(odd, b => b.u), odd, n: bills.length };
}
// the scheme usually given on sales of a product (most common qty+free in 90 days)
function saleScheme(pid) {
  const per = new Map(), from = addD(S.data.today, -89);
  for (const l of S.idx.lByProd.get(pid) || []) if (l[1] >= from) { const x = per.get(l[0]) || per.set(l[0], [0, 0]).get(l[0]); x[0] += l[4]; x[1] += l[5]; }
  const cnt = new Map(); for (const [q, f] of per.values()) if (f > 0 && q > 0) { const k = `${num(q)}+${num(f)}`; cnt.set(k, (cnt.get(k) || 0) + 1); }
  return [...cnt].sort((a, b) => b[1] - a[1])[0]?.[0] || '';
}
function poRow(p, set, cart = poCart()) {
  const D = demand(p.i, addD(S.data.today, -(set.basis - 1)));
  const used = set.oneoff ? D.T : D.reg, avg = used / set.basis, regAvg = D.reg / set.basis;
  const need = Math.max(0, Math.ceil(avg * set.cover - Math.max(p.q, 0)));
  // stock that came from a big one-off purchase: the last purchase covers 6 months or more of regular sale
  const bigBuy = p.lq && p.lq >= 30 && p.lq >= 6 * Math.max(regAvg * 30, 1) ? p.lq : 0;
  return { p, D, avg, need, qty: cart[p.i] || 0, cover: avg ? p.q / avg : null, bigBuy, monthly: regAvg * 30 };
}
const oddTxt = r => (r.D.odd.length ? `one-off: ${r.D.odd.map(b => `${num(b.u)} to ${esc(S.idx.p.get(b.p)?.name || 'a party')} (${dmy(b.d)})`).join(', ')}` : '');
function order(q) {
  const d = S.data, tab = q.tab || 'make';
  if (!hasLines()) return frame('Purchase order', NOLINES, '#/order');
  if (q.add) { const pr = S.idx.prod.get(Number(q.add)); const c = poCart(); if (pr) { const r = poRow(pr, poSet(), c); c[pr.i] = c[pr.i] || Math.max(r.need, 1); ls.set(PO.cart, JSON.stringify(c)); toast('Added to the order'); } location.replace(`#/order?co=${encodeURIComponent(pr?.co || '(no company)')}`); return; }
  if (tab === 'sent') return sentOrders();
  const set = poSet();
  if (q.co !== undefined) return companyOrder(q.co, set, q);
  const cart = poCart();
  const byCo = new Map();
  for (const p of d.prod || []) { const k = p.co || '(no company)'; (byCo.get(k) || byCo.set(k, []).get(k)).push(p); }
  const cos = [...byCo].map(([co, list]) => {
    const rows = list.map(p => poRow(p, set, cart));
    return { co, n: list.length, out: rows.filter(r => r.p.q <= 0 && r.D.reg > 0).length, sug: rows.filter(r => r.need > 0), draft: rows.filter(r => r.qty > 0), odd: rows.filter(r => r.D.odd.length).length, big: rows.filter(r => r.bigBuy).length };
  }).map(c => ({ ...c, sugV: sum(c.sug, r => r.need * (r.p.lr || 0)), draftV: sum(c.draft, r => r.qty * (r.p.lr || 0)) }))
    .sort((a, b) => b.draft.length - a.draft.length || b.out - a.out || b.sugV - a.sugV);
  frame('Purchase order', `${tabsHtml([['make', 'Company-wise'], ['sent', 'Sent orders']], tab)}
    <div class="card"><div class="filters">
      <select data-k="basis">${[60, 90].map(x => `<option value="${x}" ${set.basis === x ? 'selected' : ''}>Sales of last ${x} days</option>`).join('')}</select>
      <select data-k="cover">${[15, 30, 45, 60].map(x => `<option value="${x}" ${set.cover === x ? 'selected' : ''}>Keep ${x} days of stock</option>`).join('')}</select></div>
      <label class="muted small"><input type="checkbox" data-k="oneoff" ${set.oneoff ? 'checked' : ''}> Count one-off big orders as regular sale</label>
      <div class="muted small" style="margin-top:4px">Suggested = regular daily sale × days of stock − stock now. One-off big orders (a party taking 4× the usual quantity at once) are left out, and shown on the product.</div></div>
    <div class="filters"><input data-q placeholder="Find company"><select data-f><option value="">All companies</option><option value="need">Needing an order</option><option value="draft">With a draft</option></select></div>
    <div class="card"><h3 data-h></h3><div class="list" data-list></div></div>`, '#/order');
  wireTabs('#/order');
  document.querySelectorAll('[data-k]').forEach(el => (el.onchange = () => { const x = poSet(); x[el.dataset.k] = el.type === 'checkbox' ? el.checked : Number(el.value); ls.set(PO.set, JSON.stringify(x)); order(q); }));
  const draw = () => {
    const s = $('[data-q]').value.trim().toLowerCase(), f = $('[data-f]').value;
    const list = cos.filter(c => (!s || c.co.toLowerCase().includes(s)) && (!f || (f === 'need' ? c.sug.length : c.draft.length)));
    $('[data-h]').innerHTML = `<span>${list.length} companies</span><span>${cos.filter(c => c.draft.length).length} drafts</span>`;
    more($('[data-list]'), list, c => `<a class="row" href="#/order?co=${encodeURIComponent(c.co)}"><span class="m"><b>${esc(c.co)}</b><small>${c.n} products${c.out ? ` · <span class="red">${c.out} out of stock</span>` : ''}${c.sug.length ? ` · ${c.sug.length} to order` : ''}${c.odd ? ` · ${c.odd} one-off sales` : ''}${c.big ? ` · ${c.big} big buys` : ''}</small></span>
      <span class="r">${c.draft.length ? `<span class="tag b">draft ${c.draft.length}</span><div class="small">~${short(c.draftV)}</div>` : c.sug.length ? `~${short(c.sugV)}` : ''}</span></a>`);
  };
  $('[data-q]').oninput = draw; $('[data-f]').onchange = draw; draw();
}
function companyOrder(co, set, q) {
  const d = S.data, cart = poCart();
  const rows = (d.prod || []).filter(p => (p.co || '(no company)') === co).map(p => ({ ...poRow(p, set, cart), ss: saleScheme(p.i) }))
    .sort((a, b) => (b.p.q <= 0 && b.D.reg > 0) - (a.p.q <= 0 && a.D.reg > 0) || b.need - a.need || b.D.reg - a.D.reg || a.p.n.localeCompare(b.p.n));
  // suppliers this company's goods came from (most products first)
  const sup = [...rows.reduce((m, r) => (r.p.ls ? m.set(r.p.ls, (m.get(r.p.ls) || 0) + 1) : m), new Map())].sort((a, b) => b[1] - a[1]).map(([id]) => S.idx.p.get(id)).filter(Boolean);
  const view = q.v || 'all';
  frame(co, `<div class="card"><div class="big">${esc(co)}</div><div class="muted small">${rows.length} products · sales of last ${set.basis} days · keep ${set.cover} days of stock${set.oneoff ? '' : ' · one-off orders left out'}</div>
      <div class="actions" style="margin-top:8px"><button class="btn" data-draft>✨ Draft order for me</button><button class="btn ghost" data-clear>Clear quantities</button></div>
      <div class="muted small" style="margin-top:4px">"Draft order for me" fills the suggested quantity in every empty box; you can change any of them. Or type quantities yourself.</div></div>
    <div class="chips">${[['all', 'All products'], ['need', 'To order'], ['out', 'Out of stock'], ['odd', 'One-off / big buys'], ['dead', 'Not selling'], ['draft', 'In this order']].map(([k, l]) => `<a class="chip ${view === k ? 'on' : ''}" href="#/order?co=${encodeURIComponent(co)}&v=${k}">${l}</a>`).join('')}</div>
    <div class="filters"><input data-q placeholder="Find product"></div>
    <div class="card"><div class="polist" data-rows></div></div>
    <div class="card"><h3><span data-tot></span><span data-val></span></h3>
      <div class="filters"><select data-to>${sup.map(x => `<option value="${x.id}">${esc(x.name)}${x.wa ? '' : ' (no WhatsApp no.)'}</option>`).join('')}<option value="">Choose the contact in WhatsApp</option></select></div>
      <label class="muted small" style="display:block;margin-bottom:6px"><input type="checkbox" data-sch ${set.scheme ? 'checked' : ''}> Mention the last scheme received in the message</label>
      <textarea data-msg rows="8"></textarea>
      <div class="actions" style="margin-top:8px"><a class="btn wa" data-wa target="_blank" rel="noopener">📲 Send on WhatsApp</a><button class="btn ghost" data-copy>Copy</button><button class="btn green" data-done>Mark as sent</button></div>
      <div class="muted small" style="margin-top:6px">"Mark as sent" keeps a copy under Sent orders and clears these quantities.</div></div>
    <a class="btn ghost sm" href="#/order">◀ All companies</a>`, '#/order');
  const val = r => cart[r.p.i] || 0;
  const pick = { all: () => true, need: r => r.need > 0 || val(r) > 0, out: r => r.p.q <= 0, odd: r => r.D.odd.length || r.bigBuy, dead: r => r.p.q > 0 && !r.D.T, draft: r => val(r) > 0 }[view] || (() => true);
  const draw = () => {
    const s = $('[data-q]').value.trim().toLowerCase();
    const list = rows.filter(r => pick(r) && (!s || r.p.n.toLowerCase().includes(s)));
    $('[data-rows]').innerHTML = list.map(r => `<div class="porow ${r.p.q <= 0 && r.D.reg > 0 ? 'urgent' : ''}">
      <div class="m"><a href="#/product/${r.p.i}"><b>${esc(r.p.n)}</b></a> <span class="muted small">${esc(r.p.pk || '')}</span>
        <small>Stock <b class="${r.p.q <= 0 ? 'red' : ''}">${num(r.p.q)}</b> · sold ${num(r.D.T)} in ${set.basis} d (~${num(Math.round(r.monthly))}/month regular) · ${r.cover === null ? 'no regular sale' : `lasts ${Math.round(r.cover)} d`}${r.p.lr ? ` · ${money(r.p.lr)}` : ''}</small>
        ${r.D.odd.length ? `<small class="amber">⚠ ${oddTxt(r)}</small>` : ''}${r.bigBuy ? `<small class="amber">⚠ last purchase ${num(r.bigBuy)} (${dmy(r.p.ld)}) ≈ ${Math.round(r.bigBuy / Math.max(r.monthly, 0.1))} months of regular sale — bought for a party?</small>` : ''}</div>
      <div class="sch">${r.p.lf ? `<span class="tag g" title="scheme received on the last purchase">get ${esc(r.p.lf)}</span>` : ''}${r.ss ? `<span class="tag b" title="scheme usually given on sales">give ${esc(r.ss)}</span>` : ''}</div>
      <div class="q"><input class="qty" type="number" inputmode="numeric" min="0" data-id="${r.p.i}" value="${val(r) || ''}" placeholder="${r.need || ''}"><small>${r.need ? 'sugg. ' + r.need : ''}</small></div></div>`).join('') || '<div class="muted">No products here</div>';
    document.querySelectorAll('[data-id]').forEach(inp => (inp.oninput = () => { const c = poCart(); const v = Math.max(0, Number(inp.value) || 0); if (v) c[inp.dataset.id] = v; else delete c[inp.dataset.id]; ls.set(PO.cart, JSON.stringify(c)); if (v) cart[inp.dataset.id] = v; else delete cart[inp.dataset.id]; totals(); }));
    totals();
  };
  const totals = () => {
    const sel = rows.filter(r => val(r) > 0), to = sup.find(x => String(x.id) === $('[data-to]').value), withSch = $('[data-sch]').checked;
    $('[data-tot]').textContent = `${sel.length} items in this order`;
    $('[data-val]').textContent = '~' + short(sum(sel, r => val(r) * (r.p.lr || 0)));
    const msg = [`*Purchase Order — ${d.company || 'Arihant Medicos'}*`, `Company: ${co}`, ...(to ? [`To: ${to.name}`] : []), `Date: ${dmy(d.today)}`, '',
      ...sel.map((r, k) => `${k + 1}) ${r.p.n}${r.p.pk ? ' (' + r.p.pk + ')' : ''} — Qty *${num(val(r))}*${withSch && r.p.lf ? ` (sch ${r.p.lf})` : ''}`), '', `Total items: ${sel.length}`, 'Please send at the earliest and confirm availability / scheme.'].join('\n');
    $('[data-msg]').value = msg;
    $('[data-wa]').href = `https://wa.me/${to?.wa || ''}?text=${encodeURIComponent(msg)}`;
  };
  $('[data-q]').oninput = draw; $('[data-to]').onchange = totals;
  $('[data-sch]').onchange = () => { const x = poSet(); x.scheme = $('[data-sch]').checked; ls.set(PO.set, JSON.stringify(x)); totals(); };
  $('[data-draft]').onclick = () => { const c = poCart(); let n = 0; for (const r of rows) if (r.need > 0 && !c[r.p.i]) { c[r.p.i] = r.need; cart[r.p.i] = r.need; n++; } ls.set(PO.cart, JSON.stringify(c)); toast(n ? `${n} products filled — check and change as needed` : 'Nothing more to suggest for this company'); draw(); };
  $('[data-clear]').onclick = () => { const c = poCart(); for (const r of rows) { delete c[r.p.i]; delete cart[r.p.i]; } ls.set(PO.cart, JSON.stringify(c)); draw(); };
  $('[data-copy]').onclick = () => navigator.clipboard?.writeText($('[data-msg]').value).then(() => toast('Copied'), () => toast('Select the text and copy it'));
  $('[data-done]').onclick = () => {
    const sel = rows.filter(r => val(r) > 0);
    if (!sel.length) return toast('No quantities in this order');
    const to = sup.find(x => String(x.id) === $('[data-to]').value);
    const sent = JSON.parse(ls.get(PO.sent) || '[]');
    sent.unshift({ at: new Date().toISOString().slice(0, 16).replace('T', ' '), to: co + (to ? ' → ' + to.name : ''), wa: to?.wa || '', items: sel.map(r => [r.p.i, r.p.n, val(r), r.p.lr || 0]), msg: $('[data-msg]').value });
    ls.set(PO.sent, JSON.stringify(sent.slice(0, 200)));
    const c = poCart(); for (const r of rows) delete c[r.p.i]; ls.set(PO.cart, JSON.stringify(c));
    toast('Saved under Sent orders'); location.hash = '#/order?tab=sent';
  };
  draw();
}
function sentOrders() {
  const sent = JSON.parse(ls.get(PO.sent) || '[]');
  frame('Purchase order', `${tabsHtml([['make', 'Company-wise'], ['sent', 'Sent orders']], 'sent')}
    <div class="card"><h3>${sent.length} orders kept on this phone</h3>${sent.map((o, k) => `<details class="bill"><summary class="row"><span class="m"><b>${esc(o.to)}</b><small>${esc(o.at)} · ${o.items.length} items</small></span><span class="r">~${short(sum(o.items, x => x[2] * x[3]))}</span></summary>
      <pre class="msg">${esc(o.msg)}</pre><div class="actions" style="margin:6px 0"><a class="btn wa sm" target="_blank" rel="noopener" href="https://wa.me/${o.wa || ''}?text=${encodeURIComponent(o.msg)}">📲 Send again</a><button class="btn ghost sm" data-del="${k}">Delete</button></div></details>`).join('') || '<div class="muted">No orders sent yet</div>'}</div>`, '#/order');
  wireTabs('#/order');
  document.querySelectorAll('[data-del]').forEach(b => (b.onclick = () => { const x = JSON.parse(ls.get(PO.sent) || '[]'); x.splice(Number(b.dataset.del), 1); ls.set(PO.sent, JSON.stringify(x)); sentOrders(); }));
}

function purchases(q) {
  const d = S.data, I = S.idx, tab = q.tab || 'payable';
  const sup = [...I.open].map(([pid, l]) => ({ p: I.p.get(pid), l: l.filter(o => o.k === 'p') })).filter(x => x.p && x.l.length).map(x => ({ ...x, t: sum(x.l, o => o.b), old: Math.max(...x.l.map(o => o.age)) })).sort((a, b) => b.t - a.t);
  const P = periodRows(tab === 'payments' ? d.payments : d.purchases, q);
  frame('Purchases', `<div class="tabs">${[['payable', 'Payable'], ['bills', 'Purchase bills'], ['payments', 'Payments']].map(([k, l]) => `<button data-tab="${k}" class="${tab === k ? 'on' : ''}">${l}</button>`).join('')}</div>
    ${tab === 'payable' ? `<div class="alert b">Open purchase bills as FAWin keeps them. Supplier payments are often not adjusted bill-wise in FAWin, so this can be higher than what is really owed.</div>` : periodChips('#/purchases', { ...q }, P.p).replace(/\?p=/g, `?tab=${tab}&p=`)}
    <div class="card"><h3><span>${tab === 'payable' ? sup.length + ' suppliers' : P.rows.length + ' entries'}</span><span>${short(tab === 'payable' ? sum(sup, x => x.t) : sum(P.rows))}</span></h3><div class="list" data-list></div></div>`, '#/more');
  document.querySelectorAll('[data-tab]').forEach(b => (b.onclick = () => { location.hash = `#/purchases?tab=${b.dataset.tab}`; }));
  if (tab === 'payable') more($('[data-list]'), sup, x => `<a class="row" href="#/party/${x.p.id}?tab=due"><span class="m"><b>${esc(x.p.name)}</b><small>${x.l.length} bills · oldest ${x.old} d</small></span><span class="r amber">${short(x.t)}</span></a>`);
  else more($('[data-list]'), [...P.rows].reverse(), r => { const p = S.idx.p.get(r.p); return `<a class="row" href="#/party/${r.p}?tab=pur"><span class="m"><b>${esc(p?.name || '')}</b><small>${dmy(r.d)} · ${esc(r.n)}${r.m ? ' · ' + esc(r.m) : ''}</small></span><span class="r">${money(r.a)}</span></a>`; });
}
function stock(q) {
  const d = S.data, tab = q.tab || 'stock';
  const T = [['stock', 'Stock'], ['out', 'Out of stock'], ['dead', 'Not selling'], ['expiry', 'Expiry']];
  frame('Stock', `${tabsHtml(T, tab)}<div data-f></div><div class="kpis" data-k style="margin-bottom:8px"></div><div class="card"><h3 data-h></h3><div class="list" data-list></div></div>`, '#/stock');
  wireTabs('#/stock');
  if (tab === 'expiry') {
    $('[data-k]').remove();
    // FAWin's stock keeps old batches it never cleared: an expiry more than a year ago is shown apart ("old leftovers")
    const part = q.part || 'recent';
    const all = [...d.expiry].sort((a, b) => b.dl - a.dl), old = all.filter(x => x.dl < -365), recent = all.filter(x => x.dl >= -365);
    const rows = part === 'old' ? old : recent;
    $('[data-f]').innerHTML = `<div class="chips"><a class="chip ${part === 'recent' ? 'on' : ''}" href="#/stock?tab=expiry&part=recent">Expiring / expired this year (${recent.length})</a><a class="chip ${part === 'old' ? 'on' : ''}" href="#/stock?tab=expiry&part=old">Expired over a year ago (${old.length})</a></div>
      <div class="alert b">${part === 'old' ? 'These batches expired more than a year ago. Most are probably old batches FAWin never cleared from stock — check on the shelf, then write them off in FAWin.' : 'Check these on the shelf: return to the supplier before expiry, or move them out.'}</div>`;
    $('[data-h]').innerHTML = `<span>${rows.filter(x => x.dl < 0).length} expired · ${rows.filter(x => x.dl >= 0).length} expiring within 120 days</span><span>${short(sum(rows, x => x.v))}</span>`;
    return more($('[data-list]'), part === 'old' ? rows : [...rows].sort((a, b) => a.dl - b.dl), x => `<div class="row"><span class="m"><b>${esc(x.n)}</b><small>Batch ${esc(x.b || '')} · exp ${dmy(x.e)} · ${esc(x.s || '')}</small></span><span class="r"><span class="${x.dl < 0 ? 'red' : x.dl <= 30 ? 'amber' : ''}">${x.dl < 0 ? 'expired' : x.dl + ' d'}</span><div class="small">${num(x.q)} · ${short(x.v)}</div></span></div>`);
  }
  if (!hasLines()) { $('[data-k]').remove(); $('[data-h]').textContent = `${d.stock.length} items in stock`; return more($('[data-list]'), d.stock, x => `<div class="row"><span class="m"><b>${esc(x.name)}</b><small>${esc([x.pack, x.co].filter(Boolean).join(' · '))}</small></span><span class="r"><b>${num(x.q)}</b></span></div>`); }
  // sold in the last 90 / 30 days per product
  const t = d.today, s90 = new Map(), s30 = new Map(), lastSale = new Map();
  for (const l of d.lines) if (l[3]) { if (l[1] >= addD(t, -89)) s90.set(l[3], (s90.get(l[3]) || 0) + l[4] + l[5]); if (l[1] >= addD(t, -29)) s30.set(l[3], (s30.get(l[3]) || 0) + l[4] + l[5]); if (!lastSale.has(l[3]) || l[1] > lastSale.get(l[3])) lastSale.set(l[3], l[1]); }
  const all = d.prod.map(p => { const sold = s90.get(p.i) || 0, avg = sold / 90; return { p, sold, s30: s30.get(p.i) || 0, avg, cover: avg ? p.q / avg : null, val: Math.max(p.q, 0) * unitCost(p), last: lastSale.get(p.i) || '' }; });
  const cos = [...new Set(d.prod.map(x => x.co).filter(Boolean))].sort();
  $('[data-f]').innerHTML = `<div class="filters"><input data-q placeholder="Product" value="${esc(q.q || '')}"><select data-co><option value="">All companies</option>${cos.map(c => `<option ${q.co === c ? 'selected' : ''}>${esc(c)}</option>`).join('')}</select>${tab === 'stock' ? `<select data-sort><option value="n">A–Z</option><option value="v">Highest value</option><option value="c">Fewest days left</option><option value="o">Most days of stock</option></select>` : ''}</div>`;
  const pick = {
    stock: r => r.p.q > 0,
    out: r => r.p.q <= 0 && r.s30 > 0,             // selling, but nothing on the shelf
    dead: r => r.p.q > 0 && r.sold === 0             // in stock, not sold in 90 days
  }[tab];
  const draw = () => {
    const s = $('[data-q]').value.trim().toLowerCase(), co = $('[data-co]').value, so = $('[data-sort]')?.value || (tab === 'dead' ? 'v' : 'n');
    const rows = all.filter(r => pick(r) && (!co || r.p.co === co) && (!s || r.p.n.toLowerCase().includes(s)));
    const key = { n: (a, b) => a.p.n.localeCompare(b.p.n), v: (a, b) => b.val - a.val, c: (a, b) => (a.cover ?? 1e9) - (b.cover ?? 1e9), o: (a, b) => (b.cover ?? -1) - (a.cover ?? -1) }[tab === 'out' ? 'n' : so];
    rows.sort(tab === 'out' ? (a, b) => b.s30 - a.s30 : key);
    $('[data-k]').innerHTML = tab === 'stock' ? `${kpi('Items in stock', num(rows.length), '', 'g')}${kpi('Stock value', short(sum(rows, r => r.val)), 'at landing cost')}${kpi('Under 15 days left', num(rows.filter(r => r.cover !== null && r.cover < 15).length), '', 'r')}${kpi('Over 120 days of stock', num(rows.filter(r => r.cover !== null && r.cover > 120).length), short(sum(rows.filter(r => r.cover !== null && r.cover > 120), r => r.val)), 'a')}`
      : tab === 'out' ? `${kpi('Out of stock, still selling', num(rows.length), 'sold in the last 30 days', 'r')}${kpi('Lost sales risk', short(sum(rows, r => r.s30 * (r.p.lr || 0))), 'a month of these at cost')}`
      : `${kpi('Not sold in 90 days', num(rows.length), 'but in stock', 'a')}${kpi('Money held', short(sum(rows, r => r.val)), 'at landing cost', 'r')}`;
    $('[data-h]').innerHTML = `<span>${rows.length} items</span>${tab === 'out' ? '<a href="#/order">Make orders →</a>' : ''}`;
    more($('[data-list]'), rows, r => `<a class="row" href="#/product/${r.p.i}"><span class="m"><b>${esc(r.p.n)}</b><small>${esc([r.p.pk, r.p.co].filter(Boolean).join(' · '))} · sold ${num(r.s30)} in 30 d${tab === 'dead' ? ` · last sale ${r.last ? dmy(r.last) : 'none in data'}` : ''}</small></span>
      <span class="r"><b class="${r.p.q <= 0 ? 'red' : ''}">${num(r.p.q)}</b><div class="small ${r.cover !== null && r.cover < 15 ? 'red' : ''}">${r.cover === null ? (r.val ? short(r.val) : '') : Math.round(r.cover) + ' days'}</div></span></a>`);
  };
  $('[data-q]').oninput = draw; $('[data-co]').onchange = draw; if ($('[data-sort]')) $('[data-sort]').onchange = draw;
  draw();
}
function edits(q) {
  const d = S.data;
  const users = [...new Set(d.edits.map(e => e.un).filter(Boolean))].sort();
  const days = Number(q.days || 7);
  frame('Changes in FAWin', `<div class="chips">${[[1, 'Today'], [7, '7 days'], [45, '45 days']].map(([k, l]) => `<a class="chip ${days === k ? 'on' : ''}" href="#/edits?days=${k}${q.u ? '&u=' + encodeURIComponent(q.u) : ''}">${l}</a>`).join('')}</div>
    <div class="filters"><select data-u><option value="">All users</option>${users.map(u => `<option ${q.u === u ? 'selected' : ''}>${esc(u)}</option>`).join('')}</select><select data-t><option value="">All documents</option><option value="12">Bills</option><option value="11">Purchases</option><option value="18">Challans</option><option value="money">Amount changed</option><option value="party">Party changed</option><option value="deleted">Deleted</option></select></div>
    <div class="alert b">From FAWin's own edit log: what the document was before the change, and the user who changed it.</div><div class="card"><h3 data-h></h3><div class="list" data-list></div></div>`, '#/more');
  const from = new Date(Date.now() - (days - 1) * 86400000).toISOString().slice(0, 10);
  const draw = () => {
    const u = $('[data-u]').value, t = $('[data-t]').value;
    const rows = d.edits.filter(e => String(e.at) >= (days === 1 ? d.today : from) && (!u || e.un === u) && (!t || (t === 'money' ? e.na != null && Math.abs(e.oa - e.na) > 0.5 : t === 'party' ? e.op && e.np && e.op !== e.np : t === 'deleted' ? e.na == null : String(e.t) === t)));
    $('[data-h]').textContent = `${rows.length} changes`;
    more($('[data-list]'), rows, e => `<div class="row"><span class="m"><b>${esc(DOC[e.t] || 'Document')} ${esc(e.n || '')}</b><small>${esc(String(e.at).slice(0, 16).split(' ').map((x, i) => (i ? x : dmy(x))).join(' '))} · <b>${esc(e.un || '?')}</b>${e.op && e.np && e.op !== e.np ? `<br>party: ${esc(e.op)} → ${esc(e.np)}` : e.np ? '<br>' + esc(e.np) : ''}</small></span>
      <span class="r">${e.na == null ? '<span class="red">deleted</span>' : Math.abs((e.oa || 0) - e.na) > 0.5 ? `<span class="muted">${money(e.oa)}</span><br><b class="amber">${money(e.na)}</b>` : `<span class="muted">${money(e.na)}</span><div class="small">same amount</div>`}</span></div>`);
  };
  $('[data-u]').onchange = draw; $('[data-t]').onchange = draw; draw();
}
function reports() {
  const d = S.data;
  const top = [...S.idx.bills].map(([pid, l]) => ({ p: S.idx.p.get(pid), t: sum(l) })).filter(x => x.p).sort((a, b) => b.t - a.t).slice(0, 15);
  const byUser = d.bills.reduce((m, b) => { const k = user(b.u) || '—'; m[k] = (m[k] || 0) + b.a; return m; }, {});
  frame('Reports', `<div class="card"><h3>Month by month (FY)</h3><div class="tw"><table><thead><tr><th>Month</th><th class="n">Sales</th><th class="n">Bills</th><th class="n">Collections</th><th class="n">Discount</th></tr></thead><tbody>${d.months.map(m => `<tr><td>${esc(m.m)}</td><td class="n">${short(m.sales)}</td><td class="n">${m.bills}</td><td class="n">${short(m.collections)}</td><td class="n">${short(m.discount)}</td></tr>`).join('')}</tbody>
    <tfoot><tr><td>FY</td><td class="n">${short(sum(d.months, m => m.sales))}</td><td class="n">${sum(d.months, m => m.bills)}</td><td class="n">${short(sum(d.months, m => m.collections))}</td><td class="n">${short(sum(d.months, m => m.discount))}</td></tr></tfoot></table></div></div>
    <div class="card"><h3>Top parties (FY sales)</h3>${top.map(x => `<a class="row" href="#/party/${x.p.id}?tab=bills"><span class="m"><b>${esc(x.p.name)}</b><small>${esc(x.p.track)}</small></span><span class="r">${short(x.t)}</span></a>`).join('')}</div>
    <div class="card"><h3>Ageing of outstanding</h3>${['0-30', '31-60', '61-90', '90+'].map(k => { const [a, b] = AGES[k]; const rows = d.open.filter(o => o.k === 's' && o.age >= a && o.age <= b); return `<a class="row" href="#/due?age=${k}"><span class="m">${k} days<small> ${rows.length} bills</small></span><span class="r">${short(sum(rows, o => o.b))}</span></a>`; }).join('')}</div>
    <div class="card"><h3>Sales by FAWin user (FY)</h3>${Object.entries(byUser).sort((a, b) => b[1] - a[1]).map(([k, v]) => `<div class="row"><span class="m">${esc(k)}</span><span class="r">${short(v)}</span></div>`).join('')}</div>`, '#/more');
}
function moreMenu() {
  frame('More', `<div class="card menu">${[['#/profit', '💹 Profit (bill / day / month)'], ['#/parties', '👥 Parties'], ['#/tracks', '🛣 Tracks'], ['#/sales?tab=products&s=30', '💊 Product sales'], ['#/sales?tab=parties&s=30', '📉 Parties that stopped buying'], ['#/collect?tab=follow', '📞 Payment follow-up'], ['#/purchases', '📦 Purchases & payable'], ['#/order?tab=sent', '🛒 Sent purchase orders'], ['#/edits', '🕵 Changes in FAWin'], ['#/reports', '📈 Reports'], ['#/archive', '🗄 Older reports (Gmail)'], ['#/settings', '⚙ Settings']].map(([h, l]) => `<a href="${h}">${l}</a>`).join('')}</div>`, '#/more');
}
async function archive(q) {
  frame('Older reports', `<div class="filters"><input type="date" data-from value="${esc(q.from || '')}"><input type="date" data-to value="${esc(q.to || '')}"><select data-k><option value="">All</option><option value="daily" ${q.k === 'daily' ? 'selected' : ''}>Daily reports (8 PM)</option></select><button class="btn sm" data-go>Search Gmail</button></div>
    <div class="card"><h3>Find a party or bill in older reports</h3><div class="filters"><input data-find placeholder="Party name or bill no." value="${esc(q.find || '')}"><button class="btn sm ghost" data-findgo>Find (up to 10 reports)</button></div><div data-found class="muted small">Opens each report in the list below and shows the party's dues or the bill in each.</div></div>
    <div class="card"><div class="list" data-list><div class="muted">Choose dates and tap Search Gmail.</div></div></div>`, '#/more');
  const go = async () => {
    const f = $('[data-from]').value, t = $('[data-to]').value, k = $('[data-k]').value;
    const qq = [f ? 'after:' + f.replace(/-/g, '/') : '', t ? 'before:' + new Date(new Date(t).getTime() + 86400000).toISOString().slice(0, 10).replace(/-/g, '/') : '', k === 'daily' ? 'subject:"Daily report"' : ''].filter(Boolean).join(' ');
    $('[data-list]').innerHTML = '<div class="spin">Searching Gmail…</div>';
    try {
      S.archive = await listReports(qq, 30);
      $('[data-list]').innerHTML = S.archive.map(m => `<div class="row"><span class="m"><b>${esc(m.subject.replace('[ARIHANT-ERP] ', ''))}</b><small>${esc(m.date)}</small></span><span class="r"><button class="btn sm ghost" data-open="${m.id}">Open</button></span></div>`).join('') || '<div class="muted">No reports in these dates</div>';
      document.querySelectorAll('[data-open]').forEach(b => (b.onclick = async () => { b.textContent = '…'; try { const x = await messageFile(b.dataset.open); await useFile(x.text, x.meta, S.pw); toast('Opened: ' + x.meta.subject.replace('[ARIHANT-ERP] ', '') + ' — tap ⟳ to go back to the latest'); location.hash = '#/home'; } catch (e) { toast(e.message); b.textContent = 'Open'; } }));
    } catch (e) { $('[data-list]').innerHTML = `<div class="alert r">${esc(e.message)}</div>`; }
  };
  $('[data-go]').onclick = go;
  $('[data-findgo]').onclick = async () => {
    const s = $('[data-find]').value.trim().toLowerCase(); if (!s) return;
    if (!S.archive?.length) return toast('Search Gmail first (choose dates above)');
    const out = $('[data-found]'); out.innerHTML = '<div class="spin">Opening reports…</div>';
    const res = [];
    for (const m of S.archive.slice(0, 10)) {
      try {
        const x = await messageFile(m.id), data = await unlock(x.text, S.pw);
        const ps = data.parties.filter(p => p.name.toLowerCase().includes(s));
        const bills = data.open.filter(o => String(o.n).toLowerCase() === s);
        res.push(`<div class="row"><span class="m"><b>${esc(m.subject.replace('[ARIHANT-ERP] ', ''))}</b><small>${ps.slice(0, 3).map(p => `${esc(p.name)}: due ${short(p.due)}`).join(' · ')}${bills.map(b => `Bill ${esc(b.n)} pending ${money(b.b)}`).join(' · ')}${!ps.length && !bills.length ? 'not found (or fully paid)' : ''}</small></span></div>`);
      } catch (e) { res.push(`<div class="row"><span class="m">${esc(m.subject)}: ${esc(e.message)}</span></div>`); }
      out.innerHTML = res.join('');
    }
  };
  if (q.from || q.to) go();
}
function settings() {
  const host = location.origin + location.pathname.replace(/[^/]*$/, '');
  frame('Settings', `<div class="card"><h3>Gmail</h3>
      <div class="fg"><label>Google OAuth Client ID</label><input data-client value="${esc(ls.get(LS.client) || DEFAULT_CLIENT_ID)}" placeholder="…apps.googleusercontent.com"></div>
      <div class="fg"><label>Gmail account</label><input data-hint value="${esc(ls.get(LS.hint) || 'arimedbackup@gmail.com')}"></div>
      <div class="actions"><button class="btn" data-save>Save</button><button class="btn ghost" data-test>Get the latest from Gmail</button></div>
      <div class="muted small" style="margin-top:8px">Set up once in Google Cloud: OAuth client of type <b>Web application</b> with authorised JavaScript origin <b>${esc(location.origin)}</b>, Gmail API enabled, scope gmail.readonly, and the Gmail account added as a test user.</div></div>
    <div class="card"><h3>Data on this phone</h3>
      <div class="actions"><label class="btn ghost">Open a file…<input type="file" accept=".amz,application/octet-stream" data-file hidden></label><button class="btn ghost" data-forgetpw>${ls.get(LS.pw) ? 'Forget the password' : 'Password is not remembered'}</button><button class="btn ghost" data-wipe>Remove all data from this phone</button></div>
      <div class="muted small" style="margin-top:8px">App address: ${esc(host)} · Install: browser menu → "Add to Home screen".</div></div>`, '#/more');
  $('[data-save]').onclick = () => { ls.set(LS.client, $('[data-client]').value.trim()); ls.set(LS.hint, $('[data-hint]').value.trim()); S.token = null; toast('Saved'); };
  $('[data-test]').onclick = e => { ls.set(LS.client, $('[data-client]').value.trim()); ls.set(LS.hint, $('[data-hint]').value.trim()); refreshFromGmail(e.target); };
  $('[data-file]').onchange = e => openFile(e.target.files[0]);
  $('[data-forgetpw]').onclick = () => { ls.del(LS.pw); toast('The password will be asked next time'); settings(); };
  $('[data-wipe]').onclick = () => { if (!confirm('Remove the Arihant data and password from this phone?')) return; for (const k of [LS.file, LS.meta, LS.pw]) ls.del(k); S.data = null; S.pw = null; start(); };
}
async function openFile(f) {
  if (!f) return;
  const text = await f.text();
  ls.set(LS.file, text); ls.set(LS.meta, JSON.stringify({ subject: f.name, source: 'file' }));
  S.data = null;
  const pw = S.pw || ls.get(LS.pw);
  if (pw) { try { await useFile(text, { subject: f.name, source: 'file' }, pw); location.hash = '#/home'; return route(); } catch { /* ask */ } }
  passwordScreen();
}

// ───────────── first run / password ─────────────
function welcome() {
  app().innerHTML = `<div class="top"><h1>Arihant Medicos</h1></div><main><div class="center card">
    <div class="big">Welcome</div><p class="muted">This app shows Arihant Medicos' data that the ERP emails to the Arihant Gmail account after each sync (10 AM, 2 PM, 8 PM).</p>
    <button class="btn block" data-gmail>Sign in to Gmail and get the latest data</button><div style="height:8px"></div>
    <label class="btn ghost block">Open a data file from this phone<input type="file" accept=".amz,application/octet-stream" data-file hidden></label>
    <p class="muted small">Sign in with <b>arimedbackup@gmail.com</b>. <a href="#/settings" data-set>Settings</a></p></div></main>`;
  $('[data-gmail]').onclick = e => refreshFromGmail(e.target);
  $('[data-file]').onchange = e => openFile(e.target.files[0]);
  $('[data-set]').onclick = e => { e.preventDefault(); S.forceSettings = true; settings(); };
}
function passwordScreen(err = '') {
  const meta = JSON.parse(ls.get(LS.meta) || '{}');
  app().innerHTML = `<div class="top"><h1>Arihant Medicos</h1></div><main><form class="center card">
    <div class="big">🔒 Enter the password</div><p class="muted small">${esc(meta.subject || 'Data file')}</p>${err ? `<div class="alert r">${esc(err)}</div>` : ''}
    <div class="fg"><label>Phone data password</label><input type="password" data-pw autocomplete="current-password" required></div>
    <label class="muted small" style="display:block;margin-bottom:10px"><input type="checkbox" data-remember> Remember on this phone</label>
    <button class="btn block">Unlock</button></form></main>`;
  $('[data-pw]').focus();
  $('form').onsubmit = async e => {
    e.preventDefault();
    const pw = $('[data-pw]').value;
    const b = $('form button'); b.disabled = true; b.textContent = 'Unlocking…';
    try { await useFile(ls.get(LS.file), meta, pw); if ($('[data-remember]').checked) ls.set(LS.pw, pw); location.hash = location.hash && !/^#\/(settings)?$/.test(location.hash) ? location.hash : '#/home'; route(); }
    catch (x) { passwordScreen(x.message); }
  };
}

// ───────────── router ─────────────
function route() {
  const [path, qs] = (location.hash || '#/home').slice(1).split('?');
  const q = Object.fromEntries(new URLSearchParams(qs || ''));
  if (path === '/settings') return settings();
  if (!S.data) return start();
  const m = path.match(/^\/party\/(\d+)$/);
  if (m) return party(m[1], q);
  const mp = path.match(/^\/product\/(\d+)$/);
  if (mp) return product(mp[1], q);
  ({ '/home': home, '/parties': parties, '/due': due, '/tracks': tracks, '/sales': sales, '/receipts': collect, '/collect': collect, '/order': order, '/profit': profit, '/purchases': purchases, '/stock': stock, '/edits': edits, '/reports': reports, '/more': moreMenu, '/archive': archive }[path] || home)(q);
}
async function start() {
  const file = ls.get(LS.file);
  if (!file) return welcome();
  const pw = S.pw || ls.get(LS.pw);
  if (!pw) return passwordScreen();
  try { await useFile(file, JSON.parse(ls.get(LS.meta) || '{}'), pw); route(); } catch (e) { passwordScreen(e.message); }
}
window.addEventListener('hashchange', () => { if (S.data || location.hash.startsWith('#/settings')) route(); });
if ('serviceWorker' in navigator && location.protocol === 'https:') navigator.serviceWorker.register('sw.js').catch(() => {});
start();
