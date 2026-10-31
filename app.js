// Arihant Medicos — phone app.
// Reads the newest "[ARIHANT-ERP]" email in the Arihant Gmail account (read-only Google sign-in), unlocks its
// attachment with the phone data password (PBKDF2-SHA256 + AES-256-GCM, gzip inside — same as the ERP), and shows
// everything from it. The locked file is kept on the phone, so the app also works offline.
const GMAIL_SCOPE = 'https://www.googleapis.com/auth/gmail.readonly';
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
  const client = ls.get(LS.client);
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
  return { p, open: by(d.open), bills: by(d.bills), rec: by(d.receipts), pur: by(d.purchases), pay: by(d.payments), led: by(d.ledger), ledOpen: new Map(d.ledger_open.map(x => [x.p, x.b])) };
}

// ───────────── layout ─────────────
const NAV = [['#/home', '🏠', 'Home'], ['#/parties', '👥', 'Parties'], ['#/due', '📋', 'Due list'], ['#/stock', '💊', 'Stock'], ['#/more', '☰', 'More']];
function frame(title, body, active) {
  const d = S.data, meta = JSON.parse(ls.get(LS.meta) || '{}');
  const ageH = d ? (Date.now() - new Date(String(d.generated_at).replace(' ', 'T')).getTime()) / 3600000 : 0;
  app().innerHTML = `<div class="top"><h1>${esc(title)}</h1><button data-refresh title="Get the latest data from Gmail">⟳</button></div>
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
  const d = S.data, t = d.today, ms = d.month_start;
  const tb = d.bills.filter(b => b.d === t), mb = d.bills.filter(b => b.d >= ms), tr = d.receipts.filter(r => r.d === t), mr = d.receipts.filter(r => r.d >= ms);
  const modes = tr.reduce((m, r) => { m[modeKind(r.m)] += r.a; return m; }, { cash: 0, bank: 0, upi: 0 });
  const recv = sum(d.open.filter(o => o.k === 's'), o => o.b), pay = sum(d.open.filter(o => o.k === 'p'), o => o.b);
  const expd = d.expiry.filter(x => x.dl < 0), near = d.expiry.filter(x => x.dl >= 0 && x.dl <= 90);
  const edToday = d.edits.filter(e => String(e.at).startsWith(t));
  const ck = d.fawin?.check;
  const runs = d.fawin?.runs_today || [];
  frame('Arihant Medicos', `
    ${runs.some(r => r.status !== 'ok') ? `<div class="alert r">⚠ A FAWin sync failed today: ${esc(runs.filter(r => r.status !== 'ok').map(r => String(r.started_at).slice(11, 16) + ' ' + (r.error || '')).join('; ').slice(0, 200))}</div>` : ''}
    ${ck && !ck.matched ? `<div class="alert r">⚠ Outstanding differs from FAWin: ERP ${money(ck.erp_receivable)} vs FAWin ${money(ck.fawin_receivable)}</div>` : ''}
    <div class="card"><h3>Today <span>${dmy(t)}</span></h3><div class="kpis">
      ${kpi('Sales', short(sum(tb)), `${tb.length} bills`, 'g')}${kpi('Collections', short(sum(tr)), `cash ${short(modes.cash)} · bank ${short(modes.bank)} · UPI ${short(modes.upi)}`, 'g')}
      ${kpi('Purchases', short(sum(d.purchases.filter(x => x.d === t))))}${kpi('Payments made', short(sum(d.payments.filter(x => x.d === t))))}</div></div>
    <div class="card"><h3>Totals</h3><div class="kpis">
      ${kpi('Outstanding', `<a href="#/due">${short(recv)}</a>`, `${d.open.filter(o => o.k === 's').length} bills`, 'r')}${kpi('Payable', `<a href="#/purchases">${short(pay)}</a>`, 'FAWin open purchase bills', 'a')}
      ${kpi('This month', short(sum(mb)), `${mb.length} bills · collected ${short(sum(mr))}`)}${kpi('This FY', short(sum(d.bills)), `collected ${short(sum(d.receipts))}`)}</div></div>
    <div class="card"><h3>Tracks <a href="#/tracks">all →</a></h3>${trackTable(true)}</div>
    <div class="card"><h3>Alerts</h3>
      <a class="row" href="#/edits"><span class="m"><b>Changes in FAWin today</b><small>edited or deleted bills, with who did it</small></span><span class="r ${edToday.length ? 'amber' : ''}">${edToday.length}</span></a>
      <a class="row" href="#/stock?tab=expiry"><span class="m"><b>Expired stock</b><small>${expd.length} batches</small></span><span class="r red">${short(sum(expd, x => x.v))}</span></a>
      <a class="row" href="#/stock?tab=expiry"><span class="m"><b>Expiring within 90 days</b><small>${near.length} batches</small></span><span class="r amber">${short(sum(near, x => x.v))}</span></a>
      <a class="row" href="#/stock?tab=low"><span class="m"><b>Low stock</b><small>items to reorder</small></span><span class="r">${d.low.length}</span></a></div>
    <div class="card"><h3>Sync today</h3>${runs.length ? runs.map(r => `<div class="row"><span class="m">${esc(String(r.started_at).slice(11, 16))} ${esc(r.trigger)}</span><span class="r ${r.status === 'ok' ? 'green' : 'red'}">${r.status === 'ok' ? '✓ OK' : esc(r.status)}</span></div>`).join('') : '<div class="muted">No sync yet today</div>'}</div>`, '#/home');
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
    <div class="tabs">${[['due', 'Due bills'], ['ledger', 'Ledger'], ['bills', 'Bills'], ['rec', 'Payments'], ...(p.s || openP.length ? [['pur', 'Purchases']] : [])].map(([k, l]) => `<button data-tab="${k}" class="${tab === k ? 'on' : ''}">${l}</button>`).join('')}</div><div class="card" data-body></div>`, '#/parties');
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
    rows.sort((a, b) => b.total - a.total);
    $('[data-count]').textContent = `${rows.length} parties`; $('[data-total]').textContent = short(sum(rows, r => r.total));
    more($('[data-list]'), rows, r => `<div class="row"><a class="m" href="#/party/${r.p.id}"><b>${esc(r.p.name)}</b><small>${esc([r.p.track, r.p.city].filter(Boolean).join(' · '))} · ${r.sales.length} bills · oldest <span class="${r.oldest > 90 ? 'red' : ''}">${r.oldest} d</span>${r.purs.length ? ` · <span class="amber">purchase ${short(r.ptotal)} (${r.purs.length})</span>` : ''}</small></a>
      <span class="r"><b class="red">${short(r.total)}</b><div>${r.sales.length ? `<a target="_blank" rel="noopener" href="${esc(waLink(r.p, dueMessage(r.p, r.sales)))}">📲 WhatsApp</a>` : ''}</div></span></div>`);
    history.replaceState(null, '', '#/due?' + new URLSearchParams(Object.entries({ track: t, age: $('[data-a]').value, min: $('[data-min]').value, q: $('[data-q]').value }).filter(([, v]) => v)).toString());
  };
  for (const sel of ['[data-t]', '[data-a]', '[data-pur]']) $(sel).onchange = draw;
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
function sales(q) {
  const d = S.data, P = periodRows(d.bills, q);
  const s = (q.q || '').toLowerCase();
  const rows = P.rows.filter(b => !s || b.n.toLowerCase().includes(s) || (S.idx.p.get(b.p)?.name || '').toLowerCase().includes(s)).reverse();
  const byUser = rows.reduce((m, b) => { const k = user(b.u) || '—'; m[k] = (m[k] || 0) + b.a; return m; }, {});
  frame('Sales', `${periodChips('#/sales', q, P.p)}<div class="filters"><input data-q placeholder="Bill no. or party" value="${esc(q.q || '')}"></div>
    <div class="kpis" style="margin-bottom:8px">${kpi('Sales', short(sum(rows)), `${rows.length} bills`, 'g')}${kpi('Discount', short(sum(rows, b => b.disc)))}${kpi('Scheme', short(sum(rows, b => b.sch)))}${kpi('Average bill', short(rows.length ? sum(rows) / rows.length : 0))}</div>
    <div class="card"><h3>By FAWin user</h3>${Object.entries(byUser).sort((a, b) => b[1] - a[1]).map(([k, v]) => `<div class="row"><span class="m">${esc(k)}</span><span class="r">${short(v)}</span></div>`).join('') || '<div class="muted">none</div>'}</div>
    <div class="card"><div class="list" data-list></div></div>`, '#/more');
  $('[data-q]').onchange = e => { location.hash = `#/sales?p=${P.p}&q=${encodeURIComponent(e.target.value)}`; };
  more($('[data-list]'), rows, b => { const p = S.idx.p.get(b.p); return `<a class="row" href="#/party/${b.p}?tab=bills"><span class="m"><b>${esc(p?.name || '')}</b><small>Bill ${esc(b.n)} · ${dmy(b.d)}${b.u ? ' · ' + esc(user(b.u)) : ''}</small></span><span class="r">${money(b.a)}</span></a>`; });
}
function receipts(q) {
  const d = S.data, P = periodRows(d.receipts, q);
  const rows = [...P.rows].reverse();
  const m = rows.reduce((x, r) => { x[modeKind(r.m)] += r.a; return x; }, { cash: 0, bank: 0, upi: 0 });
  frame('Collections', `${periodChips('#/receipts', q, P.p)}<div class="kpis" style="margin-bottom:8px">${kpi('Total', short(sum(rows)), `${rows.length} receipts`, 'g')}${kpi('Cash', short(m.cash))}${kpi('Bank', short(m.bank))}${kpi('UPI', short(m.upi))}</div>
    <div class="card"><div class="list" data-list></div></div>`, '#/more');
  more($('[data-list]'), rows, r => { const p = S.idx.p.get(r.p); return `<a class="row" href="#/party/${r.p}?tab=rec"><span class="m"><b>${esc(p?.name || '')}</b><small>${dmy(r.d)} · ${esc(r.m)}${r.st.length ? ' · ' + r.st.map(([n]) => esc(n)).join(', ') : ''}</small></span><span class="r">${money(r.a)}</span></a>`; });
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
  frame('Stock', `<div class="tabs">${[['stock', 'Stock'], ['expiry', 'Expiry'], ['low', 'Low stock']].map(([k, l]) => `<button data-tab="${k}" class="${tab === k ? 'on' : ''}">${l}</button>`).join('')}</div>
    ${tab === 'stock' ? `<div class="filters"><input data-q placeholder="Item or company" value="${esc(q.q || '')}"></div>` : ''}<div class="card"><h3 data-h></h3><div class="list" data-list></div></div>`, '#/stock');
  document.querySelectorAll('[data-tab]').forEach(b => (b.onclick = () => { location.hash = `#/stock?tab=${b.dataset.tab}`; }));
  if (tab === 'stock') {
    const draw = () => { const s = $('[data-q]').value.trim().toLowerCase(); const rows = d.stock.filter(x => !s || (x.name + ' ' + (x.co || '')).toLowerCase().includes(s)); $('[data-h]').textContent = `${rows.length} items in stock`; more($('[data-list]'), rows, x => `<div class="row"><span class="m"><b>${esc(x.name)}</b><small>${esc([x.pack, x.co].filter(Boolean).join(' · '))}${x.mrp ? ' · MRP ' + money(x.mrp) : ''}</small></span><span class="r"><b>${num(x.q)}</b></span></div>`); };
    $('[data-q]').oninput = draw; draw();
  } else if (tab === 'expiry') {
    const rows = [...d.expiry].sort((a, b) => a.dl - b.dl);
    $('[data-h]').innerHTML = `<span>${rows.filter(x => x.dl < 0).length} expired · ${rows.filter(x => x.dl >= 0).length} expiring within 120 days</span><span>${short(sum(rows, x => x.v))}</span>`;
    more($('[data-list]'), rows, x => `<div class="row"><span class="m"><b>${esc(x.n)}</b><small>Batch ${esc(x.b || '')} · exp ${dmy(x.e)} · ${esc(x.s || '')}</small></span><span class="r"><span class="${x.dl < 0 ? 'red' : x.dl <= 30 ? 'amber' : ''}">${x.dl < 0 ? 'expired' : x.dl + ' d'}</span><div class="small">${num(x.q)} · ${short(x.v)}</div></span></div>`);
  } else {
    $('[data-h]').textContent = `${d.low.length} items to reorder (about 15 days left at recent sales)`;
    more($('[data-list]'), d.low, x => `<div class="row"><span class="m"><b>${esc(x.n)}</b><small>${esc(x.co || '')} · sells ${num(x.pd)}/day · ${esc(x.s || '')}</small></span><span class="r">stock ${num(x.q)}<div class="small">order ${num(x.o)}</div></span></div>`);
  }
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
  frame('More', `<div class="card menu">${[['#/tracks', '🛣 Tracks'], ['#/sales', '🧾 Sales'], ['#/receipts', '💰 Collections'], ['#/purchases', '📦 Purchases & payable'], ['#/edits', '🕵 Changes in FAWin'], ['#/reports', '📈 Reports'], ['#/archive', '🗄 Older reports (Gmail)'], ['#/settings', '⚙ Settings']].map(([h, l]) => `<a href="${h}">${l}</a>`).join('')}</div>`, '#/more');
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
      <div class="fg"><label>Google OAuth Client ID</label><input data-client value="${esc(ls.get(LS.client) || '')}" placeholder="…apps.googleusercontent.com"></div>
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
    <p class="muted small">First time: tap Settings to enter the Google Client ID. <a href="#/settings" data-set>Settings</a></p></div></main>`;
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
  ({ '/home': home, '/parties': parties, '/due': due, '/tracks': tracks, '/sales': sales, '/receipts': receipts, '/purchases': purchases, '/stock': stock, '/edits': edits, '/reports': reports, '/more': moreMenu, '/archive': archive }[path] || home)(q);
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
