"use strict";
const $ = (s) => document.querySelector(s);
let state = { rules: [], status: {} };
let editId = null, delId = null, timer = null, tunTimer = null, tunTestTimer = null;

/* ---------- api ---------- */
async function api(path, method = "GET", body) {
  const r = await fetch("/api/" + path, {
    method, credentials: "same-origin",
    headers: { "Content-Type": "application/json", "X-Requested-With": "fwpanel" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  let data = {};
  try { data = await r.json(); } catch (_) {}
  if (r.status === 401 && path !== "login") { showLogin(); throw new Error("نشست تمام شده، دوباره وارد شو"); }
  if (!r.ok) throw new Error(data.error || "خطا " + r.status);
  return data;
}

function toast(msg, isErr) {
  const t = $("#toast");
  t.textContent = msg;
  t.className = "toast show" + (isErr ? " err" : "");
  clearTimeout(toast._t);
  toast._t = setTimeout(() => (t.className = "toast"), 2600);
}

/* ---------- views ---------- */
function showLogin() {
  clearInterval(timer);
  clearInterval(liveTimer);
  clearInterval(tunTimer);
  clearInterval(tunTestTimer);
  $("#app").classList.add("hidden");
  $("#login").classList.remove("hidden");
  document.querySelectorAll("dialog[open]").forEach((d) => d.close());
  $("#loginPw").value = "";
  $("#loginPw").focus();
}

function showApp() {
  $("#login").classList.add("hidden");
  $("#app").classList.remove("hidden");
  clearInterval(timer);
  timer = setInterval(() => { if (!document.hidden) refresh(true); }, 10000);
  clearInterval(liveTimer);
  pollLive();
  liveTimer = setInterval(pollLive, 2000);
  clearInterval(tunTimer);
  loadTunnels(true);
  tunTimer = setInterval(() => { if (!document.hidden) loadTunnels(false); }, 10000);
  clearInterval(tunTestTimer);
  tunTestTimer = setInterval(() => { if (!document.hidden) testAllTunnels(); }, 60000);
}

async function refresh(silent) {
  try {
    state = await api("state");
    render();
  } catch (e) { if (!silent) toast(e.message, true); }
}

const PROTO = { tcp: "TCP", udp: "UDP", both: "TCP+UDP" };

function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined) e.textContent = text;
  return e;
}

let rateEls = {};

function render() {
  rateEls = {};
  const st = state.status || {};
  const chips = $("#chips");
  chips.replaceChildren();
  const chip = (txt, ok) => { const c = el("span", "chip" + (ok ? "" : " bad")); c.append(el("i"), document.createTextNode(txt)); chips.append(c); };
  chip(`${fa(state.rules.filter((r) => r.enabled).length)} قانون فعال از ${fa(state.rules.length)}`, true);
  chip(st.chains_ok ? "iptables سالم" : "iptables ناقص", !!st.chains_ok);
  chip(st.ip_forward ? "ip_forward روشن" : "ip_forward خاموش", !!st.ip_forward);

  const list = $("#list");
  list.replaceChildren();
  if (!state.rules.length) {
    list.append(el("div", "empty", "هنوز قانونی نداری. با «قانون جدید» اولین فوروارد را بساز."));
    applyLive();
    return;
  }
  const head = el("div", "head");
  ["وضعیت", "پروتکل", "ورودی", "مقصد", "توضیح", "لحظه‌ای", "مجموع ترافیک", ""].forEach((h) => head.append(el("div", "", h)));
  list.append(head);

  for (const r of state.rules) {
    const row = el("div", "rule" + (r.enabled ? "" : " off"));

    const sw = el("div", "c-sw");
    const lab = el("label", "sw");
    const cb = el("input"); cb.type = "checkbox"; cb.checked = r.enabled; cb.setAttribute("aria-label", "فعال/غیرفعال");
    cb.onchange = () => save(r.id, { enabled: cb.checked }, cb.checked ? "فعال شد" : "غیرفعال شد");
    const locked = !!r.managed && !!(state.status || {}).sync_receive;
    if (locked) { cb.disabled = true; row.classList.add("managed"); }
    lab.append(cb, el("span"));
    sw.append(lab);

    const proto = el("div", "c-proto");
    proto.append(el("span", "badge " + r.proto, PROTO[r.proto]));

    const route = el("div", "c-route");
    const dest = el("div", "c-dest");
    dest.append(el("span", "mono", "→ " + r.dest_ip + ":" + r.dest_port));
    if (!r.masq) dest.append(el("span", "tag", "بدون NAT"));
    route.append(el("div", "c-listen mono", (r.listen_ip || "*") + ":" + r.listen_port), dest);

    const note = el("div", "c-note note", r.comment || "");
    note.title = r.comment || "";
    if (r.managed) note.prepend(el("span", "tag auto", (locked ? "خودکار · " : "از ") + r.managed));
    else if (r.sync === false && (state.status || {}).links) note.prepend(el("span", "tag", "بدون sync"));

    const rates = el("div", "c-rates rates");
    const dn = el("div", "d", "↓ ۰ بیت"), up = el("div", "u", "↑ ۰ بیت");
    rates.append(dn, up);

    const tots = el("div", "c-tots tots");
    const td = el("div", "d", "↓ ۰ بایت"), tu = el("div", "u", "↑ ۰ بایت");
    const rb = el("button", "btn ghost", "⟲ ریست"); rb.type = "button"; rb.title = "صفر کردن مجموع ترافیک این فوروارد";
    rb.onclick = () => resetRule(r);
    const z = el("div", "z"); z.append(td, rb);
    tots.append(z, tu);
    tots.title = "از لحظه‌ی ساخت یا آخرین ریست؛ بعد از ریستارت پاک نمی‌شود";
    rateEls[r.id] = { dn, up, td, tu };

    const acts = el("div", "c-acts row-actions");
    if (locked) {
      acts.append(el("span", "lock", "🔒 فقط از پنل مبدأ"));
    } else {
      const be = el("button", "btn icon", "ویرایش"); be.onclick = () => openRule(r);
      const bd = el("button", "btn icon danger", "حذف"); bd.onclick = () => openDelete(r);
      acts.append(be, bd);
    }

    row.append(sw, proto, route, note, rates, tots, acts);
    list.append(row);
  }
  applyLive();
}

async function resetRule(r) {
  if (!confirm(`مجموع ترافیک فوروارد ${r.listen_port} → ${r.dest_ip}:${r.dest_port} صفر شود؟`)) return;
  try { await api("rules/" + r.id + "/reset", "POST"); toast("مجموع ترافیک صفر شد"); } catch (e) { toast(e.message, true); }
  pollLive();
}

/* ---------- live traffic ---------- */
let live = null, liveTimer = null;

/* Persian digits and units, so numbers never flip inside right-to-left text */
const FA = "۰۱۲۳۴۵۶۷۸۹";
const fa = (s) => String(s).replace(/\d/g, (d) => FA[d]).replace(".", "٫");
const dec = (v, big) => fa(v >= 100 ? v.toFixed(0) : v >= 10 ? v.toFixed(1) : v.toFixed(big ? 2 : 1));

function rateParts(bps) {
  const u = ["بیت", "کیلوبیت", "مگابیت", "گیگابیت"];
  if (!bps || bps < 1) return { n: fa(0), u: u[0] };
  let i = 0;
  while (bps >= 1000 && i < u.length - 1) { bps /= 1000; i++; }
  return { n: dec(bps, true), u: u[i] };
}
function fmtRate(bps) { const p = rateParts(bps); return p.n + " " + p.u; }
function fmtBytes(b) {
  const u = ["بایت", "کیلوبایت", "مگابایت", "گیگابایت", "ترابایت", "پتابایت"];
  if (!b) return fa(0) + " " + u[0];
  let i = 0;
  while (b >= 1024 && i < u.length - 1) { b /= 1024; i++; }
  return (i === 0 ? fa(Math.round(b)) : dec(b, i >= 3)) + " " + u[i];
}
function fmtSince(ts) {
  if (!ts) return "";
  try { return new Date(ts * 1000).toLocaleDateString("fa-IR"); } catch (_) { return ""; }
}

function spark(id, data, max) {
  const n = data.length;
  const pts = data.map((v, i) => ((n < 2 ? 0 : (i / (n - 1)) * 300).toFixed(1)) + "," + (54 - (max ? (v / max) * 50 : 0)).toFixed(1));
  $(id).setAttribute("points", pts.join(" "));
}

const ifName = (i) => i.alias || i.name;

function nameBtn(i) {
  const b = el("button", "pencil", "✎");
  b.type = "button"; b.title = "تغییر نام نمایشی";
  b.onclick = () => openName(i);
  return b;
}

function resetIface(i) {
  if (!confirm(`مجموع ترافیک «${ifName(i)}» صفر شود؟`)) return;
  api("iface/" + encodeURIComponent(i.name) + "/reset", "POST").then(() => { toast("مجموع ترافیک صفر شد"); pollLive(); }).catch((e) => toast(e.message, true));
}

function statBlock(cls, label, rate, total, since) {
  const d = el("div", "stat " + cls);
  const p = rateParts(rate);
  const big = el("span", "big", p.n);
  big.append(el("small", "", p.u + " بر ثانیه"));
  d.append(el("div", "lbl", label), big);
  const sub = el("div", "sub");
  sub.append(document.createTextNode("مجموع: "), el("b", "", fmtBytes(total)));
  d.append(sub);
  return d;
}

function applyLive() {
  if (!live) return;
  const ifs = live.ifaces || [];
  const main = ifs.find((i) => i.main) || ifs[0];

  const hero = $("#hero");
  hero.replaceChildren();
  if (main) {
    hero.className = "hero";
    const nm = el("div", "hero-name");
    nm.append(el("span", "", ifName(main)));
    if (main.alias) nm.append(el("small", "ltr", main.name));
    nm.append(nameBtn(main));
    const stats = el("div", "hero-stats");
    stats.append(statBlock("dn", "دانلود ↓", main.rx, main.rx_total), statBlock("up", "آپلود ↑", main.tx, main.tx_total));
    const act = el("div", "hero-actions");
    const rb = el("button", "btn ghost", "⟲ ریست مجموع" + (main.since ? "  (از " + fmtSince(main.since) + ")" : ""));
    rb.type = "button"; rb.onclick = () => resetIface(main);
    act.append(rb);
    hero.append(nm, stats, act);
  }
  const h = live.hist || { rx: [], tx: [] };
  const max = Math.max(1, ...h.rx, ...h.tx);
  spark("#sparkRx", h.rx, max);
  spark("#sparkTx", h.tx, max);

  const grid = $("#ifgrid");
  grid.replaceChildren();
  for (const i of ifs) {
    if (i === main) continue;
    const c = el("div", "ifc");
    const nm = el("div", "nm");
    nm.append(el("span", "", ifName(i)), nameBtn(i));
    const rt = el("div", "rt");
    rt.append(el("span", "d", "↓ " + fmtRate(i.rx)), el("span", "u", "↑ " + fmtRate(i.tx)));
    const tt = el("div", "tt");
    const sp = (t) => { const s = el("span", "", t); return s; };
    tt.append(document.createTextNode("مجموع: "), sp("↓ " + fmtBytes(i.rx_total)), document.createTextNode("  "), sp("↑ " + fmtBytes(i.tx_total)));
    const rb = el("button", "btn ghost", "⟲ ریست"); rb.type = "button"; rb.onclick = () => resetIface(i);
    c.append(nm);
    if (i.alias) c.append(el("span", "real", i.name));
    c.append(rt, tt, rb);
    grid.append(c);
  }
  for (const [id, e] of Object.entries(rateEls)) {
    const r = (live.rules || {})[id];
    e.dn.textContent = "↓ " + fmtRate(r ? r.down : 0);
    e.up.textContent = "↑ " + fmtRate(r ? r.up : 0);
    e.td.textContent = "↓ " + fmtBytes(r ? r.down_total : 0);
    e.tu.textContent = "↑ " + fmtBytes(r ? r.up_total : 0);
  }
}

async function pollLive() {
  if (document.hidden) return;
  try { live = await api("live"); applyLive(); } catch (_) {}
}

/* ---------- tunnel display names ---------- */
let nameFor = null;
function openName(i) {
  nameFor = i;
  $("#nameReal").textContent = "اینترفیس: " + i.name;
  $("#nameInput").value = i.alias || "";
  $("#nameDlg").showModal();
  $("#nameInput").focus();
}
$("#nameCancel").onclick = () => $("#nameDlg").close();
$("#nameForm").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  try {
    await api("iface/" + encodeURIComponent(nameFor.name) + "/alias", "PUT", { alias: $("#nameInput").value.trim() });
    $("#nameDlg").close();
    toast("نام ذخیره شد");
    pollLive();
  } catch (e) { toast(e.message, true); }
});

/* ---------- rule dialog ---------- */
const f = {
  proto: $("#fProto"), lport: $("#fLport"), dip: $("#fDip"), dport: $("#fDport"),
  lip: $("#fLip"), comment: $("#fComment"), masq: $("#fMasq"), enabled: $("#fEnabled"),
};
let dportTouched = false;

function openRule(r) {
  editId = r ? r.id : null;
  dportTouched = !!r;
  $("#ruleTitle").textContent = r ? `ویرایش قانون #${r.id}` : "قانون جدید";
  f.proto.value = r ? r.proto : "tcp";
  f.lport.value = r ? r.listen_port : "";
  f.dip.value = r ? r.dest_ip : "";
  f.dport.value = r ? r.dest_port : "";
  f.lip.value = r ? r.listen_ip : "";
  f.comment.value = r ? r.comment : "";
  f.masq.checked = r ? r.masq : true;
  $("#syncRow").classList.toggle("hidden", !((state.status || {}).links));
  $("#fSync").checked = r ? r.sync !== false : true;
  f.enabled.checked = r ? r.enabled : true;
  $("#ruleErr").textContent = "";
  $("#ruleDlg").showModal();
  f.lport.focus();
}

f.lport.addEventListener("input", () => { if (!dportTouched) f.dport.value = f.lport.value; });
f.dport.addEventListener("input", () => { dportTouched = true; });

$("#ruleForm").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const body = {
    proto: f.proto.value, listen_port: f.lport.value.trim(), dest_ip: f.dip.value.trim(),
    dest_port: f.dport.value.trim() || f.lport.value.trim(), listen_ip: f.lip.value.trim(),
    comment: f.comment.value.trim(), masq: f.masq.checked, enabled: f.enabled.checked,
    sync: $("#fSync").checked,
  };
  const btn = $("#ruleSave");
  btn.disabled = true;
  try {
    await (editId ? api("rules/" + editId, "PUT", body) : api("rules", "POST", body));
    $("#ruleDlg").close();
    toast(editId ? "ذخیره شد" : "قانون اضافه شد");
    refresh();
  } catch (e) { $("#ruleErr").textContent = e.message; }
  btn.disabled = false;
});
$("#ruleCancel").onclick = () => $("#ruleDlg").close();

async function save(id, patch, msg) {
  try { await api("rules/" + id, "PUT", patch); toast(msg); } catch (e) { toast(e.message, true); }
  refresh();
}

/* ---------- delete ---------- */
function openDelete(r) {
  delId = r.id;
  $("#delText").textContent = `قانون ${PROTO[r.proto]} ${r.listen_port} → ${r.dest_ip}:${r.dest_port} حذف شود؟`;
  $("#delDlg").showModal();
}
$("#delCancel").onclick = () => $("#delDlg").close();
$("#delOk").onclick = async () => {
  try { await api("rules/" + delId, "DELETE"); toast("حذف شد"); } catch (e) { toast(e.message, true); }
  $("#delDlg").close();
  refresh();
};

/* ---------- top buttons / settings ---------- */
$("#btnAdd").onclick = () => openRule(null);
$("#btnApply").onclick = async () => {
  try { await api("apply", "POST"); toast("قوانین دوباره اعمال شد"); } catch (e) { toast(e.message, true); }
  refresh();
};
$("#btnSettings").onclick = () => {
  $("#setErr").textContent = ""; $("#pwForm").reset(); $("#keyBox").classList.add("hidden");
  $("#setDlg").showModal();
  loadPanelSettings();
  loadLinks();
};
$("#setClose").onclick = () => $("#setDlg").close();
$("#btnLogout").onclick = async () => { try { await api("logout", "POST"); } catch (_) {} showLogin(); };

$("#btnExport").onclick = async () => {
  try {
    const d = await api("export");
    const a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([JSON.stringify(d, null, 2)], { type: "application/json" }));
    a.download = "fwpanel-rules-" + new Date().toISOString().slice(0, 10) + ".json";
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 2000);
  } catch (e) { $("#setErr").textContent = e.message; }
};
$("#btnImport").onclick = () => $("#fileImport").click();
$("#fileImport").onchange = async (ev) => {
  const file = ev.target.files[0];
  ev.target.value = "";
  if (!file) return;
  if (!confirm("همه‌ی قوانین فعلی با محتوای فایل جایگزین می‌شود. ادامه؟")) return;
  try {
    const d = await api("import", "POST", JSON.parse(await file.text()));
    $("#setDlg").close();
    toast(d.count + " قانون بازگردانی شد");
    refresh();
  } catch (e) { $("#setErr").textContent = e.message; }
};

$("#pwForm").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  try {
    await api("password", "POST", { old: $("#pwOld").value, new: $("#pwNew").value });
    toast("رمز تغییر کرد، دوباره وارد شو");
    showLogin();
  } catch (e) { $("#setErr").textContent = e.message; }
});

/* ---------- login ---------- */
$("#loginForm").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  $("#loginErr").textContent = "";
  try {
    await api("login", "POST", { password: $("#loginPw").value });
    showApp();
    refresh();
  } catch (e) { $("#loginErr").textContent = e.message; }
});

/* ---------- boot ---------- */
(async () => {
  try { state = await api("state"); showApp(); render(); }
  catch (_) { showLogin(); }
})();

/* ---------- sync links ---------- */
async function loadLinks() {
  try {
    const d = await api("links");
    renderLinks(d.links);
    $("#recvState").textContent = d.receive
      ? "دریافت فعال است. کلید جدید ساختن، کلید قبلی را از کار می‌اندازد."
      : "دریافت غیرفعال است (این پنل از جایی قانون نمی‌گیرد).";
  } catch (e) { $("#setErr").textContent = e.message; }
}

function renderLinks(links) {
  const box = $("#linkList");
  box.replaceChildren();
  if (!links.length) { box.append(el("div", "muted small", "هنوز سروری لینک نشده.")); return; }
  for (const l of links) {
    const c = el("div", "lk");
    const top = el("div", "lk-top");
    top.append(el("b", "", l.name));
    const acts = el("div", "lk-acts");
    const bs = el("button", "btn icon", "همگام‌سازی الان"); bs.type = "button";
    bs.onclick = async () => { bs.disabled = true; try { await api("links/" + l.id + "/sync", "POST"); } catch (e) { toast(e.message, true); } loadLinks(); refresh(true); };
    const bt = el("button", "btn icon", l.enabled ? "غیرفعال" : "فعال"); bt.type = "button";
    bt.onclick = async () => { try { await api("links/" + l.id, "PUT", { name: l.name, url: l.url, tunnel_ip: l.tunnel_ip, enabled: !l.enabled }); } catch (e) { toast(e.message, true); } loadLinks(); };
    const bd = el("button", "btn icon danger", "حذف"); bd.type = "button";
    bd.onclick = async () => {
      if (!confirm("لینک «" + l.name + "» حذف شود؟ قوانین خودکار آن روی سرور ایران پاک می‌شود.")) return;
      try { const d = await api("links/" + l.id, "DELETE"); if (d.warning) toast(d.warning, true); } catch (e) { toast(e.message, true); }
      loadLinks(); refresh(true);
    };
    if (l.installer) {
      const bi = el("button", "btn icon", "⬇ اسکریپت نصب"); bi.type = "button";
      bi.title = "اسکریپت نصب سرور ایران را دوباره دانلود کن";
      bi.onclick = () => downloadInstaller(l);
      acts.append(bi);
    }
    acts.append(bs, bt, bd);
    top.append(acts);
    c.append(top, el("div", "lk-meta", l.url + "  →  " + (l.tunnel ? "tunnel " + l.tunnel + " (" + (l.tunnel_kind || "").toUpperCase() + ") " : "") + l.tunnel_ip));
    if (l.status) {
      const when = new Date(l.status.ts * 1000).toLocaleTimeString("fa-IR");
      c.append(el("div", "lk-st " + (l.status.ok ? "ok" : "bad"), (l.status.ok ? "✓ " : "✗ ") + l.status.msg + "  (" + when + ")"));
    } else c.append(el("div", "lk-st muted", "هنوز همگام نشده"));
    box.append(c);
  }
}

$("#linkForm").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  try {
    await api("links", "POST", { name: $("#lkName").value, tunnel_ip: $("#lkTun").value.trim(), url: $("#lkUrl").value.trim(), secret: $("#lkKey").value.trim() });
    $("#linkForm").reset();
    toast("سرور ایران اضافه شد و همگام‌سازی شروع شد");
    setTimeout(() => { loadLinks(); refresh(true); }, 2500);
    loadLinks();
  } catch (e) { $("#setErr").textContent = e.message; }
});

$("#btnGenKey").onclick = async () => {
  if ($("#recvState").textContent.startsWith("دریافت فعال") && !confirm("کلید قبلی از کار می‌افتد. ادامه؟")) return;
  try {
    const d = await api("synckey", "POST");
    $("#keyOut").textContent = d.key;
    $("#keyBox").classList.remove("hidden");
    loadLinks();
  } catch (e) { $("#setErr").textContent = e.message; }
};
$("#btnOffKey").onclick = async () => {
  try { await api("synckey", "DELETE"); $("#keyBox").classList.add("hidden"); toast("دریافت غیرفعال شد"); loadLinks(); } catch (e) { $("#setErr").textContent = e.message; }
};
$("#btnCopyKey").onclick = async () => {
  try { await navigator.clipboard.writeText($("#keyOut").textContent); toast("کپی شد"); }
  catch (_) { const r = document.createRange(); r.selectNodeContents($("#keyOut")); getSelection().removeAllRanges(); getSelection().addRange(r); toast("کلید انتخاب شد، Ctrl+C بزن"); }
};

/* ---------- panel settings (port / protocol / allow-list) ---------- */
let panelSettings = null;
async function loadPanelSettings() {
  try {
    const s = await api("settings");
    panelSettings = s;
    $("#spPort").value = s.port;
    $("#spTls").value = s.tls ? "https" : "http";
    $("#spAllow").value = (s.allow_ips || []).join("\n");
    $("#spHint").textContent = "آی‌پی فعلی تو: " + s.client_ip + " • نسخه " + fa(s.version) + " • پورت‌های SSH محافظت‌شده: " + s.ssh_ports.map(fa).join("، ");
  } catch (e) { $("#setErr").textContent = e.message; }
}

$("#panelForm").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  $("#setErr").textContent = "";
  const body = { port: $("#spPort").value.trim(), tls: $("#spTls").value === "https", allow_ips: $("#spAllow").value };
  try {
    const r = await api("settings", "POST", body);
    (r.notes || []).forEach((n) => toast(n));
    if (r.restart) {
      toast("پنل دوباره راه‌اندازی می‌شود و به آدرس جدید می‌روی…");
      const url = (r.tls ? "https" : "http") + "://" + location.hostname + ":" + r.port + "/";
      setTimeout(() => { location.href = url; }, 3500);
    } else {
      toast("تنظیمات ذخیره شد");
      loadPanelSettings();
    }
  } catch (e) { $("#setErr").textContent = e.message; }
});

/* ---------- Iran installer wizard ---------- */
async function downloadInstaller(l) {
  try {
    const r = await fetch("/api/links/" + l.id + "/installer", { credentials: "same-origin", headers: { "X-Requested-With": "fwpanel" } });
    if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error || "خطا " + r.status);
    const a = document.createElement("a");
    a.href = URL.createObjectURL(await r.blob());
    a.download = "install-" + l.name.replace(/[^A-Za-z0-9_-]/g, "") + ".sh";
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 2000);
  } catch (e) { toast(e.message, true); }
}

function openWizard(mode) {
  ["#aErr", "#irErr"].forEach((q) => { $(q).textContent = ""; });
  $("#aPass").value = "";
  $("#progList").replaceChildren(); $("#progResult").replaceChildren();
  ["#irProg", "#irCmdOut"].forEach((q) => $(q).classList.add("hidden"));
  $("#irTabs").classList.remove("hidden");
  setTab(mode || "auto");
  $("#irHttpWarn").classList.toggle("hidden", !(location.protocol === "http:" && !["localhost", "127.0.0.1"].includes(location.hostname)));
  $("#iranDlg").showModal();
}
function setTab(m) {
  document.querySelectorAll("#irTabs button").forEach((b) => b.classList.toggle("on", b.dataset.m === m));
  $("#irAuto").classList.toggle("hidden", m !== "auto");
  $("#irCmd").classList.toggle("hidden", m !== "cmd");
  if (m === "cmd") { if (!panelSettings) loadPanelSettings().then(() => fillTunnelFields(true)); else fillTunnelFields(true); }
}
document.querySelectorAll("#irTabs button").forEach((b) => { b.onclick = () => setTab(b.dataset.m); });
document.querySelectorAll("#iranDlg [data-close]").forEach((b) => { b.onclick = () => $("#iranDlg").close(); });
$("#btnNewIran").onclick = () => { $("#setDlg").close(); openWizard("auto"); };
$("#btnTopIran").onclick = () => openWizard("auto");

/* ----- automatic install over SSH, with a live log ----- */
const ICON = { ok: "✓", warn: "!", err: "✗", info: "•" };
function renderSteps(steps, running) {
  const box = $("#progList");
  box.replaceChildren();
  steps.forEach((st, i) => {
    const d = el("div", "step " + st.level + (running && i === steps.length - 1 ? " live" : ""));
    d.append(el("i", "", running && i === steps.length - 1 ? "…" : ICON[st.level] || "•"), el("span", "", st.msg));
    box.append(d);
  });
  box.scrollTop = box.scrollHeight;
}

function resultCard(r) {
  const c = el("div", "result");
  const row = (k, vNode) => { const d = el("div", "row2"); d.append(el("span", "", k)); d.append(vNode); c.append(d); };
  const code = (t) => el("code", "", t);
  const a = el("a", "", r.panel_url); a.href = r.panel_url; a.target = "_blank"; a.rel = "noopener"; a.dir = "ltr";
  row("پنل سرور ایران", a);
  const pwBox = el("span");
  pwBox.append(code(r.password || "بدون تغییر (پنل از قبل بوده)"));
  if (r.password) { const b = el("button", "btn ghost", "کپی"); b.type = "button"; b.onclick = () => { navigator.clipboard.writeText(r.password).then(() => toast("کپی شد")); }; pwBox.append(b); }
  row("رمز پنل ایران", pwBox);
  if (r.tunnel) {
    row("تونل", code(r.tunnel.name + " (" + r.tunnel.kind.toUpperCase() + ")  " + r.tunnel.iran_ip + " ↔ " + r.tunnel.foreign_ip));
    const t = r.test;
    if (t) row("سلامت", el("span", "", (t.status === "healthy" ? "سالم" : t.status === "degraded" ? "ضعیف" : "قطع") + " • افت " + fa(Math.round(t.loss)) + "٪ • تأخیر " + fa(((t.rtt || {}).avg || 0).toFixed(1)) + " میلی‌ثانیه • MTU " + fa(t.mtu)));
  } else row("اتصال", el("span", "", "مستقیم از اینترنت (بدون تونل)"));
  row("همگام‌سازی", el("span", "", r.sync ? r.sync.msg : "-"));
  c.append(el("div", "muted small", "از این به بعد فورواردها را فقط در همین پنل بساز؛ روی سرور ایران خودکار ساخته می‌شوند. رمز را همین حالا ذخیره کن."));
  return c;
}

async function followJob(id) {
  $("#irTabs").classList.add("hidden");
  ["#irAuto", "#irCmd"].forEach((q) => $(q).classList.add("hidden"));
  $("#irProg").classList.remove("hidden");
  $("#progClose").disabled = true;
  for (;;) {
    let j;
    try { j = await api("jobs/" + id); } catch (e) { toast(e.message, true); break; }
    renderSteps(j.steps, j.state === "running");
    if (j.state !== "running") {
      if (j.state === "done" && j.result) { $("#progResult").replaceChildren(resultCard(j.result)); }
      if (j.state === "error") { const b = el("div", "warnbox", "نصب کامل نشد. هر چه تا اینجا ساخته شده در پیام‌های بالا آمده است."); $("#progResult").replaceChildren(b); }
      break;
    }
    await new Promise((r) => setTimeout(r, 1000));
  }
  $("#progClose").disabled = false;
  loadLinks(); loadTunnels(true); refresh(true);
}
$("#progClose").onclick = () => $("#iranDlg").close();

$("#irAuto").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  $("#aErr").textContent = "";
  const body = {
    name: $("#aName").value.trim(), host: $("#aHost").value.trim(), ssh_port: $("#aSsh").value.trim(), password: $("#aPass").value,
    tunnel: $("#aTun").value, panel_port: $("#aPort").value.trim(), scheme: location.protocol === "https:" ? "https" : "http",
    optimize: $("#aOpt").checked, replace_key: $("#aRep").checked,
  };
  try {
    const r = await api("iran/install", "POST", body);
    $("#aPass").value = "";
    followJob(r.job);
  } catch (e) { $("#aErr").textContent = e.message; }
});

/* ----- one-line command mode ----- */
function fillTunnelFields(reset) {
  const gre4 = $("#tnKind").value === "gre4";
  const cands = gre4 ? (panelSettings && panelSettings.ipv4 ? [panelSettings.ipv4] : []) : ((panelSettings || {}).ipv6 || []);
  const dl = $("#epList");
  dl.replaceChildren();
  for (const a of cands) { const o = document.createElement("option"); o.value = a; dl.append(o); }
  $("#lblFE").firstChild.textContent = gre4 ? "IPv4 عمومی همین سرور (خارج)" : "IPv6 همین سرور (خارج)";
  $("#lblIE").firstChild.textContent = gre4 ? "IPv4 عمومی سرور ایران" : "IPv6 سرور ایران ";
  $("#lblIE small").classList.toggle("hidden", gre4);
  if (reset) { $("#tnFE").value = cands[0] || ""; $("#tnIE").value = gre4 ? $("#irIp").value.trim() : ""; }
}
$("#tnKind").onchange = () => fillTunnelFields(true);
$("#irTun").onchange = () => $("#irTunBox").classList.toggle("hidden", !$("#irTun").checked);

let cmdLink = null, cmdTimer = null;
$("#irCmd").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  $("#irErr").textContent = "";
  const body = {
    name: $("#irName").value.trim(), port: $("#irPort").value.trim(), scheme: $("#irScheme").value, iran_ip: $("#irIp").value.trim(),
    tunnel: { enabled: $("#irTun").checked, name: $("#tnName").value.trim(), kind: $("#tnKind").value,
              foreign_ep: $("#tnFE").value.trim(), iran_ep: $("#tnIE").value.trim(), foreign_ip: $("#tnF4").value.trim(), iran_ip: $("#tnI4").value.trim() },
  };
  try {
    const r = await api("links/new-iran", "POST", body);
    cmdLink = r.link;
    const url = location.origin + "/dl/" + r.token;
    $("#irCmdText").textContent = "bash <(curl -fsSL" + (location.protocol === "https:" ? "k" : "") + " \"" + url + "\")";
    $("#irTabs").classList.add("hidden"); $("#irCmd").classList.add("hidden"); $("#irCmdOut").classList.remove("hidden");
    $("#irCmdState").textContent = "در انتظار نصب روی سرور ایران…";
    clearInterval(cmdTimer);
    cmdTimer = setInterval(async () => {
      try {
        const d = await api("links");
        const l = d.links.find((x) => x.id === cmdLink.id);
        if (l && l.installed) { clearInterval(cmdTimer); $("#irCmdState").textContent = "✓ نصب شد و همگام‌سازی شروع شد."; loadLinks(); loadTunnels(true); refresh(true); }
      } catch (_) {}
    }, 3000);
    loadLinks();
  } catch (e) { $("#irErr").textContent = e.message; }
});
$("#irCmdCopy").onclick = () => navigator.clipboard.writeText($("#irCmdText").textContent).then(() => toast("کپی شد"));
$("#irCmdFile").onclick = () => cmdLink && downloadInstaller(cmdLink);
$("#iranDlg").addEventListener("close", () => clearInterval(cmdTimer));

/* ---------- tunnels ---------- */
let tunnels = [], tunTests = {}, tunBusy = {}, tunSteps = {}, tunLinked = {};
const KIND = { gre4: "GRE4", gre6: "GRE6" };
const STATUS_FA = { healthy: "سالم", degraded: "ضعیف", down: "قطع", unknown: "تست نشده", busy: "در حال کار…" };

async function loadTunnels(first) {
  try {
    const d = await api("tunnels");
    tunnels = d.tunnels; tunLinked = d.linked || {};
    renderTunnels();
    if (first) testAllTunnels();
  } catch (_) {}
}

async function testAllTunnels() {
  for (const t of tunnels) {
    if (tunBusy[t.name]) continue;
    try { tunTests[t.name] = (await api("tunnels/" + t.name + "/test", "POST")).result; } catch (_) {}
    renderTunnels();
  }
}

function tunStatus(t) {
  if (tunBusy[t.name]) return "busy";
  const r = tunTests[t.name];
  return r ? r.status : (t.up ? "unknown" : "down");
}

function healthLine(t) {
  const r = tunTests[t.name];
  const d = el("div", "health");
  if (tunBusy[t.name]) { d.textContent = tunBusy[t.name]; return d; }
  if (!r) { d.append(el("span", "mid", t.up ? "هنوز تست نشده" : "اینترفیس پایین است")); return d; }
  const cls = r.status === "healthy" ? "good" : r.status === "degraded" ? "mid" : "bad";
  d.append(el("span", cls, STATUS_FA[r.status]));
  if (r.status !== "down" && r.rtt) d.append(document.createTextNode("  •  تأخیر " + fa(r.rtt.avg.toFixed(1)) + " میلی‌ثانیه  •  نوسان " + fa(r.rtt.jitter.toFixed(1)) + "  •  افت " + fa(Math.round(r.loss)) + "٪"));
  else d.append(document.createTextNode(r.outer_ok ? "  •  مسیر بیرونی سالم است ولی از داخل تونل جواب نمی‌آید" : "  •  سر مقابل از مسیر بیرونی هم جواب نمی‌دهد"));
  return d;
}

function tunnelCard(t) {
  const st = tunStatus(t);
  const c = el("div", "tun " + st);
  const top = el("div", "top");
  const alias = ((live && live.ifaces) || []).find((i) => i.name === t.name);
  top.append(el("span", "dot"), el("b", "", (alias && alias.alias) || t.name));
  const ed = el("button", "pencil", "✎"); ed.type = "button"; ed.title = "تغییر نام نمایشی";
  ed.onclick = () => openName({ name: t.name, alias: (alias && alias.alias) || "" });
  top.append(ed, el("span", "kbadge k", KIND[t.kind] || t.kind), el("span", "kbadge", "MTU " + fa(t.mtu_live || t.mtu)));
  if (tunLinked[t.name]) top.append(el("span", "kbadge", "↔ " + tunLinked[t.name]));
  c.append(top);
  c.append(el("div", "ep", t.local + "  →  " + t.remote));
  c.append(el("div", "inner", t.ip.split("/")[0] + "  ↔  " + t.peer_ip));
  c.append(healthLine(t));

  const btns = el("div", "btns");
  const mk = (txt, what, title) => { const b = el("button", "btn icon", txt); b.type = "button"; b.title = title || ""; b.disabled = !!tunBusy[t.name]; b.onclick = () => runTun(t, what); btns.append(b); };
  mk("تست", "test", "۱۰ پینگ از داخل تونل + مسیر بیرونی");
  mk("بهینه‌سازی", "optimize", "کشف MTU واقعی، کلمپ MSS، تنظیمات کرنل");
  mk("رفع ایراد", "fix", "بررسی و تعمیر خودکار");
  const more = el("button", "btn icon", "⋯"); more.type = "button"; more.disabled = !!tunBusy[t.name];
  more.onclick = () => tunMenu(t);
  btns.append(more);
  c.append(btns);

  const sd = tunSteps[t.name];
  if (sd) {
    const box = el("div", "steps");
    sd.items.forEach((s) => box.append(el("div", "s " + (s.fixed ? "fx" : s.ok ? "ok" : "no"), (s.fixed ? "⚙ " : s.ok ? "✓ " : "! ") + s.msg)));
    const x = el("button", "btn ghost", "بستن"); x.type = "button"; x.onclick = () => { delete tunSteps[t.name]; renderTunnels(); };
    box.append(x);
    c.append(box);
  }
  return c;
}

function renderTunnels() {
  $("#tunnelsCard").classList.toggle("hidden", !tunnels.length);
  const g = $("#tunGrid");
  g.replaceChildren();
  tunnels.forEach((t) => g.append(tunnelCard(t)));
}

async function runTun(t, what) {
  const label = { test: "در حال تست…", optimize: "در حال بهینه‌سازی (کشف MTU، چند ثانیه)…", fix: "در حال بررسی و تعمیر…", restart: "در حال ریستارت…" }[what];
  tunBusy[t.name] = label; renderTunnels();
  try {
    if (what === "test") tunTests[t.name] = (await api("tunnels/" + t.name + "/test", "POST")).result;
    else {
      const d = await api("tunnels/" + t.name + "/" + what, "POST");
      if (what === "optimize") tunSteps[t.name] = { items: [{ ok: true, msg: "MTU " + fa(d.mtu_before) + " ← " + fa(d.mtu_after) }, ...d.steps] };
      if (what === "fix") tunSteps[t.name] = { items: d.checks };
      tunTests[t.name] = (await api("tunnels/" + t.name + "/test", "POST")).result;
    }
  } catch (e) { toast(e.message, true); }
  delete tunBusy[t.name];
  loadTunnels(false);
}

function tunMenu(t) {
  const v = prompt("برای «" + t.name + "» یکی را بنویس:\n  mtu  ← تغییر MTU\n  restart  ← ریستارت تونل\n  delete  ← حذف تونل", "");
  if (!v) return;
  const w = v.trim().toLowerCase();
  if (w === "restart") return runTun(t, "restart");
  if (w === "mtu") {
    const m = prompt("MTU جدید (۱۲۸۰ تا ۱۵۰۰):", t.mtu_live || t.mtu);
    if (!m) return;
    api("tunnels/" + t.name, "PUT", { mtu: parseInt(m, 10) }).then(() => { toast("MTU تغییر کرد"); loadTunnels(false); }).catch((e) => toast(e.message, true));
    return;
  }
  if (w === "delete") {
    const force = !!tunLinked[t.name];
    if (!confirm("تونل «" + t.name + "» حذف شود؟" + (force ? "\nاین تونل برای لینک «" + tunLinked[t.name] + "» ساخته شده و ترافیک آن قطع می‌شود." : ""))) return;
    api("tunnels/" + t.name + (force ? "?force=1" : ""), "DELETE").then(() => { toast("تونل حذف شد"); delete tunTests[t.name]; loadTunnels(false); }).catch((e) => toast(e.message, true));
  }
}

$("#btnTunRefresh").onclick = () => testAllTunnels();
$("#btnTune").onclick = async () => {
  $("#btnTune").disabled = true;
  try {
    const d = await api("system/tune", "POST");
    toast(d.steps.map((s) => s.msg).slice(0, 3).join(" • "));
  } catch (e) { toast(e.message, true); }
  $("#btnTune").disabled = false;
};
