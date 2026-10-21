'use strict';
/* ===== Cisco AI Firewall Auditor — Dashboard (Vanilla JS) ===== */

const $ = (id) => document.getElementById(id);
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

const SEV = {
  CRITICA: { label: 'CRÍTICA (Atención Inmediata)', color: 'hsl(354,78%,56%)' },
  ALTA: { label: 'ALTA (Riesgo Significativo)', color: 'hsl(27,96%,56%)' },
  MEDIA: { label: 'MEDIA (Revisión Preventiva)', color: 'hsl(43,96%,58%)' },
  BAJA: { label: 'BAJA (Higiene y Limpieza)', color: 'hsl(165,66%,42%)' },
};
const CAT_COLORS = ['hsl(354,78%,56%)', 'hsl(27,96%,56%)', 'hsl(43,96%,58%)', 'hsl(165,66%,42%)', 'hsl(207,44%,49%)', 'hsl(266,80%,62%)', 'hsl(190,100%,42%)', 'hsl(330,70%,58%)'];
const ZONE_COLOR = { WAN: '#e5384f', internet: '#e5384f', firewall: '#3b82f6', DMZ: '#f5c542', LAN: '#25b583', GESTION: '#8b5cf6' };
const ZONE_ICON = { WAN: '🌐', internet: '☁️', firewall: '🛡️', DMZ: '🖥️', LAN: '💻', GESTION: '⚙️' };

let S = null;               // resumen de la sesión actual
let filter = null;          // { kind: 'sev'|'cat', value }
const planSel = {};         // id hallazgo -> 'A' | 'B'
const cmdStore = [];        // comandos copiables
let lastFile = null;

/* ---------------------------------------------------------------- API */
async function api(path, opts = {}) {
  const res = await fetch(path, opts);
  if (!res.ok) {
    let detail = res.statusText;
    try { const j = await res.json(); detail = typeof j.detail === 'string' ? j.detail : JSON.stringify(j.detail); } catch (_) { /* sin cuerpo */ }
    throw new Error(detail);
  }
  return res.json();
}
const post = (path, body) => api(path, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });

function toast(msg, kind = 'err') {
  const el = document.createElement('div');
  el.className = `alert ${kind}`;
  el.style.cssText = 'position:fixed;right:20px;bottom:20px;z-index:99;max-width:420px;backdrop-filter:blur(14px)';
  el.textContent = msg;
  document.body.appendChild(el);
  setTimeout(() => el.remove(), 5200);
}

async function download(path, fallbackName) {
  try {
    const res = await fetch(path);
    if (!res.ok) { const j = await res.json().catch(() => ({})); throw new Error(j.detail || res.statusText); }
    const cd = res.headers.get('Content-Disposition') || '';
    const name = (cd.match(/filename="([^"]+)"/) || [])[1] || fallbackName;
    const url = URL.createObjectURL(await res.blob());
    const a = Object.assign(document.createElement('a'), { href: url, download: name });
    document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(url);
  } catch (e) { toast(e.message); }
}

/* ---------------------------------------------------------------- Estado de servicios */
async function refreshStatus() {
  try {
    const st = await api('/api/status');
    $('dotBatfish').className = 'dot ' + (st.batfish.ok ? 'ok' : 'bad');
    $('txtBatfish').textContent = st.batfish.ok ? 'Batfish conectado' : 'Batfish no disponible';
    $('dotBatfish').parentElement.title = st.batfish.detalle;
    $('dotGemini').className = 'dot ' + (st.gemini.ok ? 'ok' : 'bad');
    $('txtGemini').textContent = st.gemini.ok ? `Gemini · ${st.gemini.modelo}` : 'Gemini sin API key';
  } catch (_) { $('txtBatfish').textContent = 'Servidor sin respuesta'; }
}

/* ---------------------------------------------------------------- Carga / auditoría */
function sanitizeOn() { return $('optSanitize').checked; }
function updateSanBadge() {
  const on = sanitizeOn();
  const b = $('sanBadge');
  b.className = 'badge-zero' + (on ? '' : ' off');
  b.textContent = on ? '● Protección Zero-Leak activa' : '● Sanitización desactivada — la config viaja sin enmascarar';
}

async function runAudit(promiseFactory) {
  const stages = $('stages');
  stages.classList.add('active');
  stages.querySelectorAll('.stage').forEach((s) => s.classList.remove('done'));
  $('uploadMsg').innerHTML = '';
  document.querySelectorAll('#demoButtons .btn, #dropzone').forEach((b) => (b.style.pointerEvents = 'none'));
  try {
    S = await promiseFactory();
    stages.querySelectorAll('.stage').forEach((s) => s.classList.add('done'));
    Object.keys(planSel).forEach((k) => delete planSel[k]);
    filter = null;
    render();
  } catch (e) {
    $('uploadMsg').innerHTML = `<div class="alert err">❌ ${esc(e.message)}</div>`;
    stages.classList.remove('active');
  } finally {
    document.querySelectorAll('#demoButtons .btn, #dropzone').forEach((b) => (b.style.pointerEvents = ''));
  }
}

function auditFile(file) {
  if (!file) return;
  lastFile = file;
  runAudit(() => {
    const fd = new FormData();
    fd.append('archivo', file);
    fd.append('sanitize', sanitizeOn());
    fd.append('use_ai', $('optAI').checked);
    return api('/api/audit', { method: 'POST', body: fd });
  });
}

function setupUpload() {
  const dz = $('dropzone'), fi = $('fileInput');
  dz.addEventListener('click', () => fi.click());
  dz.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') fi.click(); });
  fi.addEventListener('change', () => auditFile(fi.files[0]));
  ['dragenter', 'dragover'].forEach((ev) => dz.addEventListener(ev, (e) => { e.preventDefault(); dz.classList.add('drag'); }));
  ['dragleave', 'drop'].forEach((ev) => dz.addEventListener(ev, (e) => { e.preventDefault(); dz.classList.remove('drag'); }));
  dz.addEventListener('drop', (e) => auditFile(e.dataTransfer.files[0]));
  $('optSanitize').addEventListener('change', updateSanBadge);
  updateSanBadge();
  api('/api/demos').then((demos) => {
    $('demoButtons').innerHTML = demos.map((d) => `<button class="btn" data-demo="${esc(d.id)}">🧪 Demo ${esc(d.etiqueta)}</button>`).join('');
    $('demoButtons').querySelectorAll('button').forEach((b) =>
      b.addEventListener('click', () => runAudit(() => api(`/api/demo/${b.dataset.demo}?sanitize=${sanitizeOn()}`, { method: 'POST' }))));
  }).catch(() => { });
}

/* ---------------------------------------------------------------- Render principal */
function render() {
  $('results').classList.add('visible');
  $('hostName').textContent = S.hostname;
  $('hostMeta').textContent = `${S.dialecto} · ${S.archivo} · ` +
    (S.sanitizar ? `🔒 ${S.sanitizacion.ips} IPs y ${S.sanitizacion.secretos} secretos enmascarados` : '⚠️ sin sanitización');
  $('execSummary').textContent = S.resumen ? S.resumen.resumen_gerencial : '';
  const r = S.resumen;
  gauge('gaugeNow', 'Postura actual', r ? r.score_seguridad_actual : null, 'hsl(354,78%,56%)');
  gauge('gaugeProj', 'Postura proyectada', r ? r.score_seguridad_proyectado : null, 'hsl(158,64%,48%)',
    r ? `+${r.score_seguridad_proyectado - r.score_seguridad_actual} pts` : '');
  renderDonuts();
  renderFindings();
  Topo.load(S.grafo);
  setupSim();
  $('matrixOut').innerHTML = '<span class="empty">Pulsa el botón para evaluar la segmentación entre zonas.</span>';
  const hasReport = !!S.resumen;
  ['btnPdf', 'btnMd', 'btnRem', 'btnRoll', 'btnDiffA', 'btnDiffB'].forEach((id) => ($(id).disabled = !hasReport));
  $('results').scrollIntoView({ behavior: 'smooth' });
}

function gauge(id, label, score, color, gain = '') {
  const C = 2 * Math.PI * 52;
  const val = score == null ? 0 : score;
  $(id).innerHTML = `
    <svg viewBox="0 0 120 120" role="img" aria-label="${esc(label)}">
      <circle class="gauge-track" cx="60" cy="60" r="52" fill="none" stroke-width="9"/>
      <circle id="${id}Arc" cx="60" cy="60" r="52" fill="none" stroke="${color}" stroke-width="9" stroke-linecap="round"
        stroke-dasharray="${C}" stroke-dashoffset="${C}" transform="rotate(-90 60 60)" style="transition:stroke-dashoffset 1.2s ease;filter:drop-shadow(0 0 6px ${color})"/>
      <text x="60" y="68" text-anchor="middle" class="num" fill="currentColor" style="font-size:30px;font-weight:700">${score == null ? 'N/D' : score}</text>
    </svg>
    <div class="lbl">${esc(label)}</div>${gain ? `<span class="gain">${esc(gain)}</span>` : ''}`;
  requestAnimationFrame(() => setTimeout(() => { $(id + 'Arc').style.strokeDashoffset = C * (1 - val / 100); }, 60));
}

/* ---------------------------------------------------------------- Donuts */
function renderDonuts() {
  const sevOrder = ['CRITICA', 'ALTA', 'MEDIA', 'BAJA'];
  const sevData = sevOrder.filter((k) => S.distribucion.severidad[k]).map((k) => ({ key: k, label: SEV[k].label, count: S.distribucion.severidad[k], color: SEV[k].color }));
  const cats = Object.entries(S.distribucion.categoria).sort((a, b) => b[1] - a[1]);
  const catData = cats.map(([k, v], i) => ({ key: k, label: k, count: v, color: CAT_COLORS[i % CAT_COLORS.length] }));
  donut('donutSev', sevData, 'sev');
  donut('donutCat', catData, 'cat');
}

function donut(containerId, data, kind) {
  const el = $(containerId);
  const total = data.reduce((a, d) => a + d.count, 0);
  if (!total) { el.innerHTML = '<span class="empty">Sin hallazgos de IA para graficar.</span>'; return; }
  let acc = 0;
  const gap = data.length > 1 ? 0.6 : 0;
  const segs = data.map((d, i) => {
    const pct = (d.count / total) * 100;
    const seg = `<circle class="seg" data-i="${i}" cx="21" cy="21" r="15.9155" stroke="${d.color}" color="${d.color}"
      stroke-dasharray="${Math.max(pct - gap, 0.1)} ${100 - Math.max(pct - gap, 0.1)}" stroke-dashoffset="${-acc}"><title>${esc(d.label)}: ${d.count}</title></circle>`;
    acc += pct;
    return seg;
  }).join('');
  el.innerHTML = `
    <div class="donut-wrap"><svg viewBox="0 0 42 42">${segs}</svg>
      <div class="donut-center"><b>${total}</b><span>HALLAZGOS</span></div></div>
    <div class="legend">${data.map((d, i) => `
      <div class="legend-item" data-i="${i}"><i style="background:${d.color}"></i><span>${esc(d.label)}</span>
      <em>${d.count} (${((d.count / total) * 100).toFixed(1)}%)</em></div>`).join('')}</div>`;
  const wrap = el.querySelector('.donut-wrap');
  const setHi = (i) => {
    el.querySelectorAll('.seg,.legend-item').forEach((n) => n.classList.toggle('hi', i !== null && +n.dataset.i === i));
    wrap.classList.toggle('dim', i !== null);
  };
  el.querySelectorAll('.seg,.legend-item').forEach((n) => {
    const i = +n.dataset.i;
    n.addEventListener('mouseenter', () => setHi(i));
    n.addEventListener('mouseleave', () => setHi(null));
    n.addEventListener('click', () => { setFilter({ kind, value: data[i].key }); document.getElementById('findTitle').scrollIntoView({ behavior: 'smooth' }); });
  });
}

/* ---------------------------------------------------------------- Hallazgos */
function setFilter(f) {
  filter = filter && f && filter.kind === f.kind && filter.value === f.value ? null : f;
  renderFindings();
}

function diffCode(cmds) {
  return cmds.map((c) => {
    const t = c.trim();
    if (/^(configure terminal|conf t|end|exit|write memory)$/i.test(t)) return `<span class="ctx">  ${esc(c)}</span>`;
    if (/^no\s/i.test(t)) return `<span class="del">- ${esc(c)}</span>`;
    return `<span class="add">+ ${esc(c)}</span>`;
  }).join('');
}
function codeBox(cmds, asDiff = true) {
  const idx = cmdStore.push(cmds.join('\n')) - 1;
  return `<div class="codebox"><button class="btn sm copy" data-copy="${idx}">Copiar</button>${asDiff ? diffCode(cmds) : esc(cmds.join('\n'))}</div>`;
}

function findingCard(h) {
  const sel = planSel[h.id_hallazgo] || 'A';
  const plan = sel === 'A' ? h.plan_a_recomendado : h.plan_b_conservador;
  const rows = h.desglose_visual.map((r) => `<tr>
      <td><b>${esc(r.rol)}</b></td><td>${esc(r.secuencia)}</td>
      <td class="${/permit/i.test(r.accion) ? 'permit' : 'deny'}">${/permit/i.test(r.accion) ? '🟢' : '🔴'} ${esc(r.accion.toUpperCase())}</td>
      <td>${esc(r.protocolo)}</td><td>${esc(r.origen)}</td><td>${esc(r.destino)}</td><td>${esc(r.puerto)}</td><td>${esc(r.estado_flujo)}</td></tr>`).join('');
  return `<article class="card finding ${planSel['_open_' + h.id_hallazgo] ? 'open' : ''}" data-id="${esc(h.id_hallazgo)}">
    <div class="finding-head"><span class="chev">▶</span><span class="sev ${esc(h.severidad)}">${esc(h.severidad)}</span>
      <h3>${esc(h.categoria_problema)} · <span style="color:var(--muted)">${esc(h.acl_o_componente)}</span></h3>
      <span class="id">${esc(h.id_hallazgo)}</span>${h.confirmado_por_batfish ? '<span class="badge-zero">✔ Batfish</span>' : '<span class="badge-zero off">Semántico</span>'}</div>
    <div class="finding-body">
      <p class="block-label">Regla afectada</p><div class="codebox">${esc(h.linea_o_regla_afectada)}</div>
      ${rows ? `<p class="block-label">Comparativa y colisión de reglas</p><div style="overflow-x:auto"><table><thead><tr><th>Rol</th><th>Línea</th><th>Acción</th><th>Proto</th><th>Origen</th><th>Destino</th><th>Puerto</th><th>Estado</th></tr></thead><tbody>${rows}</tbody></table></div>` : ''}
      ${h.punto_critico_error ? `<div class="critical-point">⚠️ <b>Punto crítico del error:</b> ${esc(h.punto_critico_error)}</div>` : ''}
      <p class="block-label">Controles normativos incumplidos</p>
      <ul class="ctrl-list">${h.controles_normativos.map((c) => `<li>${esc(c)}</li>`).join('') || '<li>Sin controles asignados</li>'}</ul>
      <p class="block-label">Diagnóstico técnico</p><p>${esc(h.diagnostico_tecnico)}</p>
      <p class="block-label">Cómo mejora la red</p><p>${esc(h.como_mejora_la_red)}</p>
      <p class="block-label">Blast radius · ${esc(h.nivel_impacto_operativo)}</p><p>${esc(h.analisis_blast_radius)}</p>
      <p class="block-label">Decisión</p>
      <div class="tabs" role="tablist">
        <button class="tab ${sel === 'A' ? 'on' : ''}" data-plan="A" role="tab">Plan A · Hardening</button>
        <button class="tab ${sel === 'B' ? 'on' : ''}" data-plan="B" role="tab">Plan B · Transición</button></div>
      <p><b>${esc(plan.nombre_plan)}</b> — ${esc(plan.descripcion_accion)}</p>
      <p style="color:var(--muted);margin:4px 0 8px">Efecto en red: ${esc(plan.efecto_en_red)}</p>
      ${codeBox(plan.comandos_cli_implementacion)}
      <p class="block-label">Rollback inmediato</p>${codeBox(plan.comandos_cli_rollback, false)}
    </div></article>`;
}

function renderFindings() {
  // aviso de origen del reporte
  let notice = '';
  if (S.fuente_reporte === 'none') notice = `<div class="alert warn">⚠️ Sin reporte de IA${S.error_ia ? ': ' + esc(S.error_ia) : ' (análisis con Gemini desactivado)'}. Se muestran solo las anomalías formales de Batfish.</div>`;
  else if (S.fuente_reporte === 'cache') notice = `<div class="alert warn">ℹ️ Reporte de IA cargado desde la caché local <code>reports/</code> (demo)${S.error_ia ? ' · fallo de Gemini: ' + esc(S.error_ia) : ''}.</div>`;
  $('aiNotice').innerHTML = notice;

  if (!S.hallazgos.length) {
    $('filters').innerHTML = '';
    $('findings').innerHTML = S.matematicos.length ? `<article class="card"><h2>Anomalías confirmadas por Batfish</h2>${mathTable(S.matematicos)}</article>` : '<div class="empty">Sin hallazgos.</div>';
    return;
  }
  const chips = [`<span class="chip ${!filter ? 'on' : ''}" data-clear="1">Todos (${S.hallazgos.length})</span>`];
  Object.keys(S.distribucion.severidad).forEach((k) => chips.push(`<span class="chip ${filter && filter.value === k ? 'on' : ''}" data-kind="sev" data-v="${esc(k)}">${esc(k)} (${S.distribucion.severidad[k]})</span>`));
  $('filters').innerHTML = chips.join('');
  $('filters').querySelectorAll('.chip').forEach((c) => c.addEventListener('click', () => (c.dataset.clear ? setFilter(null) : setFilter({ kind: c.dataset.kind, value: c.dataset.v }))));

  const list = S.hallazgos.filter((h) => !filter || (filter.kind === 'sev' ? h.severidad === filter.value : h.categoria_problema === filter.value));
  cmdStore.length = 0;
  $('findings').innerHTML = list.map(findingCard).join('') || '<div class="empty">Ningún hallazgo coincide con el filtro.</div>';
  $('findings').querySelectorAll('.finding').forEach((card) => {
    const id = card.dataset.id;
    card.querySelector('.finding-head').addEventListener('click', () => { card.classList.toggle('open'); planSel['_open_' + id] = card.classList.contains('open'); });
    card.querySelectorAll('.tab').forEach((t) => t.addEventListener('click', () => { planSel[id] = t.dataset.plan; planSel['_open_' + id] = true; renderFindings(); }));
  });
  $('findings').querySelectorAll('[data-copy]').forEach((b) => b.addEventListener('click', async () => {
    await navigator.clipboard.writeText(cmdStore[+b.dataset.copy]); b.textContent = '¡Copiado!'; setTimeout(() => (b.textContent = 'Copiar'), 1400);
  }));
}

function mathTable(rows) {
  return `<div style="overflow-x:auto"><table><thead><tr><th>Tipo</th><th>ACL</th><th>Línea</th><th>Bloqueada por</th><th>Descripción</th></tr></thead><tbody>${rows.map((m) => `
    <tr><td><b>${esc(m.tipo)}</b></td><td>${esc(m.filtro_nombre)}</td><td style="font-family:var(--mono);font-size:.78rem">${esc(m.linea_afectada)}</td>
    <td style="font-family:var(--mono);font-size:.78rem">${esc(m.linea_bloqueadora || '—')}</td><td>${esc(m.descripcion)}</td></tr>`).join('')}</tbody></table></div>`;
}

/* ---------------------------------------------------------------- Modales */
function openModal(title, html) {
  $('modalTitle').textContent = title;
  $('modalBody').innerHTML = html;
  $('modalBg').classList.add('open');
}
const closeModal = () => $('modalBg').classList.remove('open');
const loading = (t) => openModal(t, '<div class="empty"><span class="spinner"></span><p style="margin-top:12px">Consultando el Digital Twin en Batfish…</p></div>');

async function batfishModal(title, fn) {
  loading(title);
  try { openModal(title, await fn()); } catch (e) { openModal(title, `<div class="alert err">❌ ${esc(e.message)}</div>`); }
}

function highlightTokens(text, tokens, cls) {
  let out = esc(text);
  tokens.filter(Boolean).forEach((t) => { out = out.split(esc(t)).join(`<mark class="${cls}">${esc(t)}</mark>`); });
  return out;
}

async function showSanitization() {
  loading('Reemplazos de sanitización');
  try {
    const v = await api(`/api/session/${S.id}/sanitization`);
    const origs = v.reemplazos.map((r) => r.original), news = v.reemplazos.map((r) => r.reemplazo);
    const table = v.reemplazos.length ? `<table><thead><tr><th>Tipo</th><th>Valor original</th><th>Reemplazo enviado a Gemini</th><th>Ocurrencias</th></tr></thead><tbody>${v.reemplazos.map((r) => `
      <tr><td>${esc(r.tipo)}</td><td class="orig" style="font-family:var(--mono)">${esc(r.original)}</td><td style="font-family:var(--mono);color:var(--ok)">${esc(r.reemplazo)}</td><td>${r.ocurrencias}</td></tr>`).join('')}</tbody></table>` :
      '<div class="empty">No se encontraron IPs públicas ni secretos para enmascarar.</div>';
    const diff = v.diff.length ? `<div class="diff-grid"><div class="hd">Línea</div><div class="hd">Original</div><div class="hd">Sanitizado (lo que ve Gemini)</div>${v.diff.map((d) => `
      <div class="ln">${d.linea}</div><div class="l orig">${highlightTokens(d.original, origs, 'o')}</div><div class="r">${highlightTokens(d.sanitizado, news, 'n')}</div>`).join('')}</div>` :
      '<div class="empty">La configuración enviada es idéntica a la original.</div>';
    openModal(`Reemplazos de sanitización · ${v.total_ips} IPs · ${v.total_secretos} secretos · ${v.lineas_modificadas}/${v.total_lineas} líneas`,
      `${v.activa ? '' : '<div class="alert warn">La sanitización estaba desactivada: no se enmascaró nada.</div>'}
       <div class="btn-row" style="margin-bottom:14px"><div class="tabs"><button class="tab on" data-t="tbl">Tabla de mapeo</button><button class="tab" data-t="diff">Diff original vs. sanitizado</button></div>
       <button class="btn sm" id="btnBlur">👁️ Ocultar valores originales</button></div>
       <p class="meta">🔐 Los secretos nunca salen del servidor en claro: se muestran enmascarados (ej. <code>ci***r</code>).</p>
       <div id="tabTbl">${table}</div><div id="tabDiff" style="display:none">${diff}</div>`);
    $('modalBody').querySelectorAll('.tab').forEach((t) => t.addEventListener('click', () => {
      $('modalBody').querySelectorAll('.tab').forEach((x) => x.classList.toggle('on', x === t));
      $('tabTbl').style.display = t.dataset.t === 'tbl' ? '' : 'none';
      $('tabDiff').style.display = t.dataset.t === 'diff' ? '' : 'none';
    }));
    $('btnBlur').addEventListener('click', () => {
      const on = $('modalBody').querySelector('.orig').classList.toggle('blur');
      $('modalBody').querySelectorAll('.orig').forEach((n) => n.classList.toggle('blur', on));
      $('btnBlur').textContent = on ? '👁️ Mostrar valores originales' : '👁️ Ocultar valores originales';
    });
  } catch (e) { openModal('Reemplazos de sanitización', `<div class="alert err">❌ ${esc(e.message)}</div>`); }
}

const showShadowing = () => batfishModal('Reglas pisadas y redundantes (filterLineReachability)', async () => {
  const d = await api(`/api/session/${S.id}/shadowing`);
  return d.reglas.length ? mathTable(d.reglas) : '<div class="empty">✅ Batfish no encontró reglas inalcanzables ni redundantes.</div>';
});

const showExposure = () => batfishModal('Puertos críticos expuestos desde WAN (searchFilters)', async () => {
  const d = await api(`/api/session/${S.id}/exposure`);
  if (!d.exposiciones.length) return '<div class="empty">✅ Batfish no encontró flujos permitidos hacia servicios críticos en las ACLs de entrada WAN.</div>';
  return `<div class="alert err">🚨 ${d.exposiciones.length} exposición(es) confirmada(s) formalmente.</div><table><thead><tr><th>ACL</th><th>Servicio</th><th>Puerto</th><th>Regla que lo permite</th><th>Flujo de ejemplo</th></tr></thead><tbody>${d.exposiciones.map((x) => `
    <tr><td>${esc(x.acl)}</td><td><b>${esc(x.servicio)}</b></td><td>${esc(x.protocolo)}/${x.puerto}</td><td style="font-family:var(--mono);font-size:.76rem">${esc(x.regla)}</td><td style="font-family:var(--mono);font-size:.72rem;color:var(--muted)">${esc(x.flujo_ejemplo)}</td></tr>`).join('')}</tbody></table>`;
});

const showDiff = (plan) => batfishModal(`Digital Twin diferencial · Plan ${plan} vs. configuración actual`, async () => {
  const d = await post(`/api/session/${S.id}/diff`, { plan });
  const changes = d.cambios.length ? `<table><thead><tr><th>Hallazgo</th><th>ACL</th><th>Ahora</th><th>Línea nueva</th><th>Línea anterior</th></tr></thead><tbody>${d.cambios.map((c) => `
    <tr><td style="font-family:var(--mono);font-size:.76rem">${esc(c.id_hallazgo || 'conjunto')}</td><td>${esc(c.acl)}</td><td class="${/permit/i.test(c.accion_nueva) ? 'permit' : 'deny'}">${esc(c.accion_nueva)}</td><td style="font-family:var(--mono);font-size:.76rem">${esc(c.linea_nueva)}</td><td style="font-family:var(--mono);font-size:.76rem;color:var(--muted)">${esc(c.linea_anterior)}</td></tr>`).join('')}</tbody></table>` :
    '<div class="empty">Sin cambios de comportamiento: los flujos se tratan igual que antes.</div>';
  const cfg = d.diff_config.map((l) => `<span class="${l.startsWith('+') && !l.startsWith('+++') ? 'add' : l.startsWith('-') && !l.startsWith('---') ? 'del' : l.startsWith('@@') ? 'hunk' : 'ctx'}">${esc(l)}</span>`).join('');
  return `<div class="alert ${d.total_cambios ? 'warn' : 'err'}" style="margin-bottom:14px">🔀 <b>${d.total_cambios}</b> par(es) de líneas tratan distinto un mismo flujo (compareFilters).</div>
    ${d.errores.length ? `<div class="alert err">Batfish no pudo comparar: ${esc(d.errores.join(' · '))}</div>` : ''}
    ${(d.no_verificables || []).length ? `<div class="alert warn">ℹ️ No verificables con compareFilters: ${d.no_verificables.map((n) => `<b>${esc(n.id)}</b>`).join(', ')}. ${esc(d.no_verificables[0].motivo)}</div>` : ''}
    <p class="block-label">Flujos que cambian de comportamiento</p>${changes}
    <p class="block-label">Configuración candidata (diff sintáctico)</p><div class="codebox">${cfg || '<span class="ctx">Sin cambios</span>'}</div>`;
});

/* ---------------------------------------------------------------- Matriz de aislamiento */
async function loadMatrix() {
  $('matrixOut').innerHTML = '<div class="empty"><span class="spinner"></span></div>';
  try {
    const d = await api(`/api/session/${S.id}/isolation`);
    const get = (o, t) => d.celdas.find((c) => c.origen === o && c.destino === t);
    $('matrixOut').innerHTML = `<div style="overflow-x:auto"><table class="matrix"><thead><tr><th>Origen ↓ / Destino →</th>${d.zonas.map((z) => `<th>${esc(z)}</th>`).join('')}</tr></thead><tbody>
      ${d.zonas.map((o) => `<tr><th>${esc(o)}</th>${d.zonas.map((t) => {
        if (o === t) return '<td style="color:var(--muted)">—</td>';
        const c = get(o, t);
        return c ? `<td><span class="cell ${esc(c.estado)}" data-o="${esc(o)}" data-t="${esc(t)}" title="${esc(c.detalle)}">${esc(c.estado)}</span></td>` : '<td>—</td>';
      }).join('')}</tr>`).join('')}</tbody></table></div>`;
    $('matrixOut').querySelectorAll('.cell').forEach((c) => c.addEventListener('click', () => {
      $('simSrcZone').value = c.dataset.o; $('simDstZone').value = c.dataset.t;
      fillIps(); Topo.highlight(c.dataset.o, c.dataset.t);
      $('topoTitle').scrollIntoView({ behavior: 'smooth' });
    }));
  } catch (e) { $('matrixOut').innerHTML = `<div class="alert err">❌ ${esc(e.message)}</div>`; }
}

/* ---------------------------------------------------------------- Simulador */
const ipToInt = (ip) => ip.split('.').reduce((a, o) => (a << 8) + (+o), 0) >>> 0;
const intToIp = (n) => [24, 16, 8, 0].map((s) => (n >>> s) & 255).join('.');
function inSubnet(ip, cidr) {
  try { const [b, m] = cidr.split('/'); const mask = m == 0 ? 0 : (~0 << (32 - m)) >>> 0; return (ipToInt(ip) & mask) === (ipToInt(b) & mask); } catch (_) { return false; }
}
function hostIn(cidr, n) {
  const [b, m] = cidr.split('/'); const size = 2 ** (32 - m);
  return intToIp(ipToInt(b) + Math.min(n, Math.max(size - 2, 1)));
}
const zoneByName = (n) => S.grafo.zonas.find((z) => z.nombre === n);

function fillIps() {
  const s = zoneByName($('simSrcZone').value), d = zoneByName($('simDstZone').value);
  $('simSrcIp').value = s ? (s.zona === 'WAN' ? '8.8.8.8' : hostIn(s.subred, 100)) : '';
  $('simDstIp').value = d ? hostIn(d.subred, d.zona === 'DMZ' ? 50 : 100) : '';
}

function setupSim() {
  const zs = S.grafo.zonas;
  const opts = zs.map((z) => `<option value="${esc(z.nombre)}">${esc(z.nombre)} · ${esc(z.subred)}</option>`).join('');
  $('simSrcZone').innerHTML = opts; $('simDstZone').innerHTML = opts;
  const wan = zs.find((z) => z.zona === 'WAN'), dmz = zs.find((z) => z.zona === 'DMZ') || zs.find((z) => z !== wan);
  if (wan) $('simSrcZone').value = wan.nombre;
  if (dmz) $('simDstZone').value = dmz.nombre;
  fillIps();
  $('simResult').className = 'sim-result';
}

async function runSim() {
  const [proto, portSvc] = $('simService').value.split(':');
  const custom = $('simPort').value;
  const body = {
    zona_origen: $('simSrcZone').value, src_ip: $('simSrcIp').value.trim(), dst_ip: $('simDstIp').value.trim(),
    protocolo: proto, puerto: proto === 'ICMP' ? null : (custom ? +custom : +portSvc),
  };
  const box = $('simResult');
  box.className = 'sim-result show';
  box.innerHTML = '<span class="spinner"></span> Ejecutando traceroute formal en Batfish…';
  $('btnSim').disabled = true;
  try {
    const r = await post(`/api/session/${S.id}/traceroute`, body);
    const dec = r.filtro_decisivo;
    box.className = `sim-result show ${r.permitido ? 'ok' : 'bad'}`;
    box.innerHTML = `<b>${r.permitido ? '✅ Tráfico PERMITIDO' : '⛔ Tráfico DENEGADO'}</b> · disposición <code>${esc(r.disposicion)}</code>
      ${dec ? `<br>Filtro decisivo: <code>${esc(dec.filtro)}</code> (${esc(dec.direccion)}) → <b>${esc(dec.accion)}</b>` : ''}
      ${r.regla ? `<br>Regla: <code>${esc(r.regla)}</code>` : ''}
      <div class="hops">${r.hops.map((h) => `▸ ${esc(h.nodo)}<br>` + h.pasos.map((p) => `&nbsp;&nbsp;${esc(p.accion)} · ${esc(p.detalle)}`).join('<br>')).join('<br>')}</div>`;
    const dstNode = (S.grafo.zonas.find((z) => inSubnet(body.dst_ip, z.subred)) || {}).nombre || (S.grafo.nodos.some((n) => n.id === 'Internet') ? 'Internet' : null);
    Topo.sendPacket(body.zona_origen, dstNode, r.permitido);
  } catch (e) {
    box.className = 'sim-result show bad'; box.textContent = '❌ ' + e.message;
  } finally { $('btnSim').disabled = false; }
}

/* ---------------------------------------------------------------- Grafo topológico con física elástica */
const Topo = {
  cv: null, cx: null, nodes: [], links: [], byId: {}, scale: 1, ox: 0, oy: 0, drag: null, pan: null,
  selected: null, hover: null, packets: [], ripples: [], hl: [], raf: null, w: 0, h: 0, dpr: 1,

  init() {
    this.cv = $('topoCanvas'); this.cx = this.cv.getContext('2d');
    const rs = () => this.resize(); window.addEventListener('resize', rs);
    this.cv.addEventListener('pointerdown', (e) => this.down(e));
    this.cv.addEventListener('pointermove', (e) => this.move(e));
    window.addEventListener('pointerup', () => this.up());
    this.cv.addEventListener('wheel', (e) => this.wheel(e), { passive: false });
  },
  resize() {
    this.dpr = window.devicePixelRatio || 1;
    this.w = this.cv.clientWidth; this.h = this.cv.clientHeight;
    this.cv.width = this.w * this.dpr; this.cv.height = this.h * this.dpr;
  },
  load(g) {
    this.resize();
    const cx = this.w / 2, cy = this.h / 2, n = g.nodos.length;
    this.nodes = g.nodos.map((nd, i) => {
      const a = (i / Math.max(n - 1, 1)) * Math.PI * 2;
      const fw = nd.tipo === 'firewall';
      return { ...nd, x: fw ? cx : cx + Math.cos(a) * 190, y: fw ? cy : cy + Math.sin(a) * 150, vx: 0, vy: 0, r: fw ? 32 : nd.tipo === 'internet' ? 27 : 25, fixed: false };
    });
    this.byId = Object.fromEntries(this.nodes.map((nd) => [nd.id, nd]));
    this.links = g.enlaces.filter((l) => this.byId[l.source] && this.byId[l.target]).map((l) => ({ ...l, a: this.byId[l.source], b: this.byId[l.target] }));
    this.scale = 1; this.ox = 0; this.oy = 0; this.selected = null; this.hl = []; this.packets = []; this.ripples = [];
    $('drawer').innerHTML = '<span class="empty">Selecciona un nodo o enlace para ver su ficha técnica.</span>';
    if (!this.raf) this.loop();
  },
  loop() { this.step(); this.draw(); this.raf = requestAnimationFrame(() => this.loop()); },

  step() {
    const N = this.nodes, cx = this.w / 2, cy = this.h / 2;
    for (let i = 0; i < N.length; i++) {
      for (let j = i + 1; j < N.length; j++) {
        let dx = N[j].x - N[i].x, dy = N[j].y - N[i].y; const d2 = Math.max(dx * dx + dy * dy, 100), d = Math.sqrt(d2);
        const f = 14000 / d2; dx /= d; dy /= d;
        N[i].vx -= dx * f; N[i].vy -= dy * f; N[j].vx += dx * f; N[j].vy += dy * f;
      }
    }
    this.links.forEach((l) => {
      const dx = l.b.x - l.a.x, dy = l.b.y - l.a.y, d = Math.max(Math.hypot(dx, dy), 1), rest = l.b.tipo === 'internet' || l.a.tipo === 'internet' ? 120 : 170;
      const f = (d - rest) * 0.012;
      l.a.vx += (dx / d) * f; l.a.vy += (dy / d) * f; l.b.vx -= (dx / d) * f; l.b.vy -= (dy / d) * f;
    });
    N.forEach((n) => {
      n.vx += (cx - n.x) * 0.0016; n.vy += (cy - n.y) * 0.0016;
      if (n.fixed) { n.vx = n.vy = 0; return; }
      n.vx *= 0.84; n.vy *= 0.84; n.x += n.vx; n.y += n.vy;
    });
  },

  toWorld(e) { const r = this.cv.getBoundingClientRect(); return { x: (e.clientX - r.left - this.ox) / this.scale, y: (e.clientY - r.top - this.oy) / this.scale }; },
  nodeAt(p) { return [...this.nodes].reverse().find((n) => Math.hypot(n.x - p.x, n.y - p.y) <= n.r + 4); },
  linkAt(p) {
    return this.links.find((l) => {
      const dx = l.b.x - l.a.x, dy = l.b.y - l.a.y, t = Math.max(0, Math.min(1, ((p.x - l.a.x) * dx + (p.y - l.a.y) * dy) / (dx * dx + dy * dy || 1)));
      return Math.hypot(l.a.x + t * dx - p.x, l.a.y + t * dy - p.y) < 8 / this.scale;
    });
  },
  down(e) {
    const p = this.toWorld(e), n = this.nodeAt(p);
    this.cv.setPointerCapture(e.pointerId); this.cv.classList.add('grabbing');
    this.moved = false;
    if (n) { this.drag = n; n.fixed = true; this.pickNode = n; }
    else { this.pan = { x: e.clientX - this.ox, y: e.clientY - this.oy }; this.pickNode = null; this.pickLink = this.linkAt(p); }
  },
  move(e) {
    if (this.drag) { const p = this.toWorld(e); this.drag.x = p.x; this.drag.y = p.y; this.moved = true; }
    else if (this.pan) { this.ox = e.clientX - this.pan.x; this.oy = e.clientY - this.pan.y; this.moved = true; }
  },
  up() {
    if (!this.drag && !this.pan) return;
    if (this.drag) this.drag.fixed = false;
    if (!this.moved) {
      if (this.pickNode) this.select(this.pickNode); else if (this.pickLink) this.selectLink(this.pickLink);
    }
    this.drag = null; this.pan = null; this.cv.classList.remove('grabbing');
  },
  wheel(e) {
    e.preventDefault();
    const r = this.cv.getBoundingClientRect(), mx = e.clientX - r.left, my = e.clientY - r.top;
    const k = e.deltaY < 0 ? 1.1 : 0.9, ns = Math.min(2.5, Math.max(0.4, this.scale * k));
    this.ox = mx - ((mx - this.ox) / this.scale) * ns; this.oy = my - ((my - this.oy) / this.scale) * ns; this.scale = ns;
  },
  select(n) {
    this.selected = n; const links = this.links.filter((l) => l.a === n || l.b === n);
    const kv = Object.entries(n.detalle || {}).map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(v)}</dd>`).join('');
    $('drawer').innerHTML = `<h3>${ZONE_ICON[n.tipo] || '•'} ${esc(n.label)}</h3><dl class="kv">${kv}</dl>
      <p class="block-label">Enlaces</p>${links.map((l) => `<div style="font-family:var(--mono);font-size:.78rem">${esc(l.a.label)} ⇄ ${esc(l.b.label)} ${l.subred ? '· ' + esc(l.subred) : ''}</div>`).join('') || '—'}`;
  },
  selectLink(l) {
    this.selected = null;
    $('drawer').innerHTML = `<h3>🔗 ${esc(l.a.label)} ⇄ ${esc(l.b.label)}</h3><dl class="kv">
      <dt>Subred</dt><dd>${esc(l.subred || '—')}</dd><dt>Interfaz</dt><dd>${esc(l.interfaz || '—')}</dd>
      <dt>ACL de entrada</dt><dd>${esc(l.acl_in || '—')}</dd><dt>ACL de salida</dt><dd>${esc(l.acl_out || '—')}</dd></dl>`;
  },

  path(from, to) {
    if (!this.byId[from] || !this.byId[to]) return [];
    const start = from === to ? [from] : [from]; const prev = { [from]: null }; const q = [from];
    while (q.length) {
      const c = q.shift(); if (c === to) break;
      this.links.forEach((l) => { const o = l.a.id === c ? l.b.id : l.b.id === c ? l.a.id : null; if (o && !(o in prev)) { prev[o] = c; q.push(o); } });
    }
    if (!(to in prev)) return start;
    const out = []; for (let c = to; c; c = prev[c]) out.unshift(c); return out;
  },
  highlight(from, to) {
    const src = zoneByName(from) && zoneByName(from).zona === 'WAN' && this.byId.Internet ? 'Internet' : from;
    this.hl = this.path(src, to); setTimeout(() => (this.hl = []), 4500);
  },
  sendPacket(srcZone, dstNode, allowed) {
    const src = zoneByName(srcZone) && zoneByName(srcZone).zona === 'WAN' && this.byId.Internet ? 'Internet' : srcZone;
    const ids = dstNode ? this.path(src, dstNode) : [src];
    if (ids.length < 2) return;
    const fwIdx = ids.findIndex((id) => this.byId[id].tipo === 'firewall');
    this.packets.push({ ids, seg: 0, t: 0, allowed, stop: allowed ? ids.length - 1 : (fwIdx > 0 ? fwIdx : ids.length - 1) });
  },

  draw() {
    const c = this.cx; c.setTransform(this.dpr, 0, 0, this.dpr, 0, 0); c.clearRect(0, 0, this.w, this.h);
    c.save(); c.translate(this.ox, this.oy); c.scale(this.scale, this.scale);
    const hlSet = new Set(); for (let i = 0; i < this.hl.length - 1; i++) hlSet.add(this.hl[i] + '|' + this.hl[i + 1]), hlSet.add(this.hl[i + 1] + '|' + this.hl[i]);
    this.links.forEach((l) => {
      const hi = hlSet.has(l.a.id + '|' + l.b.id);
      c.strokeStyle = hi ? '#38bdf8' : 'rgba(148,163,184,.35)'; c.lineWidth = hi ? 3.5 : 1.8; c.setLineDash(l.b.tipo === 'internet' || l.a.tipo === 'internet' ? [6, 5] : []);
      if (hi) { c.shadowColor = '#38bdf8'; c.shadowBlur = 14; }
      c.beginPath(); c.moveTo(l.a.x, l.a.y); c.lineTo(l.b.x, l.b.y); c.stroke(); c.shadowBlur = 0; c.setLineDash([]);
      if (l.subred && l.subred !== '0.0.0.0/0') { c.fillStyle = '#94a3b8'; c.font = '10px JetBrains Mono, monospace'; c.textAlign = 'center'; c.fillText(l.subred, (l.a.x + l.b.x) / 2, (l.a.y + l.b.y) / 2 - 6); }
    });
    this.nodes.forEach((n) => {
      const col = ZONE_COLOR[n.tipo] || '#94a3b8', sel = this.selected === n;
      const pulse = n.tipo === 'firewall' ? 3 * Math.sin(Date.now() / 450) : 0;
      const g = c.createRadialGradient(n.x, n.y, 2, n.x, n.y, n.r + 16 + pulse);
      g.addColorStop(0, col + 'cc'); g.addColorStop(1, col + '00');
      c.fillStyle = g; c.beginPath(); c.arc(n.x, n.y, n.r + 16 + pulse, 0, 7); c.fill();
      c.fillStyle = '#0b1220'; c.strokeStyle = col; c.lineWidth = sel ? 4 : 2.4;
      c.beginPath(); c.arc(n.x, n.y, n.r, 0, 7); c.fill(); c.stroke();
      c.font = `${n.r * 0.85}px sans-serif`; c.textAlign = 'center'; c.textBaseline = 'middle'; c.fillStyle = '#fff'; c.fillText(ZONE_ICON[n.tipo] || '•', n.x, n.y + 1);
      c.textBaseline = 'alphabetic'; c.font = '600 12px Outfit, sans-serif'; c.fillStyle = '#e2e8f0'; c.fillText(n.label, n.x, n.y + n.r + 17);
      if (n.hallazgos) { c.fillStyle = '#e5384f'; c.beginPath(); c.arc(n.x + n.r * 0.8, n.y - n.r * 0.8, 9, 0, 7); c.fill(); c.fillStyle = '#fff'; c.font = '700 10px Outfit'; c.fillText(n.hallazgos, n.x + n.r * 0.8, n.y - n.r * 0.8 + 3.5); }
    });
    this.ripples = this.ripples.filter((r) => r.a > 0.02);
    this.ripples.forEach((r) => { c.strokeStyle = `rgba(229,56,79,${r.a})`; c.lineWidth = 3; c.beginPath(); c.arc(r.x, r.y, r.r, 0, 7); c.stroke(); r.r += 2.2; r.a *= 0.94; });
    this.packets = this.packets.filter((p) => this.advance(p, c));
    c.restore();
  },
  advance(p, c) {
    const a = this.byId[p.ids[p.seg]], b = this.byId[p.ids[p.seg + 1]];
    p.t += 0.022;
    const x = a.x + (b.x - a.x) * Math.min(p.t, 1), y = a.y + (b.y - a.y) * Math.min(p.t, 1);
    const passedFw = this.byId[p.ids[p.seg]].tipo === 'firewall' || p.seg > p.ids.findIndex((id) => this.byId[id].tipo === 'firewall');
    const col = !passedFw || !p.allowed ? '#38bdf8' : '#34d399';
    c.shadowColor = col; c.shadowBlur = 20; c.fillStyle = col; c.beginPath(); c.arc(x, y, 6, 0, 7); c.fill(); c.shadowBlur = 0;
    if (p.t >= 1) {
      p.seg++; p.t = 0;
      if (p.seg >= p.stop) {
        const endNode = this.byId[p.ids[p.stop]];
        if (!p.allowed) { this.ripples.push({ x: endNode.x, y: endNode.y, r: endNode.r, a: 0.9 }, { x: endNode.x, y: endNode.y, r: endNode.r - 8, a: 0.7 }); }
        else this.ripples.push({ x: endNode.x, y: endNode.y, r: endNode.r, a: 0 });
        return false;
      }
    }
    return true;
  },
};

/* ---------------------------------------------------------------- Init */
document.addEventListener('DOMContentLoaded', () => {
  Topo.init();
  setupUpload();
  refreshStatus(); setInterval(refreshStatus, 30000);
  $('modalClose').addEventListener('click', closeModal);
  $('modalBg').addEventListener('click', (e) => { if (e.target === $('modalBg')) closeModal(); });
  document.addEventListener('keydown', (e) => { if (e.key === 'Escape') closeModal(); });
  $('btnSanView').addEventListener('click', showSanitization);
  $('btnShadow').addEventListener('click', showShadowing);
  $('btnExposure').addEventListener('click', showExposure);
  $('btnDiffA').addEventListener('click', () => showDiff('A'));
  $('btnDiffB').addEventListener('click', () => showDiff('B'));
  $('btnMatrix').addEventListener('click', loadMatrix);
  $('btnSim').addEventListener('click', runSim);
  $('simSrcZone').addEventListener('change', fillIps);
  $('simDstZone').addEventListener('change', fillIps);
  $('btnPdf').addEventListener('click', () => download(`/api/session/${S.id}/pdf`, 'auditoria.pdf'));
  $('btnMd').addEventListener('click', () => download(`/api/session/${S.id}/markdown`, 'auditoria.md'));
  $('btnRem').addEventListener('click', () => download(`/api/session/${S.id}/cli/remediacion`, 'remediacion.cli'));
  $('btnRoll').addEventListener('click', () => download(`/api/session/${S.id}/cli/rollback`, 'rollback.cli'));
});
