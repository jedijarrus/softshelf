"""
Software Center - pywebview HTML/CSS/JS implementation.

Design: Hybrid List + Tabs (Option C from brainstorm).
All HTML/CSS/JS embedded as Python string. No external files.
"""
import json
import threading
from html import escape as _h

import webview

from api_client import KioskApiClient, Package
from _version import __version__


# ──────────────────────────────────────────────────────────── HTML Template ────

_HTML = """<!DOCTYPE html>
<html lang="de">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{app_name}</title>
<style>
*, *::before, *::after {{
  box-sizing: border-box;
  margin: 0;
  padding: 0;
}}

:root {{
  --bg: #ffffff;
  --bg-soft: #fafafa;
  --bg-hover: #f4f4f5;
  --border: #e4e4e7;
  --border-s: #d4d4d8;
  --fg: #18181b;
  --fg-2: #27272a;
  --fg-3: #52525b;
  --fg-4: #71717a;
  --fg-5: #a1a1aa;
  --green: #16a34a;
  --green-bg: #f0fdf4;
  --green-border: #bbf7d0;
  --red: #dc2626;
  --red-bg: #fef2f2;
  --red-border: #fecaca;
  --amber: #ca8a04;
  --amber-bg: #fefce8;
  --amber-border: #fde68a;
  --radius: 8px;
  --radius-sm: 6px;
  --transition: 150ms cubic-bezier(0.4, 0, 0.2, 1);
}}

html, body {{
  height: 100%;
  font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
  font-size: 13px;
  color: var(--fg);
  background: var(--bg);
  -webkit-font-smoothing: antialiased;
  overflow: hidden;
  user-select: none;
}}

/* ─── Layout ─── */
.app {{
  display: flex;
  flex-direction: column;
  height: 100vh;
}}

/* ─── Offline Banner ─── */
.offline-banner {{
  background: var(--red);
  color: white;
  text-align: center;
  padding: 6px 16px;
  font-size: 12px;
  font-weight: 500;
  letter-spacing: 0.01em;
  display: none;
  animation: slideDown 200ms ease-out;
}}
.offline-banner.visible {{
  display: block;
}}
@keyframes slideDown {{
  from {{ transform: translateY(-100%); opacity: 0; }}
  to {{ transform: translateY(0); opacity: 1; }}
}}

/* ─── Header ─── */
.header {{
  padding: 14px 20px 0;
  border-bottom: 1px solid var(--border);
  flex-shrink: 0;
}}
.header-top {{
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 12px;
}}
.header-status {{
  display: flex;
  align-items: center;
  gap: 8px;
}}
.status-dot {{
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background: var(--green);
  animation: pulse 2s infinite;
}}
.status-dot.offline {{
  background: var(--red);
  animation: none;
}}
@keyframes pulse {{
  0%, 100% {{ opacity: 1; }}
  50% {{ opacity: 0.5; }}
}}
.status-text {{
  font-size: 11px;
  color: var(--fg-5);
}}

/* ─── Tabs ─── */
.tabs {{
  display: flex;
  gap: 0;
}}
.tab {{
  padding: 8px 14px;
  font-size: 12px;
  color: var(--fg-4);
  cursor: pointer;
  border-bottom: 2px solid transparent;
  transition: color var(--transition), border-color var(--transition);
  font-weight: 500;
  white-space: nowrap;
}}
.tab:hover {{
  color: var(--fg-3);
}}
.tab.active {{
  color: var(--fg);
  font-weight: 600;
  border-bottom-color: var(--fg);
}}
.tab-badge {{
  display: inline-block;
  background: var(--amber-bg);
  color: var(--amber);
  padding: 1px 6px;
  border-radius: 3px;
  font-size: 10px;
  font-weight: 600;
  margin-left: 4px;
  border: 1px solid var(--amber-border);
}}

/* ─── Search ─── */
.search-bar {{
  padding: 12px 20px;
  border-bottom: 1px solid var(--border);
  flex-shrink: 0;
}}
.search-input {{
  width: 100%;
  padding: 8px 12px;
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  font-size: 12px;
  color: var(--fg);
  background: var(--bg-soft);
  outline: none;
  transition: border-color var(--transition), box-shadow var(--transition);
}}
.search-input:focus {{
  border-color: var(--fg-5);
  box-shadow: 0 0 0 3px rgba(161, 161, 170, 0.1);
}}
.search-input::placeholder {{
  color: var(--fg-5);
}}

/* ─── Content ─── */
.content {{
  flex: 1;
  overflow-y: auto;
  overflow-x: hidden;
  padding: 8px 20px 20px;
}}
.content::-webkit-scrollbar {{
  width: 8px;
}}
.content::-webkit-scrollbar-track {{
  background: transparent;
}}
.content::-webkit-scrollbar-thumb {{
  background: var(--border);
  border-radius: 4px;
}}
.content::-webkit-scrollbar-thumb:hover {{
  background: var(--border-s);
}}

/* ─── Category Header ─── */
.cat-header {{
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 16px 0 8px;
}}
.cat-header:first-child {{
  padding-top: 8px;
}}
.cat-name {{
  font-size: 11px;
  font-weight: 600;
  color: var(--fg-5);
  text-transform: uppercase;
  letter-spacing: 0.04em;
}}
.cat-count {{
  font-size: 10px;
  color: var(--fg-5);
  background: var(--bg-hover);
  padding: 1px 6px;
  border-radius: 3px;
}}

/* ─── Package Row ─── */
.pkg-row {{
  display: flex;
  align-items: center;
  padding: 10px 12px;
  border-radius: var(--radius);
  gap: 12px;
  cursor: default;
  transition: background var(--transition);
}}
.pkg-row:hover {{
  background: var(--bg-hover);
}}
.pkg-row.update-row {{
  background: var(--amber-bg);
  border: 1px solid var(--amber-border);
  margin: 2px 0;
}}
.pkg-row.update-row:hover {{
  background: #fef9c3;
}}

/* ─── Avatar ─── */
.pkg-avatar {{
  width: 32px;
  height: 32px;
  border-radius: 7px;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 12px;
  font-weight: 700;
  flex-shrink: 0;
  background: var(--bg-hover);
  border: 1px solid var(--border);
  color: var(--fg-3);
  transition: transform var(--transition);
}}
.pkg-row:hover .pkg-avatar {{
  transform: scale(1.05);
}}
.pkg-row.update-row .pkg-avatar {{
  background: #fef9c3;
  border-color: var(--amber-border);
  color: #854d0e;
}}
.pkg-row.installed .pkg-avatar {{
  background: var(--green-bg);
  border-color: var(--green-border);
  color: var(--green);
}}

/* ─── Package Info ─── */
.pkg-info {{
  flex: 1;
  min-width: 0;
}}
.pkg-name {{
  font-size: 13px;
  font-weight: 500;
  color: var(--fg);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}}
.pkg-meta {{
  font-size: 11px;
  color: var(--fg-5);
  margin-top: 1px;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}}
.pkg-meta .update-label {{
  color: var(--amber);
  font-weight: 600;
}}

/* ─── Action Button ─── */
.pkg-action {{
  flex-shrink: 0;
}}
.btn {{
  padding: 5px 14px;
  font-size: 11px;
  font-weight: 500;
  border: none;
  border-radius: var(--radius-sm);
  cursor: pointer;
  transition: all var(--transition);
  white-space: nowrap;
  outline: none;
}}
.btn-install {{
  background: var(--fg);
  color: white;
  font-weight: 600;
}}
.btn-install:hover {{
  background: var(--fg-2);
  transform: translateY(-1px);
  box-shadow: 0 2px 8px rgba(24, 24, 27, 0.15);
}}
.btn-install:active {{
  transform: translateY(0);
  box-shadow: none;
}}
.btn-update {{
  background: var(--fg);
  color: white;
  font-weight: 600;
}}
.btn-update:hover {{
  background: var(--fg-2);
  transform: translateY(-1px);
  box-shadow: 0 2px 8px rgba(24, 24, 27, 0.15);
}}
.btn-installed {{
  background: transparent;
  color: var(--green);
  font-size: 11px;
  font-weight: 500;
  cursor: default;
  padding: 5px 10px;
}}
.btn-uninstall {{
  background: var(--red-bg);
  color: var(--red);
  border: 1px solid var(--red-border);
  font-weight: 600;
}}
.btn-uninstall:hover {{
  background: var(--red);
  color: white;
  border-color: var(--red);
}}
.btn-busy {{
  background: var(--bg-hover);
  color: var(--fg-5);
  cursor: wait;
  pointer-events: none;
}}

/* ─── Loading ─── */
.loading {{
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: 80px 20px;
  gap: 16px;
}}
.spinner {{
  width: 28px;
  height: 28px;
  border: 2.5px solid var(--border);
  border-top-color: var(--fg);
  border-radius: 50%;
  animation: spin 0.7s linear infinite;
}}
@keyframes spin {{
  to {{ transform: rotate(360deg); }}
}}
.loading-text {{
  font-size: 12px;
  color: var(--fg-5);
}}

/* ─── Empty State ─── */
.empty-state {{
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: 60px 20px;
  gap: 12px;
}}
.empty-icon {{
  width: 44px;
  height: 44px;
  background: var(--bg-soft);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 18px;
  font-weight: 600;
  color: var(--fg-4);
}}
.empty-title {{
  font-size: 13px;
  font-weight: 600;
  color: var(--fg);
}}
.empty-detail {{
  font-size: 12px;
  color: var(--fg-4);
  text-align: center;
  max-width: 300px;
  line-height: 1.5;
}}

/* ─── Error State ─── */
.error-state {{
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: 60px 20px;
  gap: 12px;
}}
.error-icon {{
  width: 44px;
  height: 44px;
  background: var(--red-bg);
  border: 1px solid var(--red-border);
  border-radius: var(--radius);
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 18px;
  font-weight: 700;
  color: var(--red);
}}
.error-title {{
  font-size: 13px;
  font-weight: 600;
  color: var(--fg);
}}
.error-detail {{
  font-size: 12px;
  color: var(--fg-4);
  text-align: center;
  max-width: 300px;
  line-height: 1.5;
}}
.btn-retry {{
  margin-top: 8px;
  padding: 7px 16px;
  font-size: 12px;
  font-weight: 500;
  background: var(--bg);
  color: var(--fg-2);
  border: 1px solid var(--border-s);
  border-radius: var(--radius-sm);
  cursor: pointer;
  transition: all var(--transition);
}}
.btn-retry:hover {{
  background: var(--bg-soft);
  border-color: var(--fg-5);
}}

/* ─── Toast ─── */
.toast {{
  position: fixed;
  bottom: 60px;
  left: 50%;
  transform: translateX(-50%) translateY(20px);
  padding: 10px 18px;
  border-radius: 8px;
  font-size: 12px;
  font-weight: 500;
  color: white;
  z-index: 1000;
  opacity: 0;
  transition: opacity 200ms ease, transform 200ms ease;
  pointer-events: none;
  max-width: 340px;
  text-align: center;
}}
.toast.visible {{
  opacity: 1;
  transform: translateX(-50%) translateY(0);
}}
.toast.success {{
  background: var(--fg);
}}
.toast.error {{
  background: var(--red);
}}

/* ─── Footer ─── */
.footer {{
  padding: 10px 20px;
  border-top: 1px solid var(--border);
  display: flex;
  align-items: center;
  justify-content: space-between;
  flex-shrink: 0;
}}
.footer-left {{
  display: flex;
  align-items: center;
  gap: 12px;
}}
.footer-count {{
  font-size: 11px;
  color: var(--fg-4);
}}
.btn-refresh {{
  padding: 5px 12px;
  font-size: 11px;
  font-weight: 500;
  background: var(--bg);
  color: var(--fg-3);
  border: 1px solid var(--border-s);
  border-radius: var(--radius-sm);
  cursor: pointer;
  transition: all var(--transition);
}}
.btn-refresh:hover {{
  background: var(--bg-soft);
  border-color: var(--fg-5);
}}
.btn-refresh:active {{
  background: var(--bg-hover);
}}
.footer-version {{
  font-size: 10px;
  color: var(--fg-5);
}}

/* ─── Token-Revoked Full-Screen Overlay (401-Handler) ─── */
.revoked-overlay {{
  position: fixed;
  inset: 0;
  background: var(--bg);
  display: none;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  text-align: center;
  padding: 32px;
  z-index: 9999;
}}
.revoked-overlay.visible {{ display: flex; }}
.revoked-icon {{
  width: 56px;
  height: 56px;
  border-radius: 14px;
  background: var(--red-bg);
  border: 1px solid var(--red-border);
  display: flex;
  align-items: center;
  justify-content: center;
  margin-bottom: 18px;
  color: var(--red);
  font-size: 26px;
  font-weight: 600;
}}
.revoked-title {{
  font-size: 18px;
  font-weight: 600;
  color: var(--fg);
  margin-bottom: 8px;
}}
.revoked-msg {{
  font-size: 13px;
  color: var(--fg-3);
  max-width: 460px;
  line-height: 1.5;
  margin-bottom: 22px;
}}
.revoked-btn {{
  background: var(--fg);
  color: white;
  border: none;
  padding: 10px 22px;
  border-radius: var(--radius-sm);
  font-size: 13px;
  font-weight: 500;
  cursor: pointer;
}}
.revoked-btn:hover {{ background: var(--fg-2); }}
.revoked-hint {{
  margin-top: 16px;
  font-size: 11px;
  color: var(--fg-5);
}}
.proc-modal-overlay {{
  position: fixed; inset: 0;
  background: rgba(9,9,11,.5);
  display: flex; align-items: center; justify-content: center;
  z-index: 9999;
  animation: proc-fade .15s ease-out;
}}
@keyframes proc-fade {{ from {{ opacity: 0; }} to {{ opacity: 1; }} }}
.proc-modal {{
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: 12px;
  padding: 28px 32px 24px;
  width: 90%;
  max-width: 420px;
  box-shadow: 0 20px 60px rgba(0,0,0,.25);
}}
.proc-modal-icon {{
  width: 48px; height: 48px;
  border-radius: 50%;
  background: var(--amber-bg);
  color: var(--amber);
  display: flex; align-items: center; justify-content: center;
  font-size: 24px; font-weight: 700;
  margin-bottom: 16px;
}}
.proc-modal-title {{
  font-size: 18px; font-weight: 600;
  color: var(--fg);
  margin-bottom: 12px;
}}
.proc-modal-body {{
  font-size: 14px;
  color: var(--fg-3);
  line-height: 1.5;
}}
.proc-modal-body ul {{
  margin: 10px 0 0 0;
  padding: 0;
  list-style: none;
}}
.proc-modal-body li {{
  padding: 4px 0;
  font-size: 13px;
}}
.proc-modal-body code {{
  background: var(--bg-soft);
  padding: 2px 6px;
  border-radius: 4px;
  font-family: ui-monospace, monospace;
  font-size: 12px;
  color: var(--fg-2);
}}
.proc-modal-actions {{
  display: flex; gap: 10px;
  justify-content: flex-end;
  margin-top: 22px;
}}
.proc-btn {{
  padding: 9px 18px;
  border-radius: 6px;
  border: 1px solid var(--border);
  background: var(--bg-card);
  color: var(--fg-2);
  font-size: 13px;
  font-weight: 500;
  cursor: pointer;
  font-family: inherit;
}}
.proc-btn:hover {{ background: var(--bg-hover); }}
.proc-btn-retry {{
  background: var(--fg);
  color: white;
  border-color: var(--fg);
}}
.proc-btn-retry:hover {{ background: var(--fg-2); }}
</style>
</head>
<body>
<div class="app">
  <div class="offline-banner" id="offlineBanner">
    Server nicht erreichbar &mdash; Installation nicht m&ouml;glich
  </div>

  <div class="revoked-overlay" id="revokedOverlay">
    <div class="revoked-icon">!</div>
    <div class="revoked-title">Token wurde widerrufen</div>
    <div class="revoked-msg">
      Dieses Ger&auml;t ist bei Softshelf nicht mehr autorisiert.
      Bitte installieren Sie das Software Center neu, um sich erneut zu registrieren.
    </div>
    <button class="revoked-btn" id="revokedBtn" onclick="openReinstall()">Neu installieren</button>
    <div class="revoked-hint" id="revokedHint">Bei Fragen: IT kontaktieren.</div>
  </div>

  <div class="header">
    <div class="header-top">
      <div class="tabs" id="tabs">
        <div class="tab active" data-tab="all">Alle</div>
        <div class="tab" data-tab="updates">Updates <span class="tab-badge" id="updateBadge" style="display:none">0</span></div>
        <div class="tab" data-tab="installed">Installiert</div>
      </div>
      <div class="header-status">
        <div class="status-dot" id="statusDot"></div>
        <span class="status-text" id="statusText">Verbinde...</span>
      </div>
    </div>
  </div>

  <div class="search-bar">
    <input type="text" class="search-input" id="searchInput" placeholder="Suchen..." autocomplete="off" spellcheck="false">
  </div>

  <div class="content" id="content">
    <div class="loading">
      <div class="spinner"></div>
      <div class="loading-text">Pakete werden geladen...</div>
    </div>
  </div>

  <div class="footer">
    <div class="footer-left">
      <button class="btn-refresh" id="btnRefresh" onclick="loadPackages()">Aktualisieren</button>
      <span class="footer-count" id="footerCount"></span>
    </div>
    <span class="footer-version">v{version}</span>
  </div>
</div>

<div class="toast" id="toast"></div>

<script>
'use strict';

let packages = [];
let activeTab = 'all';
let searchQuery = '';
let busyPkg = null;

// ─── Init ───
function _initApp() {{
  document.querySelectorAll('.tab').forEach(tab => {{
    tab.addEventListener('click', () => {{
      activeTab = tab.dataset.tab;
      document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
      tab.classList.add('active');
      renderPackages();
    }});
  }});
  const searchInput = document.getElementById('searchInput');
  searchInput.addEventListener('input', (e) => {{
    searchQuery = e.target.value.toLowerCase();
    renderPackages();
  }});
  loadPackages();
}}
// pywebview Bridge ist erst nach 'pywebviewready' verfuegbar
if (window.pywebview) {{ _initApp(); }}
else {{ window.addEventListener('pywebviewready', _initApp); }}

async function loadPackages() {{
  showLoading();
  try {{
    const result = await pywebview.api.get_packages();
    packages = result;
    updateCounts();
    renderPackages();
    setOnlineState(true);
  }} catch (e) {{
    const msg = e.message || 'Verbindungsfehler';
    if (msg.indexOf('__TOKEN_REVOKED__') !== -1) {{
      showRevokedOverlay();
      return;
    }}
    showError(msg);
    setOnlineState(false);
  }}
}}

let _revokedShown = false;
function showRevokedOverlay() {{
  if (_revokedShown) return;
  _revokedShown = true;
  const ov = document.getElementById('revokedOverlay');
  if (ov) ov.classList.add('visible');
  // Reinstall-URL asynchron nachladen damit der Button sinnvoll funktioniert
  (async () => {{
    try {{
      const url = await pywebview.api.get_reinstall_url();
      const btn = document.getElementById('revokedBtn');
      if (btn) btn.dataset.url = url || '';
    }} catch (e) {{}}
  }})();
}}

async function openReinstall() {{
  const btn = document.getElementById('revokedBtn');
  let url = (btn && btn.dataset.url) || '';
  if (!url) {{
    try {{ url = await pywebview.api.get_reinstall_url(); }} catch (e) {{}}
  }}
  if (!url) {{
    const hint = document.getElementById('revokedHint');
    if (hint) hint.textContent = 'Bitte IT-Support kontaktieren — keine Reinstall-URL konfiguriert.';
    return;
  }}
  try {{
    if (window.pywebview && pywebview.api && pywebview.api.open_external) {{
      await pywebview.api.open_external(url);
      return;
    }}
  }} catch (e) {{}}
  // Fallback: browser-internal navigation
  window.open(url, '_blank');
}}

function updateCounts() {{
  const installed = packages.filter(p => p.installed).length;
  const updates = packages.filter(p => p.update_available).length;
  const total = packages.length;

  document.getElementById('footerCount').textContent =
    total + ' ' + (total === 1 ? 'Paket' : 'Pakete') + ' \\u00B7 ' + installed + ' installiert';

  const badge = document.getElementById('updateBadge');
  if (updates > 0) {{
    badge.textContent = updates;
    badge.style.display = 'inline-block';
  }} else {{
    badge.style.display = 'none';
  }}
}}

function getFilteredPackages() {{
  let filtered = [...packages];

  // Tab filter
  if (activeTab === 'updates') {{
    filtered = filtered.filter(p => p.update_available);
  }} else if (activeTab === 'installed') {{
    filtered = filtered.filter(p => p.installed);
  }}

  // Search filter
  if (searchQuery) {{
    filtered = filtered.filter(p =>
      p.display_name.toLowerCase().includes(searchQuery) ||
      p.name.toLowerCase().includes(searchQuery)
    );
  }}

  // Sort: updates first, then alphabetical
  filtered.sort((a, b) => {{
    if (a.update_available && !b.update_available) return -1;
    if (!a.update_available && b.update_available) return 1;
    return a.display_name.localeCompare(b.display_name);
  }});

  return filtered;
}}

function renderPackages() {{
  const content = document.getElementById('content');
  const filtered = getFilteredPackages();

  if (filtered.length === 0) {{
    if (searchQuery) {{
      content.innerHTML = `
        <div class="empty-state">
          <div class="empty-icon">?</div>
          <div class="empty-title">Keine Treffer</div>
          <div class="empty-detail">Kein Paket passt zur Suche &bdquo;${{escHtml(searchQuery)}}&ldquo;</div>
        </div>`;
    }} else if (activeTab === 'updates') {{
      content.innerHTML = `
        <div class="empty-state">
          <div class="empty-icon" style="background:var(--green-bg);border-color:var(--green-border);color:var(--green)">\\u2713</div>
          <div class="empty-title">Alles aktuell</div>
          <div class="empty-detail">Keine Updates verf\\u00FCgbar</div>
        </div>`;
    }} else if (activeTab === 'installed') {{
      content.innerHTML = `
        <div class="empty-state">
          <div class="empty-icon">0</div>
          <div class="empty-title">Nichts installiert</div>
          <div class="empty-detail">Installiere Software aus dem Tab &bdquo;Alle&ldquo;</div>
        </div>`;
    }} else {{
      content.innerHTML = `
        <div class="empty-state">
          <div class="empty-icon">!</div>
          <div class="empty-title">Keine Pakete verf\\u00FCgbar</div>
          <div class="empty-detail">Der Administrator hat noch keine Software freigegeben.</div>
        </div>`;
    }}
    return;
  }}

  // Group by category in "all" tab
  let html = '';
  if (activeTab === 'all' && !searchQuery) {{
    const groups = {{}};
    filtered.forEach(p => {{
      const cat = p.category || 'Allgemein';
      if (!groups[cat]) groups[cat] = [];
      groups[cat].push(p);
    }});
    const sortedCats = Object.keys(groups).sort();
    sortedCats.forEach(cat => {{
      html += `<div class="cat-header"><span class="cat-name">${{escHtml(cat)}}</span><span class="cat-count">${{groups[cat].length}}</span></div>`;
      groups[cat].forEach(p => {{ html += renderRow(p); }});
    }});
  }} else {{
    filtered.forEach(p => {{ html += renderRow(p); }});
  }}

  content.innerHTML = html;
}}

function renderRow(pkg) {{
  const initial = (pkg.display_name || '?')[0].toUpperCase();
  const isBusy = busyPkg === pkg.name;
  const isUpdate = pkg.update_available;
  const isInstalled = pkg.installed && !isUpdate;

  let rowClass = 'pkg-row';
  if (isUpdate) rowClass += ' update-row';
  else if (isInstalled) rowClass += ' installed';

  // Meta line
  let meta = '';
  const source = pkg.type === 'custom' ? 'Eigenes Paket' : pkg.type;
  if (isUpdate && pkg.installed_version_label && pkg.current_version_label) {{
    meta = `<span class="update-label">Update: ${{escHtml(pkg.installed_version_label)}} \\u2192 ${{escHtml(pkg.current_version_label)}}</span>`;
  }} else if (isUpdate) {{
    meta = `<span class="update-label">Update verf\\u00FCgbar</span>`;
  }} else if (pkg.installed && pkg.version) {{
    meta = `${{escHtml(source)}} \\u00B7 ${{escHtml(pkg.version)}}`;
  }} else if (pkg.installed) {{
    meta = `${{escHtml(source)}} \\u00B7 Installiert`;
  }} else {{
    meta = escHtml(source);
    if (pkg.current_version_label) meta += ' \\u00B7 ' + escHtml(pkg.current_version_label);
  }}

  // Button
  let btn = '';
  if (isBusy) {{
    btn = `<button class="btn btn-busy">...</button>`;
  }} else if (isUpdate) {{
    btn = `<button class="btn btn-update" onclick="doInstall('${{escAttr(pkg.name)}}')">Updaten</button>`;
  }} else if (isInstalled) {{
    if (pkg.hide_uninstall) {{
      btn = `<span class="btn btn-installed">Installiert</span>`;
    }} else {{
      btn = `<span class="btn btn-installed" onmouseenter="this.innerHTML='Deinstallieren';this.className='btn btn-uninstall'" onmouseleave="this.innerHTML='Installiert';this.className='btn btn-installed'" onclick="doUninstall('${{escAttr(pkg.name)}}')">Installiert</span>`;
    }}
  }} else {{
    btn = `<button class="btn btn-install" onclick="doInstall('${{escAttr(pkg.name)}}')">Installieren</button>`;
  }}

  return `
    <div class="${{rowClass}}" data-name="${{escAttr(pkg.name)}}">
      <div class="pkg-avatar">${{escHtml(initial)}}</div>
      <div class="pkg-info">
        <div class="pkg-name">${{escHtml(pkg.display_name)}}</div>
        <div class="pkg-meta">${{meta}}</div>
      </div>
      <div class="pkg-action">${{btn}}</div>
    </div>`;
}}

async function doInstall(name) {{
  if (busyPkg) {{
    showToast('Bitte warten \\u2014 andere Aktion l\\u00E4uft noch.', false);
    return;
  }}
  // Pre-Install Process-Check: schauen ob blockierende Anwendung lokal laeuft
  const pkg = (packages || []).find(p => p.name === name);
  if (pkg && pkg.process_check) {{
    try {{
      const running = await pywebview.api.check_running_processes(pkg.process_check);
      if (running && running.length > 0) {{
        const proceed = await showProcessRunningDialog(pkg.display_name || name, running);
        if (!proceed) return;
      }}
    }} catch (e) {{
      // Check fail → einfach weitermachen, Server-side check fangt es notfalls
    }}
  }}
  busyPkg = name;
  renderPackages();
  try {{
    const msg = await pywebview.api.install_package(name);
    showToast(msg, true);
    setTimeout(loadPackages, 800);
  }} catch (e) {{
    const m = e.message || 'Fehler bei Installation';
    if (m.indexOf('__TOKEN_REVOKED__') !== -1) {{ showRevokedOverlay(); return; }}
    showToast(m, false);
  }} finally {{
    busyPkg = null;
    renderPackages();
  }}
}}

function showProcessRunningDialog(displayName, runningNames) {{
  return new Promise(resolve => {{
    const ov = document.createElement('div');
    ov.className = 'proc-modal-overlay';
    const list = runningNames.map(n => '<li><code>' + n + '.exe</code></li>').join('');
    ov.innerHTML = `
      <div class="proc-modal">
        <div class="proc-modal-icon">!</div>
        <div class="proc-modal-title">${{displayName}} ist ge\\u00f6ffnet</div>
        <div class="proc-modal-body">
          Bitte <strong>${{displayName}}</strong> erst schlie\\u00dfen, sonst kann
          die Installation/das Update nicht abgeschlossen werden.
          <ul>${{list}}</ul>
        </div>
        <div class="proc-modal-actions">
          <button class="proc-btn proc-btn-cancel">Abbrechen</button>
          <button class="proc-btn proc-btn-retry">Ich habe geschlossen</button>
        </div>
      </div>`;
    document.body.appendChild(ov);
    const cleanup = (val) => {{ ov.remove(); resolve(val); }};
    ov.querySelector('.proc-btn-cancel').onclick = () => cleanup(false);
    ov.querySelector('.proc-btn-retry').onclick = async () => {{
      // Recheck — wenn noch offen, Modal aktualisieren
      try {{
        const still = await pywebview.api.check_running_processes(runningNames.join(','));
        if (still && still.length > 0) {{
          ov.querySelector('.proc-modal-title').textContent = displayName + ' ist immer noch ge\\u00f6ffnet';
          ov.querySelector('.proc-modal-body ul').innerHTML = still.map(n => '<li><code>' + n + '.exe</code></li>').join('');
          return;
        }}
      }} catch(e) {{}}
      cleanup(true);
    }};
  }});
}}

async function doUninstall(name) {{
  if (busyPkg) {{
    showToast('Bitte warten \\u2014 andere Aktion l\\u00E4uft noch.', false);
    return;
  }}
  busyPkg = name;
  renderPackages();
  try {{
    const msg = await pywebview.api.uninstall_package(name);
    showToast(msg, true);
    setTimeout(loadPackages, 800);
  }} catch (e) {{
    const m = e.message || 'Fehler bei Deinstallation';
    if (m.indexOf('__TOKEN_REVOKED__') !== -1) {{ showRevokedOverlay(); return; }}
    showToast(m, false);
  }} finally {{
    busyPkg = null;
    renderPackages();
  }}
}}

// ─── UI Helpers ───

function showLoading() {{
  document.getElementById('content').innerHTML = `
    <div class="loading">
      <div class="spinner"></div>
      <div class="loading-text">Pakete werden geladen...</div>
    </div>`;
}}

function showError(msg) {{
  document.getElementById('content').innerHTML = `
    <div class="error-state">
      <div class="error-icon">!</div>
      <div class="error-title">Verbindungsfehler</div>
      <div class="error-detail">${{escHtml(msg)}}</div>
      <button class="btn-retry" onclick="loadPackages()">Erneut versuchen</button>
    </div>`;
}}

let toastTimer = null;
function showToast(msg, success) {{
  const el = document.getElementById('toast');
  el.textContent = msg;
  el.className = 'toast visible ' + (success ? 'success' : 'error');
  if (toastTimer) clearTimeout(toastTimer);
  toastTimer = setTimeout(() => {{
    el.className = 'toast';
    toastTimer = null;
  }}, 3200);
}}

function setOnlineState(online) {{
  const banner = document.getElementById('offlineBanner');
  const dot = document.getElementById('statusDot');
  const text = document.getElementById('statusText');
  if (online) {{
    banner.classList.remove('visible');
    dot.classList.remove('offline');
    text.textContent = 'Verbunden';
  }} else {{
    banner.classList.add('visible');
    dot.classList.add('offline');
    text.textContent = 'Offline';
  }}
}}

function escHtml(s) {{
  if (!s) return '';
  return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}}

function escAttr(s) {{
  if (!s) return '';
  return s.replace(/\\\\/g,'\\\\\\\\').replace(/'/g,"\\\\'").replace(/"/g,'&quot;');
}}
</script>
</body>
</html>"""


# ─────────────────────────────────────────────────────── Python API Bridge ────

_TOKEN_REVOKED_MARKER = "__TOKEN_REVOKED__"


def _format_http_error(e: Exception) -> str:
    """Konvertiert httpx-Fehler in eine UI-taugliche Fehlermeldung.
    401 -> Marker damit das Frontend ein Overlay zeigt statt Toast."""
    import httpx
    if isinstance(e, httpx.HTTPStatusError):
        if e.response.status_code == 401:
            return _TOKEN_REVOKED_MARKER
        try:
            detail = e.response.json().get("detail", str(e))
        except Exception:
            detail = str(e)
        return f"HTTP {e.response.status_code}: {detail}"
    return str(e)


class PackageApi:
    """JS-to-Python bridge exposed via pywebview js_api."""

    def __init__(self, api_client: KioskApiClient):
        self._api = api_client

    def get_packages(self) -> list[dict]:
        """Returns package list as list of dicts for JS consumption.
        Bei 401 wird `__TOKEN_REVOKED__` geraised damit das Frontend
        das Overlay statt eines Toasts zeigt."""
        try:
            pkgs = self._api.get_packages()
            return [
                {
                    "name": p.name,
                    "display_name": p.display_name,
                    "version": p.version,
                    "installed": p.installed,
                    "category": p.category,
                    "type": p.type,
                    "publisher": p.publisher,
                    "installed_version_label": p.installed_version_label,
                    "current_version_label": p.current_version_label,
                    "update_available": p.update_available,
                    "hide_uninstall": getattr(p, "hide_uninstall", False),
                    "process_check": getattr(p, "process_check", "") or "",
                }
                for p in pkgs
            ]
        except Exception as e:
            raise Exception(_format_http_error(e))

    def check_running_processes(self, names_csv: str) -> list[str]:
        """Lokale Prozesspruefung. Liefert Liste der gerade laufenden
        Prozessnamen die in `names_csv` (Komma-separiert) enthalten sind.
        `.exe` wird abgestrippt fuer den Vergleich, da tasklist beides liefert."""
        if not names_csv or not names_csv.strip():
            return []
        wanted = set()
        for n in names_csv.replace(";", ",").split(","):
            n = n.strip()
            if not n:
                continue
            if n.lower().endswith(".exe"):
                n = n[:-4]
            wanted.add(n.lower())
        if not wanted:
            return []
        try:
            import subprocess
            # tasklist /FO CSV /NH liefert: "name.exe","PID","Session",...
            r = subprocess.run(
                ["tasklist", "/FO", "CSV", "/NH"],
                capture_output=True, text=True, timeout=8,
                creationflags=0x08000000,  # CREATE_NO_WINDOW
            )
            running = set()
            for line in r.stdout.splitlines():
                # erste Spalte = Name in quotes
                if not line.startswith('"'):
                    continue
                end = line.find('"', 1)
                if end <= 1:
                    continue
                pname = line[1:end]
                if pname.lower().endswith(".exe"):
                    pname = pname[:-4]
                running.add(pname.lower())
            return sorted(n for n in wanted if n in running)
        except Exception:
            return []

    def install_package(self, name: str) -> str:
        """Trigger install via proxy."""
        try:
            return self._api.install_package(name)
        except Exception as e:
            raise Exception(_format_http_error(e))

    def uninstall_package(self, name: str) -> str:
        """Trigger uninstall via proxy."""
        try:
            return self._api.uninstall_package(name)
        except Exception as e:
            raise Exception(_format_http_error(e))

    def get_reinstall_url(self) -> str:
        """Optional reinstall URL aus Client-Config (default leer)."""
        try:
            cfg = self._api.get_client_config()
            return cfg.get("reinstall_url", "") or ""
        except Exception:
            return ""


# ────────────────────────────────────────────────────── Window Management ─────

_main_window: webview.Window | None = None
_window_lock = threading.Lock()


def show_main_window(api_client: KioskApiClient, app_name: str = "Softshelf"):
    """Create or show the main package window. Thread-safe."""
    global _main_window

    with _window_lock:
        if _main_window is not None:
            try:
                _main_window.show()
                _main_window.restore()
                _main_window.on_top = True
                _main_window.on_top = False
                return
            except Exception:
                _main_window = None

        html = _HTML.format(
            app_name=_h(app_name),
            version=_h(__version__),
        )
        js_api = PackageApi(api_client)
        _main_window = webview.create_window(
            app_name,
            html=html,
            js_api=js_api,
            width=480,
            height=620,
            min_size=(380, 440),
            resizable=True,
            text_select=False,
        )
        _main_window.events.closed += _on_main_closed


def _on_main_closed():
    global _main_window
    with _window_lock:
        _main_window = None


def set_online_state(online: bool):
    """Update the online/offline state in the package window JS."""
    if _main_window is not None:
        try:
            _main_window.evaluate_js(
                f"if(typeof setOnlineState==='function')setOnlineState({'true' if online else 'false'})"
            )
        except Exception:
            pass


def destroy_main_window():
    """Close the main window if open."""
    global _main_window
    with _window_lock:
        if _main_window is not None:
            try:
                _main_window.destroy()
            except Exception:
                pass
            _main_window = None
