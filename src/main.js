// ─── Tauri bridge ────────────────────────────────────────────────────────────
const tauri  = window.__TAURI__?.tauri  ?? { invoke: () => Promise.reject('No Tauri') };
const events = window.__TAURI__?.event  ?? { listen: () => {} };
const invoke = (cmd, args) => tauri.invoke(cmd, args);
const listen  = (evt, cb)  => events.listen(evt, cb);

// ─── Default settings (every configurable option) ────────────────────────────
const DEFAULTS = {
  // API & Engine
  apiKey:          '',
  model:           'claude-sonnet-4-6',
  modelCustom:     '',
  maxIter:         0,           // 0 = auto (score-guided budget per difficulty)
  maxTokens:       4096,
  concurrent:      1,
  parallelBranches: true,       // parallel hypothesis branches for hard/insane
  autoSubmit:      true,
  autoWriteup:     true,
  autoWorkspace:   true,
  retryFailed:     false,
  maxRetry:        2,
  // Python & Tools
  pythonPath:      'python3',
  solverPath:      '',
  wslDistro:       '',
  shellTimeout:    30,
  httpTimeout:     20,
  dlTimeout:       60,
  tools: {
    shell: true, python: true, decode: true, http: true,
    file:  true, workspace: true, writefile: true, download: true, submit: true,
    flagformat: true,
    knowledge: true, browser: true, ghidra: true, airename: true,
    libclookup: true, factordb: true, angr: true, sqlmap: true,
    ffuf: true, webcrawl: true, volatility: true, frida: true,
    rank: true, recon: true,
  },
  logPreview:      400,
  maxLogLines:     2000,
  verbosity:       'normal',
  // Platform
  ctfName:         '',
  platform:        'manual',
  ctfUrl:          '',
  ctfUser:         '',
  ctfPass:         '',
  ctfToken:        '',
  platformToken:   '',
  baseDir:         '',
  writeupName:     'WRITEUP.md',
  notesName:       'notes.txt',
  flagPatterns:    '',
  // Solver behaviour
  systemPrompt:    '',
  analysisDepth:   'thorough',
  pivot:           'auto',
  writeupDetail:   'normal',
  writeupStyle:    'technical',
  extraInstructions: '',
  hintPwn:         '',
  hintCrypto:      '',
  hintWeb:         '',
  hintForensics:   '',
  // UI
  panelWidth:      360,
  split:           '1fr 1fr',
  fontSize:        12,
  lineHeight:      1.6,
  font:            "'JetBrains Mono', monospace",
  colBg:           '#121722',
  colAccent:       '#8ab4ff',
  colBorder:       '#3c4b6b',
  showKb:          true,
  scanlines:       true,
  blinkCursor:     true,
  logTimestamps:   true,
  animateLog:      true,
};

// ─── State ────────────────────────────────────────────────────────────────────
let challenges  = [];
let selectedId  = null;
let settings    = deepClone(DEFAULTS);
let startTime   = Date.now();

const CAT_SHORT = {
  'Binary Exploitation':'pwn','Cryptography':'crypto','Forensics':'forensics',
  'Web':'web','Reverse Engineering':'rev','Misc':'misc','OSINT':'osint',
};
const STATUS_SORT = { solving:0, staged:1, queued:2, solved:3, failed:4 };

function deepClone(o) { return JSON.parse(JSON.stringify(o)); }
function uid()    { return Math.random().toString(36).slice(2,10); }
function esc(s)   { return String(s??'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
function ch(id)   { return challenges.find(c=>c.id===id)??null; }
function tryParseJSON(raw) {
  try { return JSON.parse(raw); }
  catch(_) { return null; }
}
function parseInvokeJson(raw, label='invoke') {
  const text = String(raw ?? '').trim();
  if (!text) throw new Error(`${label} returned empty output`);

  const direct = tryParseJSON(text);
  if (direct && typeof direct === 'object') return direct;

  const lines = text.split(/\r?\n/).map(s => s.trim()).filter(Boolean);
  for (let i = lines.length - 1; i >= 0; i--) {
    const parsed = tryParseJSON(lines[i]);
    if (parsed && typeof parsed === 'object') return parsed;
  }

  const tail = text.slice(-500).replace(/\s+/g, ' ').trim();
  throw new Error(`${label} returned non-JSON output. Raw tail: ${tail || '[empty]'}`);
}
function formatBytes(bytes) {
  if (!Number.isFinite(bytes) || bytes < 1024) return `${bytes || 0} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function normalizePathForCompare(path) {
  return String(path || '').trim().replace(/\\/g, '/').toLowerCase();
}

function validateSolverPath(path) {
  const raw = String(path || '').trim();
  const norm = normalizePathForCompare(raw);
  if (!raw) {
    return { ok: false, message: 'Solver path is required.' };
  }
  if (norm.includes('sidecarsolver.py')) {
    return { ok: false, message: "Invalid path: found 'sidecarsolver.py'. Use 'sidecar/solver.py'." };
  }
  if (!norm.endsWith('/sidecar/solver.py') && !norm.endsWith('sidecar/solver.py')) {
    return { ok: false, message: "Path must point to 'sidecar/solver.py'." };
  }
  return { ok: true, message: '✓ Solver path format looks valid.' };
}

function setSolverPathStatus(message, ok = false) {
  const el = g('s-solver-status');
  if (!el) return;
  el.textContent = message || '';
  el.style.color = ok ? 'var(--text-mid)' : '#666';
}

function isLikelyTextFile(file) {
  const type = file.type || '';
  if (type.startsWith('text/')) return true;
  if (/json|xml|javascript|x-sh|x-python|x-rust|toml|yaml|csv/i.test(type)) return true;
  return /\.(txt|md|log|json|yaml|yml|xml|csv|py|js|ts|jsx|tsx|rs|c|cc|cpp|h|hpp|java|go|php|html|css|sh|bash|zsh|sql|asm|s|ini|cfg|conf|toml|lock)$/i.test(file.name || '');
}

function readFileAsText(file) {
  return new Promise((resolve) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result ?? ''));
    reader.onerror = () => resolve('');
    reader.readAsText(file);
  });
}

function readFileAsBase64(file) {
  return new Promise((resolve) => {
    const reader = new FileReader();
    reader.onload = () => {
      const raw = String(reader.result ?? '');
      const comma = raw.indexOf(',');
      resolve(comma >= 0 ? raw.slice(comma + 1) : '');
    };
    reader.onerror = () => resolve('');
    reader.readAsDataURL(file);
  });
}

function extractDroppedFiles(event) {
  const dt = event?.dataTransfer;
  if (!dt) return [];

  if (dt.items && dt.items.length) {
    const out = [];
    for (const item of Array.from(dt.items)) {
      if (item.kind !== 'file') continue;
      const file = item.getAsFile?.();
      if (file) out.push(file);
    }
    if (out.length) return out;
  }

  return Array.from(dt.files || []);
}

async function buildSourceBlock(file) {
  const mime = file.type || 'application/octet-stream';
  const header = `[FILE] ${file.name} (${formatBytes(file.size)})`;

  if (isLikelyTextFile(file)) {
    const content = await readFileAsText(file);
    if (content.trim()) return `${header}\n[TYPE] ${mime}\n${content}`;
  }

  const b64 = await readFileAsBase64(file);
  if (!b64) return `${header}\n[TYPE] ${mime}\n[Unreadable file content]`;
  return `${header}\n[TYPE] ${mime}\n[ENCODING] base64\n[CONTENT_BASE64_BEGIN]\n${b64}\n[CONTENT_BASE64_END]`;
}

function ts() {
  const ms=Date.now()-startTime, s=Math.floor(ms/1000);
  return [Math.floor(s/3600),Math.floor((s%3600)/60),s%60].map(n=>String(n).padStart(2,'0')).join(':');
}

// ─── Persistence ─────────────────────────────────────────────────────────────
function loadSettings() {
  try {
    const s = localStorage.getItem('ctf-solver-v2');
    if (s) settings = Object.assign(deepClone(DEFAULTS), JSON.parse(s));
    const sessionKey = sessionStorage.getItem('ctf-solver-session-apikey');
    if (typeof sessionKey === 'string' && sessionKey.trim()) {
      settings.apiKey = sessionKey.trim();
    }
    const legacyBg = (settings.colBg || '').toLowerCase() === '#040404';
    const legacyAcc = (settings.colAccent || '').toLowerCase() === '#e8e8e8';
    const legacyBrd = (settings.colBorder || '').toLowerCase() === '#242424';
    if (legacyBg && legacyAcc && legacyBrd) {
      settings.colBg = DEFAULTS.colBg;
      settings.colAccent = DEFAULTS.colAccent;
      settings.colBorder = DEFAULTS.colBorder;
    }
  } catch(_) {}
}
function persistSettings() {
  const persisted = deepClone(settings);
  persisted.apiKey = '';
  localStorage.setItem('ctf-solver-v2', JSON.stringify(persisted));
  if (settings.apiKey) {
    sessionStorage.setItem('ctf-solver-session-apikey', settings.apiKey);
  } else {
    sessionStorage.removeItem('ctf-solver-session-apikey');
  }
}

// ─── Apply settings → DOM + CSS ──────────────────────────────────────────────
function applyAll() {
  // CSS variables
  const r = document.documentElement.style;
  r.setProperty('--font',   settings.font);
  r.setProperty('--fs',     settings.fontSize + 'px');
  r.setProperty('--lh',     String(settings.lineHeight));
  r.setProperty('--left-w', settings.panelWidth + 'px');
  r.setProperty('--split',  settings.split);
  r.setProperty('--bg-root',    settings.colBg);
  r.setProperty('--border',     settings.colBorder);
  r.setProperty('--border-bright', adjustBrightness(settings.colBorder, 20));
  r.setProperty('--accent', settings.colAccent);

  // Scanlines
  document.body.classList.toggle('scanlines', settings.scanlines);

  // Keyboard hints
  document.querySelectorAll('.kb').forEach(el => {
    el.classList.toggle('hidden', !settings.showKb);
  });

  // Blinking cursor
  document.getElementById('sb-cursor')?.classList.toggle('hidden', !settings.blinkCursor);

  // Status bar
  document.getElementById('sb-key').textContent =
    settings.apiKey ? 'sk-ant-...'+settings.apiKey.slice(-4) : 'not set';
  document.getElementById('sb-python').textContent = settings.pythonPath || '—';
  document.getElementById('sb-tools').textContent  = countEnabledTools();

  // Platform bar
  const nameEl = document.getElementById('pb-ctf-name');
  nameEl.textContent = settings.ctfName || 'not set';
  nameEl.className   = 'pb-val' + (settings.ctfName ? ' active' : '');
  document.getElementById('pb-platform').textContent = settings.platform || 'manual';
  document.getElementById('pb-model').textContent    = activeModel();
  document.getElementById('pb-iter').textContent     = settings.maxIter || 'auto';
  document.getElementById('pb-workdir').textContent  = settings.baseDir ? shortenPath(settings.baseDir) : 'not set';
  // New elements — reset when not solving
  if (!_runtimeInterval) {
    const rt=g('pb-runtime'); if(rt) rt.textContent='—';
    const rs=g('pb-reasoning'); if(rs){ rs.textContent='off'; rs.style.color=''; }
  }

  // Open-folder button in platform bar
  const ofBtn = document.getElementById('btn-open-folder');
  if (ofBtn) ofBtn.style.display = (settings.baseDir && settings.ctfName) ? '' : 'none';
}

function activeModel() {
  return settings.model === 'custom' ? (settings.modelCustom || '?') : settings.model.split('-').slice(1,3).join('-');
}

function countEnabledTools() {
  const t = settings.tools || {};
  const on = Object.values(t).filter(Boolean).length;
  const total = Object.keys(DEFAULTS.tools).length;
  return on === total ? 'all' : `${on}/${total}`;
}

function shortenPath(p) {
  if (p.length <= 30) return p;
  return '...' + p.slice(-27);
}

function adjustBrightness(hex, pct) {
  try {
    const n = parseInt(hex.replace('#',''), 16);
    const r = Math.min(255, ((n>>16)&0xff)+pct);
    const g = Math.min(255, ((n>>8)&0xff)+pct);
    const b = Math.min(255, (n&0xff)+pct);
    return `#${[r,g,b].map(v=>v.toString(16).padStart(2,'0')).join('')}`;
  } catch { return hex; }
}

// ─── Logging ─────────────────────────────────────────────────────────────────
function addLog(tag, msg, cls='') {
  const verbosity = settings.verbosity || 'normal';
  if (verbosity === 'minimal' && !['ok','err','sys'].includes(tag)) return;
  if (verbosity === 'normal'  && cls === 'dim') return;

  const el = document.getElementById('log-body');
  // Trim log if over limit
  while (el.children.length >= (settings.maxLogLines || 2000)) {
    el.removeChild(el.firstChild);
  }

  const d = document.createElement('div');
  d.className = 'log-line' + (settings.animateLog ? ' animate' : '');
  const tsHtml = settings.logTimestamps
    ? `<span class="log-ts">${ts()}</span>`
    : `<span class="log-ts hidden"></span>`;
  d.innerHTML = `${tsHtml}<span class="log-tag ${tag}">${tag.toUpperCase()}</span><span class="log-msg ${cls}">${esc(msg)}</span>`;
  el.appendChild(d);
  el.scrollTop = el.scrollHeight;
}

// ─── Challenge management ─────────────────────────────────────────────────────
function addChallenge(c) {
  challenges.push(c); renderList(); updateStats();
}

function sortedChallenges() {
  return [...challenges].sort((a,b) => {
    const ao=STATUS_SORT[a.status]??9, bo=STATUS_SORT[b.status]??9;
    return ao-bo || a.createdAt-b.createdAt;
  });
}

// ─── Render: list ─────────────────────────────────────────────────────────────
function renderList() {
  const el = document.getElementById('ch-list');
  const sorted = sortedChallenges();
  if (!sorted.length) {
    el.innerHTML = `<div class="list-empty">
      <span>no challenges loaded</span>
      <span style="font-size:10px;color:var(--border-bright)">add below or import from platform</span>
    </div>`; return;
  }
  el.innerHTML = sorted.map(c => {
    const cat   = CAT_SHORT[c.category] ?? c.category.toLowerCase();
    const sel   = c.id===selectedId ? 'active' : '';
    const sol   = c.status==='solving' ? 'is-solving' : '';
    return `<div class="ch-item ${sel} ${sol}" onclick="App.select('${c.id}')">
      <span class="stag ${c.status}">${c.status.toUpperCase()}</span>
      <span class="ch-sep">—</span><span class="ch-cat">${esc(cat)}</span>
      <span class="ch-sep"> </span><span class="ch-name">${esc(c.name)}</span>
    </div>`;
  }).join('');
}

// ─── Render: details ──────────────────────────────────────────────────────────
function renderDetails() {
  const body  = document.getElementById('details-body');
  const fill  = document.getElementById('details-fill');
  const wsBtn = document.getElementById('btn-open-ws');
  document.getElementById('sb-selected').textContent = selectedId ? (ch(selectedId)?.name??'—') : '—';

  if (!selectedId) {
    fill.textContent = '────────────────────────────────────────────────────────────────────';
    if (wsBtn) wsBtn.style.display='none';
    body.innerHTML = `<div class="empty-state"><pre class="empty-art empty-art-3d">
╔══════════════════════════════════════╗
║             ROOT RUNNER              ║
╚══════════════════════════════════════╝
</pre><span>select a challenge</span></div>`;
    return;
  }
  const c = ch(selectedId); if (!c) return;
  fill.textContent = `── ${c.name} `;
  if (wsBtn) wsBtn.style.display = c.workspace ? '' : 'none';

  const sCls = c.status==='solving' ? 'v-pulse' : '';
  const runtimeRow = c.runtime
    ? `<div class="det-row"><span class="det-key">runtime</span><span class="det-val">${c.runtime}s</span></div>`
    : c.status==='solving'
    ? `<div class="det-row"><span class="det-key">runtime</span><span class="det-val" id="ch-runtime-val">—</span></div>`
    : '';
  const modelRow = c.solveModel
    ? `<div class="det-row"><span class="det-key">model used</span><span class="det-val v-mid">${c.solveModel}</span></div>`
    : '';
  const iterRow = c.solveIter
    ? `<div class="det-row"><span class="det-key">iterations</span><span class="det-val">${c.solveIter}</span></div>`
    : '';
  body.innerHTML = `
    <div class="det-row"><span class="det-key">name</span><span class="det-val v-white">${esc(c.name)}</span></div>
    <div class="det-row"><span class="det-key">category</span><span class="det-val">${esc(c.category)}</span></div>
    <div class="det-row"><span class="det-key">difficulty</span><span class="det-val">${esc(c.difficulty)}</span></div>
    <div class="det-row"><span class="det-key">points</span><span class="det-val">${c.points}</span></div>
    <div class="det-row"><span class="det-key">status</span><span class="det-val ${sCls}">${c.status.toUpperCase()}${c.status==='solving'?' <span class="spin">◌</span>':''}</span></div>
    ${runtimeRow}${modelRow}${iterRow}
    ${c.platform_id?`<div class="det-row"><span class="det-key">platform id</span><span class="det-val v-mid">${esc(c.platform_id)}</span></div>`:''}
    ${c.instance?`<div class="det-row"><span class="det-key">instance</span><span class="det-val">${esc(c.instance)}</span></div>`:''}
    ${c.workspace?`<div class="det-row"><span class="det-key">workspace</span><span class="det-val v-mid" style="font-size:10px">${esc(c.workspace)}</span></div>`:''}
    <div class="det-divider">├─ description ──────────────────────────────────────────────────</div>
    <div class="det-desc">${esc(c.description||'(no description)')}</div>
    ${c.files?`<div class="det-divider">├─ files ─────────────────────────────────────────────────────────</div><div class="det-desc">${esc(c.files)}</div>`:''}
    ${c.flag?`<div class="flag-display">${esc(c.flag)}</div>`:''}
    <div class="det-divider">└────────────────────────────────────────────────────────────────</div>`;
}

// ─── Stats ────────────────────────────────────────────────────────────────────
function updateStats() {
  const ct={staged:0,solving:0,solved:0,failed:0};
  challenges.forEach(c=>{ if(ct[c.status]!==undefined) ct[c.status]++; });
  ['staged','solving','solved','failed'].forEach(k=>{
    document.getElementById(`st-${k}`).textContent=ct[k];
  });
  document.getElementById('st-total').textContent=challenges.length;
}

// ─── Solver ───────────────────────────────────────────────────────────────────
function buildPlatformConfig() {
  return {
    type:     settings.platform,
    url:      settings.ctfUrl,
    username: settings.ctfUser,
    password: settings.ctfPass,
    token:    settings.platformToken || settings.ctfToken,
  };
}

function buildEnabledTools() {
  const t = settings.tools || {};
  const toolNameMap = {
    shell:'execute_shell', python:'execute_python', decode:'decode_transform',
    http:'http_request', file:'analyze_file', workspace:'create_workspace',
    writefile:'write_file', download:'download_file', submit:'submit_flag',
    flagformat:'detect_flag_format',
    // Elite Intelligence Layer
    knowledge:'knowledge_store',   // also enables knowledge_get
    browser:'browser_agent', ghidra:'ghidra_decompile', airename:'ai_rename_functions',
    libclookup:'libc_lookup', factordb:'factordb', angr:'angr_solve',
    sqlmap:'sqlmap', ffuf:'ffuf', webcrawl:'web_crawl',
    volatility:'volatility', frida:'frida_trace',
    rank:'rank_hypotheses', recon:'pre_solve_recon',
  };
  const enabled = [];
  for (const [k,v] of Object.entries(t)) {
    if (!v) continue;
    const mapped = toolNameMap[k];
    if (mapped) {
      enabled.push(mapped);
      // knowledge_store always pairs with knowledge_get
      if (k === 'knowledge') enabled.push('knowledge_get');
    }
  }
  return enabled;
}

function buildExtraConfig() {
  return {
    maxTokens:        settings.maxTokens,
    shellTimeout:     settings.shellTimeout,
    httpTimeout:      settings.httpTimeout,
    dlTimeout:        settings.dlTimeout,
    enabledTools:     buildEnabledTools(),
    autoSubmit:       settings.autoSubmit,
    autoWriteup:      settings.autoWriteup,
    autoWorkspace:    settings.autoWorkspace,
    writeupName:      settings.writeupName,
    notesName:        settings.notesName,
    flagPatterns:     settings.flagPatterns,
    systemPrompt:     settings.systemPrompt,
    analysisDepth:    settings.analysisDepth,
    pivot:            settings.pivot,
    writeupDetail:    settings.writeupDetail,
    writeupStyle:     settings.writeupStyle,
    extraInstructions:settings.extraInstructions,
    parallelBranches: settings.parallelBranches,
    hints: {
      'Binary Exploitation': settings.hintPwn,
      'Cryptography':        settings.hintCrypto,
      'Web':                 settings.hintWeb,
      'Forensics':           settings.hintForensics,
    },
    logPreview:  settings.logPreview,
    wslDistro:   settings.wslDistro,
  };
}

// ─── Live runtime timer ───────────────────────────────────────────────────────
let _runtimeInterval = null;
let _solveStartTime  = 0;
let _currentIter     = 0;
let _currentModel    = '';
let _currentThinking = false;

function _startRuntimeTimer(c) {
  _solveStartTime = Date.now();
  _currentIter    = 0;
  if (_runtimeInterval) clearInterval(_runtimeInterval);
  _runtimeInterval = setInterval(() => {
    const elapsed = Math.floor((Date.now() - _solveStartTime) / 1000);
    const h = Math.floor(elapsed/3600).toString().padStart(2,'0');
    const m = Math.floor((elapsed%3600)/60).toString().padStart(2,'0');
    const s = (elapsed%60).toString().padStart(2,'0');
    const rt = g('pb-runtime');
    if (rt) rt.textContent = `${h}:${m}:${s}`;
    // update details panel runtime if selected
    if (selectedId === c.id) {
      const det = g('ch-runtime-val');
      if (det) det.textContent = `${h}:${m}:${s}`;
    }
  }, 1000);
}

function _stopRuntimeTimer(elapsed) {
  if (_runtimeInterval) { clearInterval(_runtimeInterval); _runtimeInterval = null; }
  const rt = g('pb-runtime');
  if (rt && elapsed) rt.textContent = `${Math.floor(elapsed/3600).toString().padStart(2,'0')}:${Math.floor((elapsed%3600)/60).toString().padStart(2,'0')}:${(elapsed%60).toString().padStart(2,'0')}`;
}

async function solveCh(c) {
  if (!settings.apiKey)    { addLog('err','No API key — open Settings → API & Engine','red'); return; }
  if (!settings.solverPath){ addLog('err','No solver path — open Settings → Python & Tools','red'); return; }

  c.status='solving'; c.flag=null; c.runtime=null; c.solveModel=null; c.solveIter=null;
  renderList(); if(selectedId===c.id) renderDetails(); updateStats();
  document.getElementById('solving-indicator').style.display='';

  // Reset live indicators
  const fmtEl=g('pb-flagfmt');
  if(fmtEl){ fmtEl.textContent='detecting...'; fmtEl.style.color='var(--text-dim)'; fmtEl.title=''; }
  const reasonEl=g('pb-reasoning');
  if(reasonEl){ reasonEl.textContent='off'; reasonEl.style.color=''; }
  const modelEl=g('pb-model');
  if(modelEl) modelEl.textContent=activeModel();

  _startRuntimeTimer(c);
  addLog('sys',`━━━ Solving: [${c.category}] ${c.name} ━━━`,'bright');
  addLog('sys',`Budget: auto (score-guided) | Parallel branches: ${settings.parallelBranches?'on':'off'}`,'dim');

  try {
    const raw = await invoke('solve_challenge', {
      challenge:     c,
      apiKey:        settings.apiKey,
      pythonPath:    settings.pythonPath || 'python3',
      solverPath:    settings.solverPath,
      model:         settings.model==='custom' ? settings.modelCustom : settings.model,
      maxIterations: Number(settings.maxIter)||0,   // 0 = auto budget
      platform:      buildPlatformConfig(),
      baseDir:       settings.baseDir || '',
      ctfName:       settings.ctfName || '',
      extraConfig:   buildExtraConfig(),
    });
    const res = parseInvokeJson(raw, 'solve_challenge');
    c.status    = res.status;
    if (res.flag)      c.flag      = res.flag;
    if (res.workspace) c.workspace = res.workspace;
    if (String(res.status || '').toLowerCase() === 'failed' && res.reason) {
      addLog('err', `Failure reason: ${res.reason}`, 'red');
    }
    // Capture final stats if emitted
    if (res.elapsed)   { c.runtime   = res.elapsed; _stopRuntimeTimer(res.elapsed); }
    if (res.iterations){ c.solveIter = res.iterations; }
    if (res.model)     { c.solveModel= res.model; }
  } catch(err) {
    c.status='failed';
    addLog('err',`Invoke error: ${err && err.message ? err.message : err}`,'red');
  }

  const elapsed = Math.round((Date.now()-_solveStartTime)/1000);
  _stopRuntimeTimer(elapsed);
  c.runtime = c.runtime || elapsed;

  addLog('sys',`━━━ Done: ${c.name} → ${c.status.toUpperCase()} | ${elapsed}s ━━━`,
    c.status==='solved'?'white':c.status==='failed'?'red':'');
  document.getElementById('solving-indicator').style.display='none';
  renderList(); if(selectedId===c.id) renderDetails(); updateStats();
}

// ─── Settings tab switching ───────────────────────────────────────────────────
document.querySelectorAll('.stab').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.stab').forEach(b=>b.classList.remove('active'));
    document.querySelectorAll('.stab-content').forEach(c=>c.classList.remove('active'));
    btn.classList.add('active');
    const tab = document.getElementById('tab-'+btn.dataset.tab);
    if (tab) tab.classList.add('active');
  });
});

// ─── Settings helpers ─────────────────────────────────────────────────────────
function g(id)    { return document.getElementById(id); }
function gv(id)   { return g(id)?.value ?? ''; }
function gc(id)   { return g(id)?.checked ?? false; }
function sv(id,v) { if(g(id)) g(id).value = v ?? ''; }
function sc(id,v) { if(g(id)) g(id).checked = !!v; }

function syncModelInput() {
  const isCustom = gv('s-model') === 'custom';
  const ci = g('s-model-custom');
  if (ci) ci.disabled = !isCustom;
}

function updatePlatformFields() {
  const plat = gv('s-platform');
  const pf   = g('platform-fields');
  const url  = g('pf-url-group');
  if (pf)  pf.style.display  = plat==='manual' ? 'none' : '';
  if (url) url.style.display = ['ctfd','htb'].includes(plat) ? '' : 'none';
}

function toggleShow(inputId, btn) {
  const el = g(inputId);
  if (!el) return;
  const show = el.type === 'password';
  el.type = show ? 'text' : 'password';
  btn.textContent = show ? 'HIDE' : 'SHOW';
}

function syncColor(colorId, textId, fromText) {
  if (fromText) {
    const val = gv(textId);
    if (/^#[0-9a-fA-F]{6}$/.test(val)) sv(colorId, val);
  } else {
    sv(textId, gv(colorId));
  }
  App.applyUISettings();
}

// ─── Public App API ───────────────────────────────────────────────────────────
const App = {

  select(id) { selectedId=id; renderList(); renderDetails(); },

  quickAdd() {
    const name=gv('qa-name').trim(), cat=gv('qa-cat');
    if (!name) return;
    const c={id:uid(),name,category:cat,description:'',files:'',instance:'',
             flagFormat:'',points:100,difficulty:'medium',
             status:'staged',flag:null,workspace:'',platform_id:'',createdAt:Date.now()};
    addChallenge(c);
    g('qa-name').value='';
    App.select(c.id);
    addLog('sys',`Added: [${cat}] ${name}`,'bright');
    addLog('warn','No description — open ⚙ to add context before solving.');
  },

  openModal() {
    const n=gv('qa-name').trim();
    if(n) sv('m-name',n);
    g('modal-overlay').classList.add('open');
    g('m-name').focus();
  },
  closeModal() {
    g('modal-overlay').classList.remove('open');
    ['m-name','m-desc','m-files','m-inst','m-fmt'].forEach(id=>sv(id,''));
    sv('m-pts','100');
    if (g('m-files-input')) g('m-files-input').value = '';
    g('m-files')?.classList.remove('is-drop');
  },
  pickSourceFiles() {
    g('m-files-input')?.click();
  },
  async loadSourceFiles(fileList) {
    const files = Array.from(fileList || []);
    if (!files.length) return;

    const blocks = [];
    for (const file of files) {
      blocks.push(await buildSourceBlock(file));
    }

    const existing = gv('m-files').trim();
    const next = blocks.join('\n\n');
    sv('m-files', existing ? `${existing}\n\n${next}` : next);
    if (g('m-files-input')) g('m-files-input').value = '';
    addLog('sys', `Attached ${files.length} file(s) into challenge source field.`);
    g('m-files')?.focus();
  },
  addFromModal() {
    const name=gv('m-name').trim(), desc=gv('m-desc').trim();
    if(!name||!desc){ alert('Name and description are required.'); return; }
    const c={id:uid(),name,category:gv('m-cat'),description:desc,
             files:gv('m-files').trim(),instance:gv('m-inst').trim(),
             flagFormat:gv('m-fmt').trim(),points:parseInt(gv('m-pts'))||100,
             difficulty:gv('m-diff'),status:'staged',flag:null,
             workspace:'',platform_id:'',createdAt:Date.now()};
    addChallenge(c); App.closeModal(); App.select(c.id);
    addLog('sys',`Added: [${c.category}] ${c.name}`,'bright');
  },

  removeSelected() {
    if(!selectedId) return;
    const c=ch(selectedId); if(!c) return;
    if(c.status==='solving'){ addLog('warn','Cannot remove while solving.'); return; }
    challenges=challenges.filter(x=>x.id!==selectedId);
    selectedId=null; renderList(); renderDetails(); updateStats();
    addLog('sys','Challenge removed.');
  },

  async solveSelected() {
    if(!selectedId){ addLog('warn','No challenge selected.'); return; }
    const c=ch(selectedId); if(!c) return;
    if(c.status==='solving'){ addLog('warn','Already solving.'); return; }
    await solveCh(c);
  },

  async solveAll() {
    const statuses = ['staged','queued'];
    if(settings.retryFailed) statuses.push('failed');
    const queue=challenges.filter(c=>statuses.includes(c.status));
    if(!queue.length){ addLog('warn','No unsolved challenges.'); return; }
    addLog('sys',`Queuing ${queue.length} challenge(s)...`,'bright');
    queue.forEach(c=>{ if(c.status!=='solving') c.status='queued'; });
    renderList(); updateStats();

    const concur = Number(settings.concurrent)||1;
    for(let i=0;i<queue.length;i+=concur) {
      const batch=queue.slice(i,i+concur);
      await Promise.all(batch.map(c=>solveCh(c)));
    }
  },

  async cancelSolve() {
    try{ await invoke('cancel_solve'); addLog('sys','Cancel signal sent.'); }
    catch(e){ addLog('err',`Cancel failed: ${e}`,'red'); }
  },

  clearLog() { g('log-body').innerHTML=''; addLog('sys','Log cleared.'); },

  async openWorkspace() {
    if(!settings.baseDir||!settings.ctfName){ addLog('warn','Set CTF Name and Working Directory in Settings.'); return; }
    const sep=settings.baseDir.includes('/')?'/':'\\';
    const p=settings.baseDir+sep+settings.ctfName;
    try{ await invoke('open_folder',{path:p}); }
    catch(e){ addLog('err',`Cannot open folder: ${e}`,'red'); }
  },

  async openSelectedWorkspace() {
    const c=ch(selectedId);
    if(!c||!c.workspace){ addLog('warn','No workspace for this challenge yet.'); return; }
    try{ await invoke('open_folder',{path:c.workspace}); }
    catch(e){ addLog('err',`Cannot open folder: ${e}`,'red'); }
  },

  async importChallenges() {
    if(!settings.ctfName)  { addLog('err','Set CTF Name in Settings first.','red'); return; }
    if(!settings.baseDir)  { addLog('err','Set Working Directory in Settings first.','red'); return; }
    if(!settings.solverPath){ addLog('err','Set Solver Script Path in Settings first.','red'); return; }
    if(settings.platform!=='manual'&&!settings.ctfUser&&!settings.ctfToken&&!settings.platformToken){
      addLog('err','No credentials set. Open Settings → Platform.','red'); return;
    }
    addLog('sys',`Importing from ${settings.platform} — ${settings.ctfName}...`,'bright');
    g('btn-import').disabled=true;
    try {
      const raw=await invoke('import_challenges',{
        platform:   buildPlatformConfig(),
        baseDir:    settings.baseDir,
        ctfName:    settings.ctfName,
        apiKey:     settings.apiKey,
        model:      settings.model==='custom' ? settings.modelCustom : settings.model,
        watchNewChallenges: !!settings.watchNewChallenges,
        watchIntervalSeconds: Number(settings.watchIntervalSeconds)||30,
        watchCycles: Number(settings.watchCycles)||0,
        autoQueuePolicy: settings.autoQueuePolicy!==false,
        autoStartSolveOnNew: !!settings.autoStartSolveOnNew,
        maxAutoStartsPerCycle: Number(settings.maxAutoStartsPerCycle)||1,
        singleActiveSolveLock: settings.singleActiveSolveLock!==false,
        singleActiveSolveLockTtlSeconds: Number(settings.singleActiveSolveLockTtlSeconds)||21600,
        autoSolveQueueSize: Number(settings.autoSolveQueueSize)||16,
        autoSolveQueueHeartbeatSeconds: Number(settings.autoSolveQueueHeartbeatSeconds)||15,
        autoSolveMaxRetries: Number(settings.autoSolveMaxRetries)||2,
        extraConfig: buildExtraConfig(),
        pythonPath: settings.pythonPath||'python3',
        solverPath: settings.solverPath,
      });
      if(!raw){ addLog('warn','Import returned empty.'); return; }
      const res = parseInvokeJson(raw, 'import_challenges');
      if(res.error){ addLog('err',`Import failed: ${res.error}`,'red'); return; }
      if(res.platform_token){ settings.platformToken=res.platform_token; persistSettings(); }
      const imported=res.challenges||[];
      addLog('ok',`Imported ${imported.length} challenges`,'white');
      imported.forEach(pc=>{
        if(challenges.find(c=>c.platform_id&&c.platform_id===pc.platform_id)) return;
        challenges.push({
          id:uid(), platform_id:pc.platform_id||'',
          name:pc.name, category:pc.category,
          description:pc.description||'', files:(pc.files||[]).join('\n'),
          instance:pc.instance||'', flagFormat:'',
          points:pc.points||0, difficulty:pc.difficulty||'medium',
          status:pc.solved?'solved':'staged', flag:null,
          workspace:pc.workspace||'', createdAt:Date.now(),
        });
      });
      renderList(); updateStats();
    } catch(e){ addLog('err',`Import error: ${e}`,'red'); }
    finally{ g('btn-import').disabled=false; }
  },

  // ── Settings open/close ─────────────────────────────────────────────────────
  openSettings() {
    // Populate all fields from settings
    sv('s-apikey',    settings.apiKey);
    sv('s-model',     settings.model);
    sv('s-model-custom', settings.modelCustom);
    sv('s-maxiter',   settings.maxIter);
    sv('s-maxtokens', settings.maxTokens);
    sv('s-concurrent',settings.concurrent);
    sc('s-auto-submit',   settings.autoSubmit);
    sc('s-auto-writeup',  settings.autoWriteup);
    sc('s-auto-workspace',settings.autoWorkspace);
    sc('s-retry-failed',  settings.retryFailed);
    sc('s-parallel-branches', settings.parallelBranches!==false);
    sv('s-maxretry',  settings.maxRetry);

    sv('s-python',    settings.pythonPath);
    sv('s-solver',    settings.solverPath);
    sv('s-wsl-distro',settings.wslDistro);
    sv('s-shell-timeout', settings.shellTimeout);
    sv('s-http-timeout',  settings.httpTimeout);
    sv('s-dl-timeout',    settings.dlTimeout);
    const t=settings.tools||{};
    sc('t-shell',t.shell); sc('t-python',t.python); sc('t-decode',t.decode);
    sc('t-http',t.http);   sc('t-file',t.file);     sc('t-workspace',t.workspace);
    sc('t-writefile',t.writefile); sc('t-download',t.download); sc('t-submit',t.submit);
    sc('t-flagformat', t.flagformat!==false);
    // Elite Intelligence Layer
    sc('t-knowledge', t.knowledge!==false);  sc('t-browser',  t.browser!==false);
    sc('t-ghidra',    t.ghidra!==false);     sc('t-airename', t.airename!==false);
    sc('t-libclookup',t.libclookup!==false); sc('t-factordb', t.factordb!==false);
    sc('t-angr',      t.angr!==false);       sc('t-sqlmap',   t.sqlmap!==false);
    sc('t-ffuf',      t.ffuf!==false);       sc('t-webcrawl', t.webcrawl!==false);
    sc('t-volatility',t.volatility!==false); sc('t-frida',    t.frida!==false);
    sc('t-rank',      t.rank!==false);       sc('t-recon',    t.recon!==false);
    sv('s-log-preview', settings.logPreview);
    sv('s-log-lines',   settings.maxLogLines);
    sv('s-verbosity',   settings.verbosity);

    sv('s-ctfname',   settings.ctfName);
    sv('s-platform',  settings.platform);
    sv('s-ctfurl',    settings.ctfUrl);
    sv('s-ctfuser',   settings.ctfUser);
    sv('s-ctfpass',   settings.ctfPass);
    sv('s-ctftoken',  settings.ctfToken);
    sv('s-basedir',   settings.baseDir);
    sv('s-writeup-name', settings.writeupName);
    sv('s-notes-name',   settings.notesName);
    sv('s-flag-patterns',settings.flagPatterns);

    sv('s-system-prompt',     settings.systemPrompt);
    sv('s-analysis-depth',    settings.analysisDepth);
    sv('s-pivot',             settings.pivot);
    sv('s-writeup-detail',    settings.writeupDetail);
    sv('s-writeup-style',     settings.writeupStyle);
    sv('s-extra-instructions',settings.extraInstructions);
    sv('s-hint-pwn',      settings.hintPwn);
    sv('s-hint-crypto',   settings.hintCrypto);
    sv('s-hint-web',      settings.hintWeb);
    sv('s-hint-forensics',settings.hintForensics);

    sv('s-panel-width', settings.panelWidth);
    sv('s-split',       settings.split);
    sv('s-font-size',   settings.fontSize);
    sv('s-line-height', settings.lineHeight);
    sv('s-font',        settings.font);
    sv('s-col-bg',      settings.colBg);     sv('s-col-bg-hex',     settings.colBg);
    sv('s-col-accent',  settings.colAccent); sv('s-col-accent-hex', settings.colAccent);
    sv('s-col-border',  settings.colBorder); sv('s-col-border-hex', settings.colBorder);
    sc('s-show-kb',       settings.showKb);
    sc('s-scanlines',     settings.scanlines);
    sc('s-blink-cursor',  settings.blinkCursor);
    sc('s-log-timestamps',settings.logTimestamps);
    sc('s-animate-log',   settings.animateLog);

    g('s-python-status').textContent='';
    syncModelInput();
    updatePlatformFields();
    g('settings-overlay').classList.add('open');
  },

  closeSettings() { g('settings-overlay').classList.remove('open'); },

  saveSettings() {
    const solverPathInput = gv('s-solver').trim();
    const solverValidation = validateSolverPath(solverPathInput);
    if (!solverValidation.ok) {
      setSolverPathStatus(`✗ ${solverValidation.message}`, false);
      addLog('err', `Settings not saved: ${solverValidation.message}`, 'red');
      g('s-solver')?.focus();
      return;
    }

    settings.apiKey       = gv('s-apikey').trim();
    settings.model        = gv('s-model');
    settings.modelCustom  = gv('s-model-custom').trim();
    settings.maxIter      = parseInt(gv('s-maxiter'))||20;
    settings.maxTokens    = parseInt(gv('s-maxtokens'))||4096;
    settings.concurrent   = parseInt(gv('s-concurrent'))||1;
    settings.autoSubmit   = gc('s-auto-submit');
    settings.autoWriteup  = gc('s-auto-writeup');
    settings.autoWorkspace= gc('s-auto-workspace');
    settings.retryFailed  = gc('s-retry-failed');
    settings.parallelBranches = gc('s-parallel-branches');
    settings.maxRetry     = parseInt(gv('s-maxretry'))||2;

    settings.pythonPath   = gv('s-python').trim()||'python3';
    settings.solverPath   = solverPathInput;
    settings.wslDistro    = gv('s-wsl-distro').trim();
    settings.shellTimeout = parseInt(gv('s-shell-timeout'))||30;
    settings.httpTimeout  = parseInt(gv('s-http-timeout'))||20;
    settings.dlTimeout    = parseInt(gv('s-dl-timeout'))||60;
    settings.tools = {
      shell:gc('t-shell'), python:gc('t-python'), decode:gc('t-decode'),
      http:gc('t-http'),   file:gc('t-file'),     workspace:gc('t-workspace'),
      writefile:gc('t-writefile'), download:gc('t-download'), submit:gc('t-submit'),
      flagformat:gc('t-flagformat'),
      // Elite Intelligence Layer
      knowledge:gc('t-knowledge'),   browser:gc('t-browser'),
      ghidra:gc('t-ghidra'),         airename:gc('t-airename'),
      libclookup:gc('t-libclookup'), factordb:gc('t-factordb'),
      angr:gc('t-angr'),             sqlmap:gc('t-sqlmap'),
      ffuf:gc('t-ffuf'),             webcrawl:gc('t-webcrawl'),
      volatility:gc('t-volatility'), frida:gc('t-frida'),
      rank:gc('t-rank'),             recon:gc('t-recon'),
    };
    settings.logPreview   = parseInt(gv('s-log-preview'))||400;
    settings.maxLogLines  = parseInt(gv('s-log-lines'))||2000;
    settings.verbosity    = gv('s-verbosity');

    settings.ctfName      = gv('s-ctfname').trim();
    settings.platform     = gv('s-platform');
    settings.ctfUrl       = gv('s-ctfurl').trim();
    settings.ctfUser      = gv('s-ctfuser').trim();
    settings.ctfPass      = gv('s-ctfpass');
    settings.ctfToken     = gv('s-ctftoken').trim();
    settings.baseDir      = gv('s-basedir').trim();
    settings.writeupName  = gv('s-writeup-name').trim()||'WRITEUP.md';
    settings.notesName    = gv('s-notes-name').trim()||'notes.txt';
    settings.flagPatterns = gv('s-flag-patterns').trim();

    settings.systemPrompt      = gv('s-system-prompt').trim();
    settings.analysisDepth     = gv('s-analysis-depth');
    settings.pivot             = gv('s-pivot');
    settings.writeupDetail     = gv('s-writeup-detail');
    settings.writeupStyle      = gv('s-writeup-style');
    settings.extraInstructions = gv('s-extra-instructions').trim();
    settings.hintPwn      = gv('s-hint-pwn').trim();
    settings.hintCrypto   = gv('s-hint-crypto').trim();
    settings.hintWeb      = gv('s-hint-web').trim();
    settings.hintForensics= gv('s-hint-forensics').trim();

    settings.panelWidth   = parseInt(gv('s-panel-width'))||360;
    settings.split        = gv('s-split')||'1fr 1fr';
    settings.fontSize     = parseFloat(gv('s-font-size'))||12;
    settings.lineHeight   = parseFloat(gv('s-line-height'))||1.6;
    settings.font         = gv('s-font');
    settings.colBg        = gv('s-col-bg');
    settings.colAccent    = gv('s-col-accent');
    settings.colBorder    = gv('s-col-border');
    settings.showKb       = gc('s-show-kb');
    settings.scanlines    = gc('s-scanlines');
    settings.blinkCursor  = gc('s-blink-cursor');
    settings.logTimestamps= gc('s-log-timestamps');
    settings.animateLog   = gc('s-animate-log');

    setSolverPathStatus(solverValidation.message, true);
    persistSettings(); applyAll(); App.closeSettings();
    addLog('sys','Settings saved and applied.','bright');
  },

  // Live UI preview (called from onchange in HTML)
  applyUISettings() {
    // Read current UI tab values and apply immediately for preview
    const fs  = parseFloat(gv('s-font-size'))||12;
    const lh  = parseFloat(gv('s-line-height'))||1.6;
    const pw  = parseInt(gv('s-panel-width'))||360;
    const sp  = gv('s-split')||'1fr 1fr';
    const fnt = gv('s-font');
    const bg  = gv('s-col-bg');
    const acc = gv('s-col-accent');
    const brd = gv('s-col-border');
    const r   = document.documentElement.style;
    if(fs)  r.setProperty('--fs',fs+'px');
    if(lh)  r.setProperty('--lh',String(lh));
    if(pw)  r.setProperty('--left-w',pw+'px');
    if(sp)  r.setProperty('--split',sp);
    if(fnt) r.setProperty('--font',fnt);
    if(bg)  r.setProperty('--bg-root',bg);
    if(acc) r.setProperty('--accent',acc);
    if(brd) r.setProperty('--border',brd);
    document.body.classList.toggle('scanlines',gc('s-scanlines'));
    document.querySelectorAll('.kb').forEach(el=>el.classList.toggle('hidden',!gc('s-show-kb')));
    document.getElementById('sb-cursor')?.classList.toggle('hidden',!gc('s-blink-cursor'));
  },

  resetColors() {
    sv('s-col-bg',    DEFAULTS.colBg);     sv('s-col-bg-hex',    DEFAULTS.colBg);
    sv('s-col-accent',DEFAULTS.colAccent); sv('s-col-accent-hex',DEFAULTS.colAccent);
    sv('s-col-border',DEFAULTS.colBorder); sv('s-col-border-hex',DEFAULTS.colBorder);
    App.applyUISettings();
  },

  resetSystemPrompt() {
    sv('s-system-prompt','');
    addLog('info','System prompt cleared — built-in prompt will be used.');
  },

  async testApiKey() {
    const key = gv('s-apikey').trim();
    const el  = g('s-apikey-status');
    if (!key) { el.textContent='Enter an API key first.'; return; }
    el.textContent='Testing...';
    try {
      // Minimal API call — 1 token, costs <$0.001
      const resp = await fetch('https://api.anthropic.com/v1/messages', {
        method:'POST',
        headers:{
          'Content-Type':'application/json',
          'x-api-key': key,
          'anthropic-version':'2023-06-01',
          'anthropic-dangerous-direct-browser-access':'true',
        },
        body: JSON.stringify({
          model:'claude-haiku-4-5-20251001', max_tokens:5,
          messages:[{role:'user',content:'hi'}]
        })
      });
      if(resp.ok) {
        el.textContent='✓ API key valid and working.';
        el.style.color='var(--text-mid)';
      } else {
        const d=await resp.json();
        el.textContent=`✗ ${d.error?.message||resp.statusText}`;
        el.style.color='#666';
      }
    } catch(e) {
      el.textContent=`✗ ${e}`;
      el.style.color='#666';
    }
  },

  async checkPython() {
    const path=gv('s-python').trim()||'python3';
    const el=g('s-python-status');
    el.textContent='checking...';
    try {
      const ver=await invoke('check_python',{pythonPath:path});
      el.textContent=`✓ ${ver}`; el.style.color='var(--text-mid)';
    } catch(e) {
      el.textContent=`✗ ${e}`; el.style.color='#666';
    }
  },

  async detectPython() {
    const candidates=['python3','python','python3.11','python3.10','python3.9'];
    const el=g('s-python-status');
    el.textContent='detecting...';
    for(const p of candidates) {
      try {
        const ver=await invoke('check_python',{pythonPath:p});
        sv('s-python',p);
        el.textContent=`✓ Found: ${ver}`; el.style.color='var(--text-mid)';
        return;
      } catch(_) {}
    }
    el.textContent='No Python found. Install Python 3 and set path manually.';
    el.style.color='#666';
  },

  async autoDetectSolver() {
    const el=g('s-solver-status');
    el.textContent='detecting...';
    try {
      const dir=await invoke('get_bin_dir');
      if(!dir) throw new Error('No bin dir');
      const sep=dir.includes('/')? '/' : '\\';
      const guesses=[
        dir+sep+'..'+sep+'..'+sep+'..'+sep+'sidecar'+sep+'solver.py',
        dir+sep+'..'+sep+'..'+sep+'sidecar'+sep+'solver.py',
        dir+sep+'sidecar'+sep+'solver.py',
        dir+sep+'..'+sep+'sidecar'+sep+'solver.py',
      ];
      // Use first guess — can't stat from Tauri easily, just suggest
      sv('s-solver', guesses[0]);
      const status = validateSolverPath(guesses[0]);
      el.textContent = status.ok
        ? `Suggested: ${guesses[0]} (verify file exists)`
        : `Suggested path format warning: ${status.message}`;
    } catch(e) {
      el.textContent=`Could not auto-detect: ${e}`;
    }
  },

  // ── Export / Import settings ─────────────────────────────────────────────────
  exportSettings() {
    const json=JSON.stringify(settings, null, 2);
    const blob=new Blob([json],{type:'application/json'});
    const url=URL.createObjectURL(blob);
    const a=document.createElement('a');
    a.href=url; a.download='ctf-solver-settings.json'; a.click();
    URL.revokeObjectURL(url);
    addLog('sys','Settings exported to ctf-solver-settings.json');
  },

  importSettingsFile() { g('settings-file-input').click(); },

  loadSettingsFile(input) {
    const file=input.files[0]; if(!file) return;
    const reader=new FileReader();
    reader.onload=e=>{
      try {
        const loaded=JSON.parse(e.target.result);
        settings=Object.assign(deepClone(DEFAULTS), loaded);
        persistSettings(); applyAll(); App.openSettings();
        addLog('ok','Settings imported successfully.','white');
      } catch(err) {
        addLog('err',`Failed to import settings: ${err}`,'red');
      }
    };
    reader.readAsText(file);
    input.value='';
  },

  resetAllSettings() {
    if(!confirm('Reset ALL settings to defaults? This cannot be undone.')) return;
    settings=deepClone(DEFAULTS);
    persistSettings(); applyAll(); App.openSettings();
    addLog('sys','All settings reset to defaults.');
  },

  // ── Connect modal ───────────────────────────────────────────────────────────

  openConnectModal() {
    // Pre-fill from existing settings
    if (settings.ctfUrl)  sv('conn-url', settings.ctfUrl);
    if (settings.ctfUser) sv('conn-user', settings.ctfUser);
    if (settings.ctfPass) sv('conn-pass', settings.ctfPass);
    if (settings.ctfToken)sv('conn-token', settings.ctfToken);
    if (settings.ctfName) sv('conn-ctf-name', settings.ctfName);
    if (settings.baseDir) sv('conn-basedir', settings.baseDir);

    const url = settings.ctfUrl || '';
    if (url) App.detectPlatformFromUrl(url);

    showConnStep(1);
    document.getElementById('conn-log').style.display = 'none';
    document.getElementById('conn-log-body').innerHTML = '';
    clearConnError();
    g('connect-overlay').classList.add('open');
    setTimeout(()=>g('conn-url')?.focus(), 50);
  },

  closeConnectModal() {
    g('connect-overlay').classList.remove('open');
  },

  detectPlatformFromUrl(url) {
    if (!url.trim()) {
      document.querySelectorAll('.platform-card').forEach(c=>c.classList.remove('selected'));
      document.getElementById('conn-detected-badge').style.display='none';
      g('conn-url-hint').textContent='Paste the CTF site URL — platform auto-detected';
      connectState.platform = '';
      return;
    }
    const detected = detectPlatform(url.trim());
    if (detected) {
      connectState.platform = detected.type;
      connectState.url      = detected.url || url.trim();

      // Update cards
      document.querySelectorAll('.platform-card').forEach(c=>c.classList.remove('selected'));
      const card = document.getElementById(`pc-${detected.type}`);
      if (card) card.classList.add('selected');

      // Badge
      const badge = document.getElementById('conn-detected-badge');
      badge.textContent = detected.label;
      badge.style.display = '';

      g('conn-url-hint').textContent = `✓ Detected: ${detected.label}`;
    } else {
      connectState.platform = '';
      g('conn-url-hint').textContent = 'Could not detect platform — select manually below';
    }
  },

  selectPlatform(type, url) {
    connectState.platform = type;
    if (url) { connectState.url = url; sv('conn-url', url); }
    document.querySelectorAll('.platform-card').forEach(c=>c.classList.remove('selected'));
    document.getElementById(`pc-${type}`)?.classList.add('selected');
    const badge = document.getElementById('conn-detected-badge');
    badge.textContent = type.toUpperCase();
    badge.style.display = '';
  },

  connectStep2() {
    const url = gv('conn-url').trim();
    if (!url && connectState.platform !== 'manual') {
      setConnError('Enter the CTF site URL or select a platform.'); return;
    }
    if (!connectState.platform) {
      // Try to detect one more time
      App.detectPlatformFromUrl(url);
      if (!connectState.platform) {
        connectState.platform = 'ctfd'; // default assumption
      }
    }
    connectState.url = url || connectState.url;
    showCredsFor(connectState.platform);
    showConnStep(2);

    // Auto-advance for manual
    if (connectState.platform === 'manual') App.connectStep3();
  },

  connectStep3() {
    // Validate creds
    const platform = connectState.platform;
    if (platform === 'htb') {
      if (!gv('conn-htb-token').trim()) {
        setConnError('HTB API token is required.'); return;
      }
    } else if (platform !== 'manual') {
      const hasCredentials = gv('conn-user').trim() || gv('conn-token').trim();
      if (!hasCredentials) {
        setConnError('Enter username/password or an API token.'); return;
      }
    }

    // Pre-fill CTF name from URL
    if (!gv('conn-ctf-name').trim()) {
      try {
        const host = new URL(connectState.url).hostname.replace('www.','').replace('play.','');
        const name = host.split('.')[0];
        sv('conn-ctf-name', name.charAt(0).toUpperCase()+name.slice(1)+' '+new Date().getFullYear());
      } catch(_) {}
    }
    sv('conn-year', gv('conn-year') || String(new Date().getFullYear()));
    showConnStep(3);
  },

  connectBack() {
    if (connectState.step === 3) showConnStep(2);
    else if (connectState.step === 2) showConnStep(1);
  },

  async connectAndImport() {
    const ctfName = gv('conn-ctf-name').trim();
    const baseDir = gv('conn-basedir').trim();

    if (!ctfName) { setConnError('Enter a CTF name.'); return; }
    if (!baseDir) { setConnError('Enter a working directory path.'); return; }
    if (!settings.apiKey)    { setConnError('No API key set — go to Settings → API & Engine first.'); return; }
    if (!settings.solverPath){ setConnError('No solver script path — go to Settings → Python & Tools.'); return; }

    // Build credentials
    const platform = connectState.platform;
    const url      = connectState.url || gv('conn-url').trim();
    const user     = gv('conn-user').trim();
    const pass     = gv('conn-pass');
    const token    = platform === 'htb' ? gv('conn-htb-token').trim() : gv('conn-token').trim();

    // Save to settings
    settings.platform  = platform;
    settings.ctfUrl    = url;
    settings.ctfUser   = user;
    settings.ctfPass   = pass;
    settings.ctfToken  = token;
    settings.ctfName   = ctfName;
    settings.baseDir   = baseDir;
    persistSettings();
    applyAll();

    // Show log
    document.getElementById('conn-log').style.display = '';
    document.getElementById('conn-log-body').innerHTML = '';
    setConnProgress('Connecting...');
    clearConnError();

    // Disable actions during connect
    g('conn-btn-connect').disabled = true;
    g('conn-btn-back').disabled    = true;

    clog('sys', `Platform: ${platform.toUpperCase()} — ${url}`, 'bright');
    clog('sys', `CTF: ${ctfName}`, 'bright');
    clog('sys', `Working directory: ${baseDir}`, '');

    try {
      const platformConfig = { type:platform, url, username:user, password:pass, token };
      const raw = await invoke('import_challenges', {
        platform:   platformConfig,
        baseDir,
        ctfName,
        pythonPath: settings.pythonPath || 'python3',
        solverPath: settings.solverPath,
      });

      if (!raw) throw new Error('Empty response from solver');

      const res = JSON.parse(raw);

      if (res.error) {
        clog('err', res.error, 'red');
        setConnError(`Connection failed: ${res.error}`);
        setConnProgress('');
        return;
      }

      // Cache platform token
      if (res.platform_token) {
        settings.platformToken = res.platform_token;
        persistSettings();
      }

      const imported = res.challenges || [];
      clog('ok', `Connected! ${imported.length} challenges fetched.`, 'white');

      // Import challenges
      let added = 0;
      imported.forEach(pc => {
        if (challenges.find(c=>c.platform_id&&c.platform_id===pc.platform_id)) return;
        challenges.push({
          id:uid(), platform_id:pc.platform_id||'',
          name:pc.name, category:pc.category,
          description:pc.description||'', files:(pc.files||[]).join('\n'),
          instance:pc.instance||'', flagFormat:'',
          points:pc.points||0, difficulty:pc.difficulty||'medium',
          status:pc.solved?'solved':'staged', flag:null,
          workspace:pc.workspace||'', createdAt:Date.now(),
        });
        added++;
      });

      renderList(); updateStats();

      // Log per-category counts
      const byCat = {};
      imported.forEach(c => { byCat[c.category] = (byCat[c.category]||0)+1; });
      Object.entries(byCat).sort((a,b)=>b[1]-a[1]).forEach(([cat,n]) => {
        clog('info', `  ${cat}: ${n} challenge${n>1?'s':''}`, '');
      });

      for (const err of (res.errors||[])) clog('warn', err, '');

      // Update platform bar
      const statusEl = document.getElementById('pb-conn-status');
      statusEl.textContent = `✓ connected`;
      statusEl.className = 'connected';
      g('btn-connect').textContent    = '✓ RECONNECT';
      g('btn-disconnect').style.display = '';
      g('btn-import').style.display     = '';
      g('btn-open-folder').style.display = baseDir ? '' : 'none';

      setConnProgress('');
      clog('sys', `Done. ${added} new challenge${added!==1?'s':''} added.`, 'bright');

      addLog('ok', `Connected to ${ctfName} — ${added} challenges imported`, 'white');
      addLog('sys', `Working directory: ${baseDir}`, '');
      addLog('info', 'Select a challenge and press S to solve, or press A to solve all.');

      // Close after 1.5s
      setTimeout(()=>App.closeConnectModal(), 1500);

    } catch(e) {
      clog('err', String(e), 'red');
      setConnError(`Error: ${e}`);
      setConnProgress('');
    } finally {
      g('conn-btn-connect').disabled = false;
      g('conn-btn-back').disabled    = false;
    }
  },

  disconnect() {
    settings.platform      = 'manual';
    settings.ctfUrl        = '';
    settings.ctfUser       = '';
    settings.ctfPass       = '';
    settings.ctfToken      = '';
    settings.platformToken = '';
    persistSettings(); applyAll();
    const statusEl = document.getElementById('pb-conn-status');
    statusEl.textContent = '';
    statusEl.className = '';
    g('btn-connect').textContent      = '⚡ CONNECT TO CTF';
    g('btn-disconnect').style.display = 'none';
    g('btn-import').style.display     = 'none';
    addLog('sys', 'Disconnected from platform.');
  },

  // ── Keyboard navigation ──────────────────────────────────────────────────────
  navigateList(dir) {
    const s=sortedChallenges(); if(!s.length) return;
    const i=s.findIndex(c=>c.id===selectedId);
    const next=i===-1?s[0]:dir===-1?s[Math.max(0,i-1)]:s[Math.min(s.length-1,i+1)];
    if(next) App.select(next.id);
  },
};

// ─── Connect modal state ─────────────────────────────────────────────────────
let connectState = {
  step:     1,   // 1=url, 2=creds, 3=details
  platform: '',
  url:      '',
};

// Platform detection from URL
const PLATFORM_SIGNATURES = [
  { match: /picoctf\.org/i,      type: 'picoctf', url: 'https://play.picoctf.org',       label: 'picoCTF' },
  { match: /hackthebox\.com/i,   type: 'htb',     url: 'https://www.hackthebox.com',     label: 'HackTheBox' },
  { match: /hackthebox\.eu/i,    type: 'htb',     url: 'https://www.hackthebox.eu',      label: 'HackTheBox' },
  { match: /tryhackme\.com/i,    type: 'ctfd',    url: 'https://tryhackme.com',          label: 'TryHackMe (CTFd)' },
  { match: /ctfd\./i,            type: 'ctfd',    url: '',                               label: 'CTFd' },
];

function detectPlatform(url) {
  for (const sig of PLATFORM_SIGNATURES) {
    if (sig.match.test(url)) return sig;
  }
  // Heuristic: if it looks like a URL at all, assume CTFd
  if (/^https?:\/\/.+/.test(url)) {
    return { type: 'ctfd', url, label: 'CTFd (auto-detected)' };
  }
  return null;
}

function clog(tag, msg, cls='') {
  const el = document.getElementById('conn-log-body');
  if (!el) return;
  const d = document.createElement('div');
  d.className = 'clog-line';
  d.innerHTML = `<span class="clog-tag ${tag}">[${tag.toUpperCase()}]</span><span class="clog-msg ${cls}">${esc(msg)}</span>`;
  el.appendChild(d);
  el.scrollTop = el.scrollHeight;
}

function showConnStep(step) {
  connectState.step = step;
  document.getElementById('conn-step-url').style.display    = step===1 ? '' : 'none';
  document.getElementById('conn-step-creds').style.display  = step===2 ? '' : 'none';
  document.getElementById('conn-step-details').style.display= step===3 ? '' : 'none';
  document.getElementById('conn-btn-back').style.display    = step > 1 ? '' : 'none';
  document.getElementById('conn-btn-next').style.display    = step < 3 ? '' : 'none';
  document.getElementById('conn-btn-connect').style.display = step===3 ? '' : 'none';
  clearConnError();
}

function setConnProgress(msg) {
  document.getElementById('conn-progress').style.display = msg ? '' : 'none';
  document.getElementById('conn-progress-msg').textContent = msg || '';
}

function setConnError(msg) {
  const el = document.getElementById('conn-error');
  el.style.display = msg ? '' : 'none';
  el.textContent = msg || '';
}

function clearConnError() { setConnError(''); setConnProgress(''); }

function showCredsFor(platform) {
  document.getElementById('conn-creds-picoctf').style.display = ['picoctf','ctfd'].includes(platform) ? '' : 'none';
  document.getElementById('conn-creds-htb').style.display     = platform==='htb' ? '' : 'none';
  document.getElementById('conn-creds-manual').style.display  = platform==='manual' ? '' : 'none';
}

// ─── Tauri events ─────────────────────────────────────────────────────────────
listen('solver-log', event => {
  const e=event.payload??{};
  if(e.type==='log'&&e.tag&&e.msg!==undefined) {
    addLog(e.tag, e.msg, e.cls||'');

  } else if(e.type==='error') {
    addLog('err', e.message || e.msg || 'Sidecar error', 'red');

  } else if(e.type==='solve_start') {
    // Budget/iteration count now displayed from solver
    const ibEl=g('pb-iter');
    if(ibEl) ibEl.textContent=`0/${e.budget||'auto'}`;
    addLog('sys',`[ENGINE] Budget: ${e.budget||'auto'} iters | Tools: ${e.tools||'?'}`, 'dim');

  } else if(e.type==='model_switch') {
    // Live model + reasoning indicator in platform bar
    const shortModel = (e.model||'').includes('opus') ? 'opus' :
                       (e.model||'').includes('sonnet') ? 'sonnet' :
                       (e.model||'').includes('haiku') ? 'haiku' : e.model||'?';
    _currentModel   = shortModel;
    _currentThinking= !!e.thinking;
    const mEl=g('pb-model');
    if(mEl){
      mEl.textContent = shortModel + (e.thinking ? '+think' : '');
      mEl.style.color = e.thinking ? 'var(--accent)' : '';
    }
    const rEl=g('pb-reasoning');
    if(rEl){
      rEl.textContent = e.thinking ? `${(e.thinking_tokens||0)/1000}k` : 'off';
      rEl.style.color = e.thinking ? 'var(--accent)' : 'var(--text-dim)';
    }
    const ibEl=g('pb-iter');
    if(ibEl) ibEl.textContent=`${e.iteration||0}/${e.budget||'?'}`;
    _currentIter = e.iteration||0;

  } else if(e.type==='tool_call') {
    // Pulse the solving indicator with tool name
    const ind=document.getElementById('solving-indicator');
    if(ind){
      const toolSpan=ind.querySelector('span:last-child');
      if(toolSpan) toolSpan.textContent=` ${e.tool||''}...`;
    }

  } else if(e.type==='solve_stats') {
    // Final stats after solve
    const c=ch(selectedId);
    if(c){
      c.runtime   = e.elapsed;
      c.solveIter = e.iterations;
      c.solveModel= e.model;
      renderDetails();
    }

  } else if(e.type==='workspace'&&e.path) {
    const c=ch(selectedId);
    if(c){ c.workspace=e.path; renderDetails(); }
    addLog('sys',`Workspace: ${e.path}`,'');
    const btn=g('btn-open-ws'); if(btn) btn.style.display='';

  } else if(e.type==='flag_format'&&e.prefix) {
    const el=g('pb-flagfmt');
    if(el){
      el.textContent=e.prefix+'{...}';
      el.title=`Source: ${e.source||'?'} | Confidence: ${e.confidence||'?'}`;
      const conf=e.confidence||'';
      el.style.color = conf==='confirmed' ? 'var(--accent)'
                     : conf==='high'      ? 'var(--text-bright)'
                     :                      'var(--text-mid)';
    }
    const confLabel = e.confidence==='confirmed' ? '✓' : e.confidence==='high' ? 'high' : e.confidence||'?';
    addLog('sys',`[FMT] ${e.prefix}{...} (${confLabel} | ${e.source||'?'})`,'dim');

  } else if(e.type==='knowledge') {
    addLog('sys',`[KG] ${e.ctf||''} → ${e.key}: ${(e.value||'').slice(0,80)}`,'dim');

  } else if(e.type==='writeup'&&e.path) {
    addLog('ok',`📝 Writeup: ${e.path}`,'white');
  }
});

// ─── Keyboard shortcuts ───────────────────────────────────────────────────────
document.addEventListener('keydown', e => {
  const tag=e.target.tagName;
  if(tag==='INPUT'||tag==='TEXTAREA'||tag==='SELECT') return;
  switch(e.key) {
    case 'n': case 'N': App.openModal();       break;
    case 's': case 'S': App.solveSelected();   break;
    case 'a': case 'A': App.solveAll();        break;
    case 'x': case 'X': App.cancelSolve();    break;
    case 'Delete': case 'Backspace': App.removeSelected(); break;
    case 'Escape': App.closeModal(); App.closeSettings(); App.closeConnectModal(); break;
    case 'ArrowUp':   App.navigateList(-1); e.preventDefault(); break;
    case 'ArrowDown': App.navigateList( 1); e.preventDefault(); break;
  }
});

g('btn-settings').addEventListener('click', ()=>App.openSettings());

// ─── Init ─────────────────────────────────────────────────────────────────────
(function init() {
  loadSettings();
  applyAll();

  if(!settings.solverPath) {
    invoke('get_bin_dir').then(dir=>{
      if(!dir) return;
      const sep=dir.includes('/')?'/':'\\';
      addLog('info',`Solver not set. Try: ${dir}${sep}..${sep}..${sep}sidecar${sep}solver.py`);
    }).catch(()=>{});
  }

  renderList(); renderDetails(); updateStats();
  addLog('sys','CTF::SOLVER initialized.','bright');
  addLog('info',`Engine: ${activeModel()} | Iterations: ${settings.maxIter} | Tools: ${countEnabledTools()}`);
  if(!settings.apiKey)    addLog('warn','⚠ No API key — Settings → API & Engine (console.anthropic.com for key)');
  if(!settings.solverPath)addLog('warn','⚠ Solver script not set — Settings → Python & Tools');
  if(!settings.baseDir)   addLog('info','Tip: Click ⚡ CONNECT TO CTF to log into your competition and import challenges automatically');
  addLog('info','Shortcuts: N=new  S=solve  A=solve-all  X=cancel  Del=remove  ↑↓=navigate');

  // Restore connected state if we have saved credentials
  if (settings.ctfName && settings.platform !== 'manual') {
    const statusEl = document.getElementById('pb-conn-status');
    statusEl.textContent = '✓ connected';
    statusEl.className = 'connected';
    g('btn-connect').textContent      = '✓ RECONNECT';
    g('btn-disconnect').style.display = '';
    g('btn-import').style.display     = '';
    if (settings.baseDir) g('btn-open-folder').style.display = '';
    addLog('sys', `Restored connection: ${settings.ctfName} (${settings.platform})`, '');
  }

  const modalFiles = g('m-files');
  if (modalFiles) {
    const prevent = (e) => { e.preventDefault(); e.stopPropagation(); };
    ['dragenter', 'dragover'].forEach((evt) => {
      modalFiles.addEventListener(evt, (e) => {
        prevent(e);
        modalFiles.classList.add('is-drop');
      });
    });
    ['dragleave', 'dragend', 'drop'].forEach((evt) => {
      modalFiles.addEventListener(evt, () => modalFiles.classList.remove('is-drop'));
    });
    modalFiles.addEventListener('drop', (e) => {
      prevent(e);
      const files = extractDroppedFiles(e);
      if (files.length) App.loadSourceFiles(files);
    });

    const modal = g('modal');
    if (modal) {
      ['dragenter', 'dragover', 'drop'].forEach((evt) => {
        modal.addEventListener(evt, prevent);
      });
      modal.addEventListener('drop', (e) => {
        const files = extractDroppedFiles(e);
        if (files.length) App.loadSourceFiles(files);
      });
    }

    ['dragenter', 'dragover', 'drop'].forEach((evt) => {
      window.addEventListener(evt, (e) => {
        if (g('modal-overlay')?.classList.contains('open')) {
          e.preventDefault();
        }
      });
    });
  }

  const solverInput = g('s-solver');
  if (solverInput) {
    solverInput.addEventListener('input', () => {
      const status = validateSolverPath(gv('s-solver'));
      setSolverPathStatus(status.ok ? status.message : `✗ ${status.message}`, status.ok);
    });
  }
})();
