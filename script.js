/* ==========================================================================
 * VAULTBOOK v2.0
 * A private, offline-first encrypted notebook.
 *
 * Sections:
 *   1.  Constants & element refs
 *   2.  State
 *   3.  Utilities (base64, uid, toast, format)
 *   4.  Screen navigation
 *   5.  Theme
 *   6.  Password strength
 *   7.  Crypto core (AES-256-GCM + PBKDF2)
 *   8.  File format (build/parse .vbk and legacy .rna import)
 *   9.  Editor: text, stats, autosave
 *   10. Editor: drawing engine
 *   11. Editor: images
 *   12. Panic Lock
 *   13. Save (encrypt & download)
 *   14. Unlock flow
 *   15. Export (PDF, TXT)
 *   16. Keyboard shortcuts
 *   17. Init
 * ========================================================================== */

'use strict';

/* ------------------------------------------------------------------ *
 * 1. CONSTANTS & ELEMENT REFS                                         *
 * ------------------------------------------------------------------ */
const FORMAT_ID     = 'VAULTBOOK';
const FORMAT_VER    = 2;
const SIGNATURE     = 'VAULTBOOK_V2::';
const LEGACY_ID     = 'RNA';
const LEGACY_VER    = 1;
const LEGACY_SIG    = 'RNA_NOTEBOOK_V1::';
const PBKDF2_ITERS  = 250_000;
const SALT_BYTES    = 16;
const IV_BYTES      = 12;
const KEY_BITS      = 256;
const HASH_ALG      = 'SHA-256';
const CANVAS_W      = 1000;
const CANVAS_H      = 700;
const UNDO_LIMIT    = 40;
const AUTOSAVE_MS   = 800;

const $  = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

const el = {
  // screens
  screenHome:     $('#screenHome'),
  screenPassword: $('#screenPassword'),
  screenOpen:     $('#screenOpen'),
  screenEditor:   $('#screenEditor'),
  // home
  btnNew:         $('#btnNewVaultbook'),
  btnOpen:        $('#btnOpenVaultbook'),
  // password setup
  pwSetupForm:    $('#pwSetupForm'),
  pwNew:          $('#pwNew'),
  pwConfirm:      $('#pwConfirm'),
  pwStrength:     $('#pwStrength'),
  pwMatchHint:    $('#pwMatchHint'),
  pwSetupStatus:  $('#pwSetupStatus'),
  // open
  dropzone:       $('#dropzone'),
  fileInput:      $('#fileInput'),
  btnBrowseFile:  $('#btnBrowseFile'),
  dzFilename:     $('#dropzoneFilename'),
  unlockForm:     $('#unlockForm'),
  unlockPassword: $('#unlockPassword'),
  unlockStatus:   $('#unlockStatus'),
  // editor
  editorTitle:    $('#editorTitle'),
  editorBody:     $('#editorBody'),
  tabWrite:       $('#tabWrite'),
  tabDraw:        $('#tabDraw'),
  modeWrite:      $('#modeWrite'),
  modeDraw:       $('#modeDraw'),
  saveIndicator:  $('#saveIndicator'),
  btnSave:        $('#btnSave'),
  btnPanic:       $('#btnPanic'),
  btnEditorHome:  $('#btnEditorHome'),
  btnAddImage:    $('#btnAddImage'),
  imageInput:     $('#imageInput'),
  btnExportMenu:  $('#btnExportMenu'),
  exportMenu:     $('#exportMenu'),
  imagesSection:  $('#imagesSection'),
  imagesGrid:     $('#imagesGrid'),
  importNotice:   $('#importNoticeCard'),
  // stats
  statWords:      $('#statWords'),
  statChars:      $('#statChars'),
  statRead:       $('#statRead'),
  // drawing
  drawCanvas:     $('#drawCanvas'),
  brushSize:      $('#brushSize'),
  sizeLabel:      $('#sizeLabel'),
  customColor:    $('#customColor'),
  btnUndo:        $('#btnUndo'),
  btnRedo:        $('#btnRedo'),
  btnClearCanvas: $('#btnClearCanvas'),
  // panic
  panicOverlay:   $('#panicOverlay'),
  panicForm:      $('#panicUnlockForm'),
  panicPassword:  $('#panicPassword'),
  panicStatus:    $('#panicStatus'),
  btnPanicDiscard:$('#btnPanicDiscard'),
  // modal
  imageModal:     $('#imageModal'),
  modalImg:       $('#modalImg'),
  btnRemoveImage: $('#btnRemoveImage'),
  // theme
  themeToggle:    $('#themeToggle'),
  // toast
  toast:          $('#toast'),
};

/* ------------------------------------------------------------------ *
 * 2. STATE                                                            *
 *    Everything sensitive lives here and only here. On Panic Lock or  *
 *    return-to-home we wipe fields we no longer need.                 *
 * ------------------------------------------------------------------ */
const state = {
  currentScreen: 'home',

  // Held ONLY while the notebook is unlocked in this session. Never
  // written to localStorage / IndexedDB / DOM.
  password: null,

  // Current notebook document (see makeEmptyNotebook()).
  notebook: null,

  // For the unlock flow.
  pendingFile: null,         // Uint8Array of the uploaded file
  pendingFileName: null,
  pendingFormat: null,       // 'VAULTBOOK' | 'RNA'
  isImportedLegacy: false,

  // Panic-lock buffer: while non-null, editor is hidden and only
  // this + the correct password can restore the notebook.
  panicVault: null,          // { salt, iv, ciphertext } — all Uint8Arrays

  // Autosave / dirty tracking.
  dirty: false,
  autosaveTimer: null,

  drawing: {
    ctx: null,
    tool: 'brush',
    color: '#1e1c17',
    size: 3,
    isDrawing: false,
    lastX: 0,
    lastY: 0,
    undoStack: [],           // dataURLs
    redoStack: [],
    dirty: false,            // has the canvas been modified since last sync into state.notebook
  },
};

function makeEmptyNotebook() {
  const now = new Date().toISOString();
  return {
    title: '',
    body: '',
    drawing: null,           // dataURL PNG or null
    images: [],              // [{ id, name, dataURL }]
    createdAt: now,
    updatedAt: now,
  };
}

/* ------------------------------------------------------------------ *
 * 3. UTILITIES                                                        *
 * ------------------------------------------------------------------ */
function bytesToB64(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s);
}
function b64ToBytes(b64) {
  const s = atob(b64);
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}
const textEnc = new TextEncoder();
const textDec = new TextDecoder();

function randomBytes(n) {
  const b = new Uint8Array(n);
  crypto.getRandomValues(b);
  return b;
}
function uid() {
  return 'i_' + Math.random().toString(36).slice(2, 10) + Date.now().toString(36);
}

let toastTimer = null;
function toast(msg, kind = 'default') {
  el.toast.textContent = msg;
  el.toast.style.background = kind === 'error'
    ? 'var(--warn)'
    : kind === 'success'
      ? 'var(--success)'
      : 'var(--ink)';
  el.toast.style.color = kind === 'default' ? 'var(--paper)' : 'white';
  el.toast.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { el.toast.hidden = true; }, 2600);
}

function sanitizeFilename(name) {
  const base = (name || 'Untitled').trim().slice(0, 60)
    .replace(/[\\/:*?"<>|]+/g, '_')
    .replace(/\s+/g, ' ');
  return base || 'Untitled';
}

function downloadBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = filename; a.rel = 'noopener';
  document.body.appendChild(a);
  a.click();
  a.remove();
  // Revoke shortly after — some browsers need a tick.
  setTimeout(() => URL.revokeObjectURL(url), 500);
}

/* ------------------------------------------------------------------ *
 * 4. SCREEN NAVIGATION                                                *
 * ------------------------------------------------------------------ */
function showScreen(name) {
  const map = {
    home:     el.screenHome,
    password: el.screenPassword,
    open:     el.screenOpen,
    editor:   el.screenEditor,
  };
  Object.values(map).forEach(s => s.classList.remove('is-active'));
  const target = map[name];
  if (target) target.classList.add('is-active');
  state.currentScreen = name;
  // scroll top on transitions
  window.scrollTo({ top: 0, behavior: 'instant' });
}

function goHome({ confirmIfDirty = true } = {}) {
  if (confirmIfDirty && state.dirty && state.notebook) {
    if (!confirm('You have unsaved changes. Return to home and lose them?')) return;
  }
  wipeSession();
  resetOpenScreen();
  showScreen('home');
}

/**
 * Wipes any sensitive session state and clears editor DOM.
 * Called when returning to home, or discarding a panic-locked notebook.
 */
function wipeSession() {
  state.password = null;
  state.notebook = null;
  state.pendingFile = null;
  state.pendingFileName = null;
  state.pendingFormat = null;
  state.isImportedLegacy = false;
  state.panicVault = null;
  state.dirty = false;
  clearTimeout(state.autosaveTimer);

  // clear editor DOM
  el.editorTitle.value = '';
  el.editorBody.value  = '';
  el.imagesGrid.innerHTML = '';
  el.imagesSection.hidden = true;
  el.importNotice.hidden = true;
  if (state.drawing.ctx) clearCanvas(true);
  state.drawing.undoStack = [];
  state.drawing.redoStack = [];
  state.drawing.dirty = false;
  refreshStats();
  updateSaveIndicator();
}

function resetOpenScreen() {
  el.fileInput.value = '';
  el.dzFilename.textContent = '';
  el.unlockPassword.value = '';
  el.unlockStatus.textContent = '';
  el.unlockStatus.className = 'status-line';
  el.unlockForm.hidden = true;
}

/* ------------------------------------------------------------------ *
 * 5. THEME                                                            *
 * ------------------------------------------------------------------ */
function applyTheme(theme) {
  document.documentElement.setAttribute('data-theme', theme);
  try { localStorage.setItem('vaultbook.theme', theme); } catch (_) {}
  const meta = document.querySelector('meta[name="theme-color"]');
  if (meta) meta.setAttribute('content', theme === 'dark' ? '#131316' : '#efece5');
}
function initTheme() {
  let saved;
  try { saved = localStorage.getItem('vaultbook.theme'); } catch (_) {}
  if (!saved) {
    saved = window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  }
  applyTheme(saved);
}
function toggleTheme() {
  const cur = document.documentElement.getAttribute('data-theme') || 'light';
  applyTheme(cur === 'dark' ? 'light' : 'dark');
}

/* ------------------------------------------------------------------ *
 * 6. PASSWORD STRENGTH                                                *
 *    Simple entropy-inspired estimate. Not authoritative.             *
 * ------------------------------------------------------------------ */
function scorePassword(pw) {
  if (!pw) return { level: 'none', label: 'Enter a password' };
  let cats = 0;
  if (/[a-z]/.test(pw)) cats++;
  if (/[A-Z]/.test(pw)) cats++;
  if (/[0-9]/.test(pw)) cats++;
  if (/[^A-Za-z0-9]/.test(pw)) cats++;
  const len = pw.length;
  // rough scoring
  if (len < 6)  return { level: 'weak',   label: 'Weak — too short' };
  if (len < 10 && cats < 3) return { level: 'weak', label: 'Weak' };
  if (len < 12 && cats < 3) return { level: 'fair', label: 'Fair' };
  if (len >= 12 && cats >= 3) return { level: 'strong', label: 'Strong' };
  if (len >= 16) return { level: 'strong', label: 'Strong' };
  return { level: 'good', label: 'Good' };
}
function updateStrength() {
  const s = scorePassword(el.pwNew.value);
  el.pwStrength.className = 'pw-strength is-' + s.level;
  el.pwStrength.querySelector('.pw-strength-label').textContent = s.label;
}
function updateMatchHint() {
  const a = el.pwNew.value, b = el.pwConfirm.value;
  if (!b) { el.pwMatchHint.textContent = ''; el.pwMatchHint.className = 'field-hint'; return; }
  if (a === b) { el.pwMatchHint.textContent = 'Passwords match'; el.pwMatchHint.className = 'field-hint is-success'; }
  else         { el.pwMatchHint.textContent = 'Passwords do not match'; el.pwMatchHint.className = 'field-hint is-error'; }
}

/* ------------------------------------------------------------------ *
 * 7. CRYPTO CORE                                                      *
 *    Uses Web Crypto API only. No custom algorithms.                  *
 * ------------------------------------------------------------------ */
async function deriveKey(password, salt) {
  const baseKey = await crypto.subtle.importKey(
    'raw', textEnc.encode(password), 'PBKDF2', false, ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: PBKDF2_ITERS, hash: HASH_ALG },
    baseKey,
    { name: 'AES-GCM', length: KEY_BITS },
    false,
    ['encrypt', 'decrypt']
  );
}

async function encryptPayload(plaintext, password) {
  const salt = randomBytes(SALT_BYTES);
  const iv   = randomBytes(IV_BYTES);
  const key  = await deriveKey(password, salt);
  const ctBuf = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    textEnc.encode(plaintext)
  );
  return { salt, iv, ciphertext: new Uint8Array(ctBuf) };
}

async function decryptPayload(ciphertext, password, salt, iv) {
  const key = await deriveKey(password, salt);
  const ptBuf = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv },
    key,
    ciphertext
  );
  return textDec.decode(ptBuf);
}

/* ------------------------------------------------------------------ *
 * 8. FILE FORMAT                                                      *
 * ------------------------------------------------------------------ */

/**
 * Build a .vbk file (JSON envelope) from a notebook object.
 * The signature marker is prepended inside the encrypted payload so
 * that a wrong password fails authentication OR fails the signature
 * check, never silently returns garbage.
 */
async function buildVbkFile(notebook, password) {
  const payload = SIGNATURE + JSON.stringify(notebook);
  const { salt, iv, ciphertext } = await encryptPayload(payload, password);
  const envelope = {
    format:     FORMAT_ID,
    version:    FORMAT_VER,
    salt:       bytesToB64(salt),
    iv:         bytesToB64(iv),
    ciphertext: bytesToB64(ciphertext),
  };
  return new Blob([JSON.stringify(envelope, null, 2)], { type: 'application/json' });
}

/**
 * Parse a file byte array into an envelope descriptor. Detects both
 * modern and legacy formats.
 * @returns { kind: 'vbk'|'rna', salt, iv, ciphertext }
 */
function parseEnvelope(bytes) {
  let obj;
  try { obj = JSON.parse(textDec.decode(bytes)); }
  catch (e) { throw new Error('This file is not a valid Vaultbook or R. Note file.'); }
  if (!obj || typeof obj !== 'object') throw new Error('Malformed file.');

  if (obj.format === FORMAT_ID && obj.version === FORMAT_VER) {
    return {
      kind: 'vbk',
      salt: b64ToBytes(obj.salt),
      iv: b64ToBytes(obj.iv),
      ciphertext: b64ToBytes(obj.ciphertext),
    };
  }
  if (obj.format === LEGACY_ID && obj.version === LEGACY_VER) {
    return {
      kind: 'rna',
      salt: b64ToBytes(obj.salt),
      iv: b64ToBytes(obj.iv),
      ciphertext: b64ToBytes(obj.ciphertext),
    };
  }
  throw new Error('Unrecognized file format or version.');
}

/**
 * Decrypt an envelope with the given password and return a normalized
 * notebook object regardless of source format.
 */
async function decryptToNotebook(env, password) {
  let pt;
  try {
    pt = await decryptPayload(env.ciphertext, password, env.salt, env.iv);
  } catch (_) {
    throw new Error('Incorrect password or corrupted file.');
  }

  if (env.kind === 'vbk') {
    if (!pt.startsWith(SIGNATURE)) throw new Error('Incorrect password or corrupted file.');
    const jsonStr = pt.slice(SIGNATURE.length);
    let nb;
    try { nb = JSON.parse(jsonStr); }
    catch (_) { throw new Error('Notebook data was corrupted.'); }
    return normalizeNotebook(nb);
  }

  if (env.kind === 'rna') {
    if (!pt.startsWith(LEGACY_SIG)) throw new Error('Incorrect password or corrupted file.');
    const jsonStr = pt.slice(LEGACY_SIG.length);
    let legacy;
    try { legacy = JSON.parse(jsonStr); }
    catch (_) { throw new Error('Legacy notebook data was corrupted.'); }
    // Legacy shape: { title, body, savedAt }
    return normalizeNotebook({
      title: legacy.title || '',
      body:  legacy.body  || '',
      drawing: null,
      images: [],
      createdAt: legacy.savedAt || new Date().toISOString(),
      updatedAt: legacy.savedAt || new Date().toISOString(),
    });
  }

  throw new Error('Unknown envelope kind.');
}

function normalizeNotebook(nb) {
  return {
    title:     typeof nb.title === 'string' ? nb.title : '',
    body:      typeof nb.body  === 'string' ? nb.body  : '',
    drawing:   typeof nb.drawing === 'string' ? nb.drawing : null,
    images:    Array.isArray(nb.images) ? nb.images.filter(
                 im => im && typeof im.dataURL === 'string'
               ).map(im => ({
                 id:      im.id      || uid(),
                 name:    im.name    || 'image',
                 dataURL: im.dataURL,
               })) : [],
    createdAt: nb.createdAt || new Date().toISOString(),
    updatedAt: nb.updatedAt || new Date().toISOString(),
  };
}

/* ------------------------------------------------------------------ *
 * 9. EDITOR: text, stats, autosave                                    *
 * ------------------------------------------------------------------ */
function loadNotebookIntoEditor(nb) {
  state.notebook = nb;
  el.editorTitle.value = nb.title;
  el.editorBody.value  = nb.body;
  // drawing → canvas
  if (nb.drawing) loadCanvasFromDataURL(nb.drawing);
  else            clearCanvas(true);
  // images → grid
  renderImages();
  autoGrowBody();
  refreshStats();
  markSaved();
}

function autoGrowBody() {
  el.editorBody.style.height = 'auto';
  el.editorBody.style.height = (el.editorBody.scrollHeight + 4) + 'px';
}

function refreshStats() {
  const text = el.editorBody.value || '';
  const words = text.trim() ? text.trim().split(/\s+/).length : 0;
  const chars = text.length;
  const mins  = Math.max(1, Math.round(words / 220));
  el.statWords.textContent = words.toLocaleString();
  el.statChars.textContent = chars.toLocaleString();
  el.statRead.textContent  = words === 0 ? '<1 min' : (mins === 1 ? '~1 min' : '~' + mins + ' min');
}

function markDirty() {
  state.dirty = true;
  updateSaveIndicator();
  // Debounced sync of textarea + title into state.notebook.
  clearTimeout(state.autosaveTimer);
  state.autosaveTimer = setTimeout(syncEditorIntoState, AUTOSAVE_MS);
}
function markSaved() {
  state.dirty = false;
  updateSaveIndicator();
}
function updateSaveIndicator() {
  if (!state.notebook) { el.saveIndicator.textContent = ''; return; }
  if (state.dirty) {
    el.saveIndicator.textContent = 'Unsaved changes';
    el.saveIndicator.className = 'save-indicator is-unsaved';
  } else {
    el.saveIndicator.textContent = 'All changes saved (locally)';
    el.saveIndicator.className = 'save-indicator is-saved';
  }
}

/**
 * Push editor DOM values into state.notebook. Also snapshots drawing
 * if it has been modified since last sync. Called on autosave, before
 * mode switch, before save, before panic lock.
 */
function syncEditorIntoState() {
  if (!state.notebook) return;
  state.notebook.title = el.editorTitle.value;
  state.notebook.body  = el.editorBody.value;
  if (state.drawing.dirty) {
    state.notebook.drawing = getCanvasDataURL();
    state.drawing.dirty = false;
  }
  state.notebook.updatedAt = new Date().toISOString();
}

function bindEditorEvents() {
  el.editorTitle.addEventListener('input', () => { markDirty(); });
  el.editorBody.addEventListener('input',  () => { refreshStats(); autoGrowBody(); markDirty(); });

  // mode tabs
  el.tabWrite.addEventListener('click', () => setMode('write'));
  el.tabDraw.addEventListener('click',  () => setMode('draw'));

  // topbar
  el.btnEditorHome.addEventListener('click', () => goHome());
  el.btnSave.addEventListener('click', doSave);
  el.btnPanic.addEventListener('click', doPanicLock);

  // images
  el.btnAddImage.addEventListener('click', () => el.imageInput.click());
  el.imageInput.addEventListener('change', onImagePicked);

  // export menu
  el.btnExportMenu.addEventListener('click', (e) => {
    e.stopPropagation();
    const open = !el.exportMenu.hidden;
    el.exportMenu.hidden = open;
    el.btnExportMenu.setAttribute('aria-expanded', String(!open));
  });
  document.addEventListener('click', () => {
    if (!el.exportMenu.hidden) { el.exportMenu.hidden = true; el.btnExportMenu.setAttribute('aria-expanded', 'false'); }
  });
  el.exportMenu.addEventListener('click', (e) => {
    const btn = e.target.closest('.menu-item');
    if (!btn) return;
    if (btn.dataset.action === 'export-pdf') exportPDF();
    if (btn.dataset.action === 'export-txt') exportTXT();
  });
}

function setMode(mode) {
  syncEditorIntoState(); // capture current state before switching
  if (mode === 'write') {
    el.modeWrite.hidden = false;
    el.modeDraw.hidden  = true;
    el.tabWrite.classList.add('is-active'); el.tabWrite.setAttribute('aria-selected', 'true');
    el.tabDraw.classList.remove('is-active'); el.tabDraw.setAttribute('aria-selected', 'false');
    setTimeout(() => { el.editorBody.focus(); autoGrowBody(); }, 30);
  } else {
    el.modeWrite.hidden = true;
    el.modeDraw.hidden  = false;
    el.tabWrite.classList.remove('is-active'); el.tabWrite.setAttribute('aria-selected', 'false');
    el.tabDraw.classList.add('is-active'); el.tabDraw.setAttribute('aria-selected', 'true');
    // Ensure canvas reflects latest notebook drawing
    if (state.notebook && state.notebook.drawing) loadCanvasFromDataURL(state.notebook.drawing);
  }
}

/* ------------------------------------------------------------------ *
 * 10. EDITOR: DRAWING ENGINE                                          *
 * ------------------------------------------------------------------ */
function initCanvas() {
  const cv = el.drawCanvas;
  cv.width = CANVAS_W;
  cv.height = CANVAS_H;
  const ctx = cv.getContext('2d', { willReadFrequently: false });
  ctx.lineCap = 'round';
  ctx.lineJoin = 'round';
  ctx.fillStyle = '#ffffff';
  ctx.fillRect(0, 0, CANVAS_W, CANVAS_H);
  state.drawing.ctx = ctx;
  pushUndo(); // baseline

  const getPos = (evt) => {
    const rect = cv.getBoundingClientRect();
    const scaleX = cv.width  / rect.width;
    const scaleY = cv.height / rect.height;
    const src = (evt.touches && evt.touches[0]) ? evt.touches[0] : evt;
    return {
      x: (src.clientX - rect.left) * scaleX,
      y: (src.clientY - rect.top)  * scaleY,
    };
  };

  const start = (e) => {
    e.preventDefault();
    const p = getPos(e);
    state.drawing.isDrawing = true;
    state.drawing.lastX = p.x;
    state.drawing.lastY = p.y;
    // draw a dot for click-only
    ctx.beginPath();
    ctx.fillStyle = state.drawing.tool === 'eraser' ? '#ffffff' : state.drawing.color;
    ctx.arc(p.x, p.y, state.drawing.size / 2, 0, Math.PI * 2);
    ctx.fill();
  };
  const move = (e) => {
    if (!state.drawing.isDrawing) return;
    e.preventDefault();
    const p = getPos(e);
    ctx.beginPath();
    ctx.strokeStyle = state.drawing.tool === 'eraser' ? '#ffffff' : state.drawing.color;
    ctx.lineWidth   = state.drawing.size;
    ctx.moveTo(state.drawing.lastX, state.drawing.lastY);
    ctx.lineTo(p.x, p.y);
    ctx.stroke();
    state.drawing.lastX = p.x;
    state.drawing.lastY = p.y;
  };
  const end = () => {
    if (!state.drawing.isDrawing) return;
    state.drawing.isDrawing = false;
    state.drawing.dirty = true;
    pushUndo();
    markDirty();
  };

  cv.addEventListener('mousedown', start);
  cv.addEventListener('mousemove', move);
  window.addEventListener('mouseup', end);
  cv.addEventListener('mouseleave', end);
  cv.addEventListener('touchstart', start, { passive: false });
  cv.addEventListener('touchmove',  move,  { passive: false });
  cv.addEventListener('touchend',   end);
  cv.addEventListener('touchcancel', end);
}

function bindDrawingUI() {
  // tool buttons
  $$('.tool-btn[data-tool]').forEach(btn => {
    btn.addEventListener('click', () => {
      $$('.tool-btn[data-tool]').forEach(b => { b.classList.remove('is-active'); b.setAttribute('aria-checked', 'false'); });
      btn.classList.add('is-active'); btn.setAttribute('aria-checked', 'true');
      state.drawing.tool = btn.dataset.tool;
    });
  });
  // color swatches
  $$('.color-swatch[data-color]').forEach(sw => {
    sw.addEventListener('click', () => {
      $$('.color-swatch').forEach(s => s.classList.remove('is-active'));
      sw.classList.add('is-active');
      state.drawing.color = sw.dataset.color;
      // switch to brush automatically if in eraser
      if (state.drawing.tool === 'eraser') {
        const brushBtn = $('.tool-btn[data-tool="brush"]');
        brushBtn.click();
      }
    });
  });
  // custom color
  el.customColor.addEventListener('input', () => {
    state.drawing.color = el.customColor.value;
    $$('.color-swatch').forEach(s => s.classList.remove('is-active'));
    $('.color-custom').classList.add('is-active');
    const brushBtn = $('.tool-btn[data-tool="brush"]');
    if (state.drawing.tool === 'eraser') brushBtn.click();
  });
  // brush size
  el.brushSize.addEventListener('input', () => {
    state.drawing.size = parseInt(el.brushSize.value, 10) || 1;
    el.sizeLabel.textContent = String(state.drawing.size);
  });
  // undo / redo / clear
  el.btnUndo.addEventListener('click',        () => doUndo());
  el.btnRedo.addEventListener('click',        () => doRedo());
  el.btnClearCanvas.addEventListener('click', () => {
    if (!confirm('Clear the entire drawing? This can be undone.')) return;
    clearCanvas();
    state.drawing.dirty = true;
    pushUndo();
    markDirty();
  });
}

function clearCanvas(silent = false) {
  const ctx = state.drawing.ctx; if (!ctx) return;
  ctx.save();
  ctx.setTransform(1, 0, 0, 1, 0, 0);
  ctx.fillStyle = '#ffffff';
  ctx.fillRect(0, 0, CANVAS_W, CANVAS_H);
  ctx.restore();
  if (silent) {
    state.drawing.undoStack = [];
    state.drawing.redoStack = [];
    pushUndo();
  }
}

function getCanvasDataURL() {
  // Skip empty canvases to keep files small.
  if (isCanvasBlank()) return null;
  return el.drawCanvas.toDataURL('image/png');
}

function isCanvasBlank() {
  const ctx = state.drawing.ctx;
  if (!ctx) return true;
  const { data } = ctx.getImageData(0, 0, CANVAS_W, CANVAS_H);
  // all white?
  for (let i = 0; i < data.length; i += 4) {
    if (data[i] !== 255 || data[i+1] !== 255 || data[i+2] !== 255) return false;
  }
  return true;
}

function loadCanvasFromDataURL(dataURL) {
  const ctx = state.drawing.ctx; if (!ctx) return;
  const img = new Image();
  img.onload = () => {
    ctx.fillStyle = '#ffffff';
    ctx.fillRect(0, 0, CANVAS_W, CANVAS_H);
    ctx.drawImage(img, 0, 0, CANVAS_W, CANVAS_H);
    state.drawing.undoStack = [];
    state.drawing.redoStack = [];
    pushUndo();
  };
  img.src = dataURL;
}

function pushUndo() {
  try {
    const url = el.drawCanvas.toDataURL('image/png');
    state.drawing.undoStack.push(url);
    if (state.drawing.undoStack.length > UNDO_LIMIT) state.drawing.undoStack.shift();
    state.drawing.redoStack = [];
    updateUndoButtons();
  } catch (_) { /* ignore */ }
}

function doUndo() {
  if (state.drawing.undoStack.length <= 1) return;
  const current = state.drawing.undoStack.pop();
  state.drawing.redoStack.push(current);
  const prev = state.drawing.undoStack[state.drawing.undoStack.length - 1];
  restoreFromDataURL(prev);
  state.drawing.dirty = true;
  markDirty();
  updateUndoButtons();
}
function doRedo() {
  if (!state.drawing.redoStack.length) return;
  const url = state.drawing.redoStack.pop();
  state.drawing.undoStack.push(url);
  restoreFromDataURL(url);
  state.drawing.dirty = true;
  markDirty();
  updateUndoButtons();
}
function restoreFromDataURL(url) {
  const ctx = state.drawing.ctx;
  const img = new Image();
  img.onload = () => {
    ctx.clearRect(0, 0, CANVAS_W, CANVAS_H);
    ctx.drawImage(img, 0, 0);
  };
  img.src = url;
}
function updateUndoButtons() {
  el.btnUndo.disabled = state.drawing.undoStack.length <= 1;
  el.btnRedo.disabled = state.drawing.redoStack.length === 0;
}

/* ------------------------------------------------------------------ *
 * 11. EDITOR: IMAGES                                                  *
 * ------------------------------------------------------------------ */
async function onImagePicked(e) {
  const file = e.target.files && e.target.files[0];
  el.imageInput.value = '';
  if (!file) return;
  if (!file.type.startsWith('image/')) {
    toast('That doesn\'t look like an image.', 'error'); return;
  }
  // Guard against extremely large images (5MB warning).
  if (file.size > 5 * 1024 * 1024) {
    if (!confirm('This image is large (>' + Math.round(file.size / 1024 / 1024) + ' MB). It will make your notebook file bigger. Continue?')) return;
  }
  const dataURL = await new Promise((resolve, reject) => {
    const fr = new FileReader();
    fr.onload = () => resolve(fr.result);
    fr.onerror = () => reject(fr.error);
    fr.readAsDataURL(file);
  }).catch(() => null);
  if (!dataURL) { toast('Could not read that image.', 'error'); return; }

  const img = { id: uid(), name: file.name, dataURL };
  state.notebook.images.push(img);
  renderImages();
  markDirty();
  toast('Image added.');
}

function renderImages() {
  const imgs = (state.notebook && state.notebook.images) || [];
  el.imagesGrid.innerHTML = '';
  if (!imgs.length) { el.imagesSection.hidden = true; return; }
  el.imagesSection.hidden = false;
  imgs.forEach(im => {
    const thumb = document.createElement('div');
    thumb.className = 'img-thumb';
    thumb.dataset.id = im.id;
    thumb.setAttribute('role', 'button');
    thumb.setAttribute('aria-label', 'Open image ' + im.name);
    thumb.innerHTML = `<img alt="" src="${im.dataURL}" />`;
    thumb.addEventListener('click', () => openImageModal(im.id));
    el.imagesGrid.appendChild(thumb);
  });
}

function openImageModal(id) {
  const im = state.notebook.images.find(i => i.id === id);
  if (!im) return;
  el.modalImg.src = im.dataURL;
  el.modalImg.alt = im.name;
  el.imageModal.hidden = false;
  el.imageModal.dataset.currentId = id;
}
function closeImageModal() {
  el.imageModal.hidden = true;
  el.modalImg.src = '';
  el.imageModal.dataset.currentId = '';
}
function bindModal() {
  $$('[data-modal-close]').forEach(x => x.addEventListener('click', closeImageModal));
  el.btnRemoveImage.addEventListener('click', () => {
    const id = el.imageModal.dataset.currentId;
    if (!id) return;
    state.notebook.images = state.notebook.images.filter(i => i.id !== id);
    renderImages();
    markDirty();
    closeImageModal();
    toast('Image removed.');
  });
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && !el.imageModal.hidden) closeImageModal();
  });
}

/* ------------------------------------------------------------------ *
 * 12. PANIC LOCK                                                      *
 *                                                                     *
 *   Panic Lock hides the notebook and drops references to the         *
 *   plaintext + password, BUT keeps the encrypted bytes in memory so  *
 *   the same session can restore the notebook once the correct        *
 *   password is re-entered. If the user closes the tab, the panic     *
 *   vault is gone forever; that's by design.                          *
 * ------------------------------------------------------------------ */
async function doPanicLock() {
  if (!state.notebook || !state.password) return;
  syncEditorIntoState();
  try {
    const payload = SIGNATURE + JSON.stringify(state.notebook);
    const { salt, iv, ciphertext } = await encryptPayload(payload, state.password);
    state.panicVault = { salt, iv, ciphertext };
  } catch (err) {
    console.error(err);
    toast('Panic lock failed. Try Save instead.', 'error');
    return;
  }

  // Wipe visible + plaintext state (keep only panicVault).
  state.notebook = null;
  state.password = null;
  state.dirty = false;
  clearTimeout(state.autosaveTimer);

  el.editorTitle.value = '';
  el.editorBody.value  = '';
  el.imagesGrid.innerHTML = '';
  el.imagesSection.hidden = true;
  if (state.drawing.ctx) clearCanvas(true);
  state.drawing.undoStack = [];
  state.drawing.redoStack = [];
  state.drawing.dirty = false;
  refreshStats();
  updateSaveIndicator();

  el.panicStatus.textContent = '';
  el.panicStatus.className = 'status-line';
  el.panicPassword.value = '';
  el.panicOverlay.hidden = false;
  el.panicOverlay.setAttribute('aria-hidden', 'false');
  setTimeout(() => el.panicPassword.focus(), 50);
}

async function doPanicUnlock(e) {
  e && e.preventDefault();
  if (!state.panicVault) { hidePanicOverlay(); return; }
  const pw = el.panicPassword.value;
  if (!pw) return;
  el.panicStatus.textContent = 'Unlocking…';
  el.panicStatus.className = 'status-line info';

  try {
    const pt = await decryptPayload(
      state.panicVault.ciphertext, pw,
      state.panicVault.salt, state.panicVault.iv
    );
    if (!pt.startsWith(SIGNATURE)) throw new Error('bad signature');
    const nb = JSON.parse(pt.slice(SIGNATURE.length));

    state.password = pw;
    state.panicVault = null;
    el.panicPassword.value = '';
    loadNotebookIntoEditor(normalizeNotebook(nb));
    hidePanicOverlay();
    toast('Vaultbook restored.', 'success');
  } catch (err) {
    el.panicStatus.textContent = 'Incorrect password.';
    el.panicStatus.className = 'status-line error';
    el.panicPassword.select();
  }
}

function hidePanicOverlay() {
  el.panicOverlay.hidden = true;
  el.panicOverlay.setAttribute('aria-hidden', 'true');
}

/* ------------------------------------------------------------------ *
 * 13. SAVE (encrypt & download)                                       *
 * ------------------------------------------------------------------ */
async function doSave() {
  if (!state.notebook || !state.password) return;
  syncEditorIntoState();
  try {
    el.saveIndicator.textContent = 'Encrypting…';
    el.saveIndicator.className = 'save-indicator';
    const blob = await buildVbkFile(state.notebook, state.password);
    const fname = sanitizeFilename(state.notebook.title || 'Untitled') + '.vbk';
    downloadBlob(blob, fname);
    // legacy notice is one-time: once user saves as .vbk they've upgraded.
    state.isImportedLegacy = false;
    el.importNotice.hidden = true;
    markSaved();
    toast('Saved as ' + fname, 'success');
  } catch (err) {
    console.error(err);
    toast('Encryption failed. Please try again.', 'error');
    updateSaveIndicator();
  }
}

/* ------------------------------------------------------------------ *
 * 14. UNLOCK FLOW                                                     *
 * ------------------------------------------------------------------ */
function bindOpenScreen() {
  el.btnBrowseFile.addEventListener('click', () => el.fileInput.click());
  el.dropzone.addEventListener('click',      () => el.fileInput.click());
  el.dropzone.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); el.fileInput.click(); }
  });
  el.fileInput.addEventListener('change', (e) => {
    const f = e.target.files && e.target.files[0];
    if (f) acceptFile(f);
  });
  ['dragenter','dragover'].forEach(ev =>
    el.dropzone.addEventListener(ev, (e) => { e.preventDefault(); el.dropzone.classList.add('is-dragover'); })
  );
  ['dragleave','drop'].forEach(ev =>
    el.dropzone.addEventListener(ev, (e) => { e.preventDefault(); el.dropzone.classList.remove('is-dragover'); })
  );
  el.dropzone.addEventListener('drop', (e) => {
    const f = e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0];
    if (f) acceptFile(f);
  });

  el.unlockForm.addEventListener('submit', doUnlock);
}

async function acceptFile(file) {
  const name = file.name || '';
  if (!/\.(vbk|rna)$/i.test(name)) {
    toast('Please choose a .vbk or .rna file.', 'error');
    return;
  }
  try {
    const buf = new Uint8Array(await file.arrayBuffer());
    // Quick sanity parse to detect format before asking for password.
    const env = parseEnvelope(buf);
    state.pendingFile = buf;
    state.pendingFileName = name;
    state.pendingFormat = env.kind;
    el.dzFilename.textContent =
      (env.kind === 'rna' ? 'Legacy R. Note file: ' : 'Vaultbook file: ') + name;
    el.unlockForm.hidden = false;
    el.unlockStatus.textContent = '';
    el.unlockStatus.className = 'status-line';
    setTimeout(() => el.unlockPassword.focus(), 50);
  } catch (err) {
    el.unlockForm.hidden = true;
    toast(err.message || 'Could not read this file.', 'error');
  }
}

async function doUnlock(e) {
  e.preventDefault();
  if (!state.pendingFile) return;
  const pw = el.unlockPassword.value;
  if (!pw) return;
  el.unlockStatus.textContent = 'Decrypting…';
  el.unlockStatus.className = 'status-line info';
  try {
    const env = parseEnvelope(state.pendingFile);
    const nb  = await decryptToNotebook(env, pw);
    state.password = pw;
    state.isImportedLegacy = (env.kind === 'rna');
    // pendingFile no longer needed
    state.pendingFile = null;
    el.unlockPassword.value = '';

    showScreen('editor');
    loadNotebookIntoEditor(nb);
    el.importNotice.hidden = !state.isImportedLegacy;
    toast(state.isImportedLegacy
      ? 'Legacy R. Note file imported. Save to convert to .vbk.'
      : 'Vaultbook unlocked.', 'success');
  } catch (err) {
    el.unlockStatus.textContent = err.message || 'Incorrect password or corrupted file.';
    el.unlockStatus.className = 'status-line error';
    el.unlockPassword.select();
  }
}

/* ------------------------------------------------------------------ *
 * 15. EXPORTS                                                         *
 * ------------------------------------------------------------------ */
async function exportPDF() {
  if (!state.notebook) return;
  syncEditorIntoState();
  toast('Building PDF…');
  try {
    const { jsPDF } = window.jspdf;
    const doc = new jsPDF({ unit: 'pt', format: 'a4', compress: true });
    const pageW = doc.internal.pageSize.getWidth();
    const pageH = doc.internal.pageSize.getHeight();
    const margin = 54;
    const contentW = pageW - margin * 2;
    let y = margin;

    // Title
    const title = state.notebook.title || 'Untitled Vaultbook';
    doc.setFont('helvetica', 'bold'); doc.setFontSize(22);
    const titleLines = doc.splitTextToSize(title, contentW);
    doc.text(titleLines, margin, y + 18);
    y += 18 * titleLines.length + 10;

    // Meta line
    doc.setFont('helvetica', 'normal'); doc.setFontSize(9); doc.setTextColor(120);
    const meta = 'Exported from Vaultbook · ' + new Date().toLocaleString();
    doc.text(meta, margin, y);
    y += 18;
    doc.setDrawColor(210); doc.line(margin, y, pageW - margin, y); y += 18;
    doc.setTextColor(30);

    // Body text
    if (state.notebook.body && state.notebook.body.trim()) {
      doc.setFont('helvetica', 'normal'); doc.setFontSize(11);
      const bodyLines = doc.splitTextToSize(state.notebook.body, contentW);
      const lh = 15;
      for (const line of bodyLines) {
        if (y > pageH - margin) { doc.addPage(); y = margin; }
        doc.text(line, margin, y);
        y += lh;
      }
      y += 12;
    }

    // Drawing
    if (state.notebook.drawing) {
      const imgW = contentW;
      const imgH = imgW * (CANVAS_H / CANVAS_W);
      if (y + imgH + 30 > pageH - margin) { doc.addPage(); y = margin; }
      doc.setFont('helvetica', 'bold'); doc.setFontSize(11);
      doc.text('Sketch', margin, y); y += 12;
      doc.addImage(state.notebook.drawing, 'PNG', margin, y, imgW, imgH);
      y += imgH + 20;
    }

    // Images
    if (state.notebook.images && state.notebook.images.length) {
      if (y > pageH - margin - 100) { doc.addPage(); y = margin; }
      doc.setFont('helvetica', 'bold'); doc.setFontSize(11);
      doc.text('Attached images', margin, y); y += 14;
      for (const im of state.notebook.images) {
        // Determine natural dimensions for aspect ratio.
        const dim = await getImageSize(im.dataURL);
        const maxW = contentW;
        const maxH = pageH - margin - y - 20;
        let iw = dim.w, ih = dim.h;
        if (iw > maxW) { ih = ih * (maxW / iw); iw = maxW; }
        if (ih > maxH) {
          // insufficient room; new page
          doc.addPage(); y = margin;
          iw = dim.w; ih = dim.h;
          if (iw > contentW) { ih = ih * (contentW / iw); iw = contentW; }
          const availH = pageH - margin * 2;
          if (ih > availH) { iw = iw * (availH / ih); ih = availH; }
        }
        const fmt = /^data:image\/(png|jpeg|jpg|webp);/i.exec(im.dataURL);
        const type = fmt ? fmt[1].toUpperCase().replace('JPG','JPEG') : 'PNG';
        try { doc.addImage(im.dataURL, type, margin, y, iw, ih); }
        catch (_) { /* skip un-embeddable */ }
        y += ih + 16;
      }
    }

    const fname = sanitizeFilename(title) + '.pdf';
    doc.save(fname);
    toast('PDF saved: ' + fname, 'success');
  } catch (err) {
    console.error(err);
    toast('PDF export failed.', 'error');
  }
}

function getImageSize(dataURL) {
  return new Promise((res) => {
    const img = new Image();
    img.onload = () => res({ w: img.naturalWidth, h: img.naturalHeight });
    img.onerror = () => res({ w: 400, h: 300 });
    img.src = dataURL;
  });
}

function exportTXT() {
  if (!state.notebook) return;
  syncEditorIntoState();
  const nb = state.notebook;
  const hasNonText = nb.drawing || (nb.images && nb.images.length);
  if (hasNonText) {
    if (!confirm('This notebook contains a drawing or images. A TXT export will only include the title and text. Continue?')) return;
  }
  const parts = [];
  parts.push(nb.title || 'Untitled Vaultbook');
  parts.push('='.repeat(Math.min(60, (nb.title || 'Untitled Vaultbook').length)));
  parts.push('');
  parts.push(nb.body || '');
  parts.push('');
  parts.push('---');
  parts.push('Exported from Vaultbook · ' + new Date().toLocaleString());
  if (hasNonText) parts.push('(Drawing and/or images not included in this TXT export.)');

  const blob = new Blob([parts.join('\n')], { type: 'text/plain;charset=utf-8' });
  const fname = sanitizeFilename(nb.title || 'Untitled') + '.txt';
  downloadBlob(blob, fname);
  toast('Text saved: ' + fname, 'success');
}

/* ------------------------------------------------------------------ *
 * 16. KEYBOARD SHORTCUTS                                              *
 * ------------------------------------------------------------------ */
function bindShortcuts() {
  document.addEventListener('keydown', (e) => {
    const mod = e.ctrlKey || e.metaKey;
    // Ctrl+D → toggle theme (any screen)
    if (mod && (e.key === 'd' || e.key === 'D')) {
      e.preventDefault();
      toggleTheme();
      return;
    }
    // Editor-only shortcuts
    if (state.currentScreen !== 'editor') return;
    if (!state.notebook) return;

    // Ctrl+S → save
    if (mod && (e.key === 's' || e.key === 'S')) {
      e.preventDefault();
      doSave();
      return;
    }
    // Ctrl+L → panic lock
    if (mod && (e.key === 'l' || e.key === 'L')) {
      e.preventDefault();
      doPanicLock();
      return;
    }
    // Draw-mode undo/redo (do NOT interfere with text areas)
    if (!el.modeDraw.hidden && mod) {
      if ((e.key === 'z' || e.key === 'Z') && !e.shiftKey) {
        e.preventDefault(); doUndo();
      } else if ((e.key === 'y' || e.key === 'Y') || ((e.key === 'z' || e.key === 'Z') && e.shiftKey)) {
        e.preventDefault(); doRedo();
      }
    }
    // Escape in draw mode → back to write
    if (e.key === 'Escape' && !el.modeDraw.hidden) {
      setMode('write');
    }
  });
}

/* ------------------------------------------------------------------ *
 * 17. INIT                                                            *
 * ------------------------------------------------------------------ */
function bindGlobal() {
  el.themeToggle.addEventListener('click', toggleTheme);

  // password toggles (all screens)
  document.addEventListener('click', (e) => {
    const t = e.target.closest('.pw-toggle');
    if (!t) return;
    const targetId = t.dataset.target;
    const input = document.getElementById(targetId);
    if (!input) return;
    input.type = (input.type === 'password') ? 'text' : 'password';
  });

  // back buttons
  $$('[data-goto="home"]').forEach(b => b.addEventListener('click', () => goHome({ confirmIfDirty: false })));
}

function bindHome() {
  el.btnNew.addEventListener('click', () => {
    resetPasswordSetup();
    showScreen('password');
    setTimeout(() => el.pwNew.focus(), 50);
  });
  el.btnOpen.addEventListener('click', () => {
    resetOpenScreen();
    showScreen('open');
  });
}

function resetPasswordSetup() {
  el.pwSetupForm.reset();
  el.pwStrength.className = 'pw-strength';
  el.pwStrength.querySelector('.pw-strength-label').textContent = 'Enter a password';
  el.pwMatchHint.textContent = '';
  el.pwMatchHint.className = 'field-hint';
  el.pwSetupStatus.textContent = '';
  el.pwSetupStatus.className = 'status-line';
}

function bindPasswordSetup() {
  el.pwNew.addEventListener('input', () => { updateStrength(); updateMatchHint(); });
  el.pwConfirm.addEventListener('input', updateMatchHint);

  el.pwSetupForm.addEventListener('submit', (e) => {
    e.preventDefault();
    const a = el.pwNew.value, b = el.pwConfirm.value;
    el.pwSetupStatus.className = 'status-line';
    el.pwSetupStatus.textContent = '';
    if (!a) { el.pwSetupStatus.textContent = 'Please enter a password.'; el.pwSetupStatus.className = 'status-line error'; return; }
    if (a.length < 4) { el.pwSetupStatus.textContent = 'That password is very short. Please use at least 4 characters.'; el.pwSetupStatus.className = 'status-line error'; return; }
    if (a !== b) { el.pwSetupStatus.textContent = 'Passwords do not match.'; el.pwSetupStatus.className = 'status-line error'; return; }

    // OK — create notebook.
    state.password = a;
    state.notebook = makeEmptyNotebook();
    state.isImportedLegacy = false;
    el.pwNew.value = '';
    el.pwConfirm.value = '';
    showScreen('editor');
    loadNotebookIntoEditor(state.notebook);
    setTimeout(() => el.editorTitle.focus(), 60);
    toast('New Vaultbook ready. Write away.', 'success');
  });
}

function bindPanic() {
  el.panicForm.addEventListener('submit', doPanicUnlock);
  el.btnPanicDiscard.addEventListener('click', () => {
    if (!confirm('Discard this notebook and return to home? If you didn\'t Save it as a .vbk file first, its contents will be lost.')) return;
    state.panicVault = null;
    hidePanicOverlay();
    goHome({ confirmIfDirty: false });
  });
}

function init() {
  initTheme();
  bindGlobal();
  bindHome();
  bindPasswordSetup();
  bindOpenScreen();
  bindEditorEvents();
  bindDrawingUI();
  bindModal();
  bindPanic();
  bindShortcuts();
  initCanvas();

  // Warn on page unload if there is unsaved sensitive state.
  window.addEventListener('beforeunload', (e) => {
    if (state.dirty || state.panicVault) {
      e.preventDefault();
      e.returnValue = '';
    }
  });
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', init);
} else {
  init();
}
