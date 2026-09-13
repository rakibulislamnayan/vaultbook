/* ==========================================================================
 * VAULTBOOK v2.0
 * Sections:
 *   1.  Constants & refs
 *   2.  State
 *   3.  Utilities
 *   4.  Screen nav
 *   5.  Theme
 *   6.  Password strength
 *   7.  Crypto (AES-256-GCM + PBKDF2)
 *   8.  File format (.vbk / legacy .rna)
 *   9.  Document model (blocks)
 *   10. Block: text
 *   11. Block: draw (per-canvas engine)
 *   12. Block: image
 *   13. Stats
 *   14. Panic Lock
 *   15. Save
 *   16. Unlock flow
 *   17. Exports (PDF, TXT)
 *   18. Keyboard shortcuts
 *   19. Init
 * ========================================================================== */
'use strict';

/* ------------------------------------------------------------------ *
 * 1. CONSTANTS & REFS                                                 *
 * ------------------------------------------------------------------ */
const FORMAT_ID    = 'VAULTBOOK';
const FORMAT_VER   = 2;
const SIGNATURE    = 'VAULTBOOK_V2::';
const LEGACY_ID    = 'RNA';
const LEGACY_VER   = 1;
const LEGACY_SIG   = 'RNA_NOTEBOOK_V1::';
const PBKDF2_ITERS = 250_000;
const SALT_BYTES   = 16;
const IV_BYTES     = 12;
const KEY_BITS     = 256;
const CANVAS_W     = 900;
const CANVAS_H     = 500;
const UNDO_LIMIT   = 40;
const AUTOSAVE_MS  = 700;

const $ = (s, r = document) => r.querySelector(s);
const el = {
  screenHome:     $('#screenHome'),
  screenPassword: $('#screenPassword'),
  screenOpen:     $('#screenOpen'),
  screenEditor:   $('#screenEditor'),
  btnNew:         $('#btnNewVaultbook'),
  btnOpen:        $('#btnOpenVaultbook'),
  pwSetupForm:    $('#pwSetupForm'),
  pwNew:          $('#pwNew'),
  pwConfirm:      $('#pwConfirm'),
  pwStrength:     $('#pwStrength'),
  pwMatchHint:    $('#pwMatchHint'),
  pwSetupStatus:  $('#pwSetupStatus'),
  dropzone:       $('#dropzone'),
  fileInput:      $('#fileInput'),
  btnBrowseFile:  $('#btnBrowseFile'),
  dzFilename:     $('#dropzoneFilename'),
  unlockForm:     $('#unlockForm'),
  unlockPassword: $('#unlockPassword'),
  unlockStatus:   $('#unlockStatus'),
  // editor bar
  btnEditorHome:  $('#btnEditorHome'),
  editorBrand:    $('.editor-brand'),
  saveIndicator:  $('#saveIndicator'),
  btnInsertDraw:  $('#btnInsertDraw'),
  btnInsertImage: $('#btnInsertImage'),
  imageInput:     $('#imageInput'),
  btnExportMenu:  $('#btnExportMenu'),
  exportMenu:     $('#exportMenu'),
  btnSave:        $('#btnSave'),
  btnPanic:       $('#btnPanic'),
  themeToggle:    $('#themeToggle'),
  // editor page
  editorTitle:    $('#editorTitle'),
  docBody:        $('#docBody'),
  // sidebar
  statWords:      $('#statWords'),
  statChars:      $('#statChars'),
  statRead:       $('#statRead'),
  importNotice:   $('#importNoticeCard'),
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
  // misc
  toast:          $('#toast'),
  drawToolbarTpl: $('#drawToolbarTemplate'),
};

/* ------------------------------------------------------------------ *
 * 2. STATE                                                            *
 * ------------------------------------------------------------------ */
const state = {
  currentScreen:    'home',
  password:         null,
  notebook:         null,   // { title, blocks[], createdAt, updatedAt }
  pendingFile:      null,
  pendingFormat:    null,
  isImportedLegacy: false,
  panicVault:       null,   // { salt, iv, ciphertext }
  dirty:            false,
  autosaveTimer:    null,
  // map of blockId → per-block draw state (only for draw blocks)
  drawStates:       {},
  // currently open image modal info
  modalBlockId:     null,
};

function makeEmptyNotebook() {
  const now = new Date().toISOString();
  return { title:'', blocks:[ makeTextBlock() ], createdAt:now, updatedAt:now };
}

/* ── Block types ──
 * text  : { id, type:'text',  content:string }
 * draw  : { id, type:'draw',  dataURL:string|null, w:number, h:number }
 * image : { id, type:'image', dataURL:string, name:string }
 */
let _bid = 0;
function mkid() { return 'b' + (++_bid) + '_' + Math.random().toString(36).slice(2,7); }
const makeTextBlock  = (content='') => ({ id:mkid(), type:'text',  content });
const makeDrawBlock  = ()            => ({ id:mkid(), type:'draw',  dataURL:null, w:CANVAS_W, h:CANVAS_H });
const makeImageBlock = (dataURL,name)=> ({ id:mkid(), type:'image', dataURL, name:name||'image' });

/* ------------------------------------------------------------------ *
 * 3. UTILITIES                                                        *
 * ------------------------------------------------------------------ */
const textEnc = new TextEncoder();
const textDec = new TextDecoder();
const bytesToB64 = b => btoa(String.fromCharCode(...b));
const b64ToBytes = s => { const r=atob(s); return new Uint8Array(r.length).map((_,i)=>r.charCodeAt(i)); };
function randomBytes(n) { const b=new Uint8Array(n); crypto.getRandomValues(b); return b; }

let _toastT = null;
function toast(msg, kind='default') {
  el.toast.textContent = msg;
  el.toast.style.background = kind==='error'?'var(--warn)':kind==='success'?'var(--success)':'var(--ink)';
  el.toast.style.color = 'white';
  el.toast.hidden = false;
  clearTimeout(_toastT);
  _toastT = setTimeout(()=>{ el.toast.hidden=true; }, 2600);
}
function sanitizeFilename(n) {
  return ((n||'Untitled').trim().slice(0,60).replace(/[\\/:*?"<>|]+/g,'_')||'Untitled');
}
function downloadBlob(blob, filename) {
  const url=URL.createObjectURL(blob), a=document.createElement('a');
  a.href=url; a.download=filename; a.rel='noopener';
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(()=>URL.revokeObjectURL(url),500);
}

/* ------------------------------------------------------------------ *
 * 4. SCREEN NAV                                                       *
 * ------------------------------------------------------------------ */
function showScreen(name) {
  ['home','password','open','editor'].forEach(n => {
    const s = {home:el.screenHome,password:el.screenPassword,open:el.screenOpen,editor:el.screenEditor}[n];
    s.classList.toggle('is-active', n===name);
  });
  state.currentScreen = name;
  window.scrollTo({top:0,behavior:'instant'});
}
function goHome({confirm:needConfirm=true}={}) {
  if (needConfirm && state.dirty && state.notebook) {
    if (!window.confirm('You have unsaved changes. Return to home and lose them?')) return;
  }
  wipeSession();
  resetOpenScreen();
  showScreen('home');
}
function wipeSession() {
  state.password = null;
  state.notebook = null;
  state.pendingFile = null;
  state.pendingFormat = null;
  state.isImportedLegacy = false;
  state.panicVault = null;
  state.dirty = false;
  state.drawStates = {};
  clearTimeout(state.autosaveTimer);
  el.editorTitle.value = '';
  el.docBody.innerHTML = '';
  el.importNotice.hidden = true;
  refreshStats();
  updateSaveIndicator();
}
function resetOpenScreen() {
  el.fileInput.value='';
  el.dzFilename.textContent='';
  el.unlockPassword.value='';
  el.unlockStatus.textContent='';
  el.unlockStatus.className='status-line';
  el.unlockForm.hidden=true;
}

/* ------------------------------------------------------------------ *
 * 5. THEME                                                            *
 * ------------------------------------------------------------------ */
function applyTheme(t) {
  document.documentElement.setAttribute('data-theme', t);
  try { localStorage.setItem('vaultbook.theme', t); } catch(_){}
  const m=document.querySelector('meta[name="theme-color"]');
  if(m) m.setAttribute('content', t==='dark'?'#131316':'#efece5');
}
function initTheme() {
  let t; try { t=localStorage.getItem('vaultbook.theme'); } catch(_){}
  if(!t) t=window.matchMedia('(prefers-color-scheme:dark)').matches?'dark':'light';
  applyTheme(t);
}
function toggleTheme() {
  applyTheme(document.documentElement.getAttribute('data-theme')==='dark'?'light':'dark');
}

/* ------------------------------------------------------------------ *
 * 6. PASSWORD STRENGTH                                                *
 * ------------------------------------------------------------------ */
function scorePassword(pw) {
  if(!pw) return {level:'none',label:'Enter a password'};
  let cats=0;
  if(/[a-z]/.test(pw))cats++;if(/[A-Z]/.test(pw))cats++;
  if(/[0-9]/.test(pw))cats++;if(/[^A-Za-z0-9]/.test(pw))cats++;
  const l=pw.length;
  if(l<6)  return {level:'weak',  label:'Weak — too short'};
  if(l<12&&cats<3) return {level:'weak', label:'Weak'};
  if(l<14&&cats<3) return {level:'fair', label:'Fair'};
  if(l>=12&&cats>=3) return {level:'strong',label:'Strong'};
  return {level:'good',label:'Good'};
}
function updateStrength() {
  const s=scorePassword(el.pwNew.value);
  el.pwStrength.className='pw-strength is-'+s.level;
  el.pwStrength.querySelector('.pw-strength-label').textContent=s.label;
}
function updateMatchHint() {
  const [a,b]=[el.pwNew.value,el.pwConfirm.value];
  if(!b){el.pwMatchHint.textContent='';el.pwMatchHint.className='field-hint';return;}
  if(a===b){el.pwMatchHint.textContent='Passwords match';el.pwMatchHint.className='field-hint is-success';}
  else     {el.pwMatchHint.textContent='Passwords do not match';el.pwMatchHint.className='field-hint is-error';}
}

/* ------------------------------------------------------------------ *
 * 7. CRYPTO                                                           *
 * ------------------------------------------------------------------ */
async function deriveKey(password, salt) {
  const bk = await crypto.subtle.importKey('raw',textEnc.encode(password),'PBKDF2',false,['deriveKey']);
  return crypto.subtle.deriveKey(
    {name:'PBKDF2',salt,iterations:PBKDF2_ITERS,hash:'SHA-256'},
    bk, {name:'AES-GCM',length:KEY_BITS}, false, ['encrypt','decrypt']
  );
}
async function encryptPayload(plaintext, password) {
  const salt=randomBytes(SALT_BYTES), iv=randomBytes(IV_BYTES);
  const key=await deriveKey(password,salt);
  const ct=new Uint8Array(await crypto.subtle.encrypt({name:'AES-GCM',iv},key,textEnc.encode(plaintext)));
  return {salt,iv,ciphertext:ct};
}
async function decryptPayload(ciphertext, password, salt, iv) {
  const key=await deriveKey(password,salt);
  return textDec.decode(await crypto.subtle.decrypt({name:'AES-GCM',iv},key,ciphertext));
}

/* ------------------------------------------------------------------ *
 * 8. FILE FORMAT                                                      *
 * ------------------------------------------------------------------ */
async function buildVbkBlob(notebook, password) {
  const payload = SIGNATURE + JSON.stringify(notebook);
  const {salt,iv,ciphertext} = await encryptPayload(payload, password);
  return new Blob([JSON.stringify({
    format:FORMAT_ID, version:FORMAT_VER,
    salt:bytesToB64(salt), iv:bytesToB64(iv), ciphertext:bytesToB64(ciphertext),
  },null,2)], {type:'application/json'});
}
function parseEnvelope(bytes) {
  let obj; try{obj=JSON.parse(textDec.decode(bytes));}catch(_){throw new Error('Not a valid Vaultbook file.');}
  const dec = o=>({salt:b64ToBytes(o.salt),iv:b64ToBytes(o.iv),ciphertext:b64ToBytes(o.ciphertext)});
  if(obj.format===FORMAT_ID&&obj.version===FORMAT_VER) return {kind:'vbk',...dec(obj)};
  if(obj.format===LEGACY_ID&&obj.version===LEGACY_VER) return {kind:'rna',...dec(obj)};
  throw new Error('Unrecognised file format.');
}
async function decryptToNotebook(env, password) {
  let pt;
  try { pt=await decryptPayload(env.ciphertext,password,env.salt,env.iv); }
  catch(_){ throw new Error('Incorrect password or corrupted file.'); }

  if(env.kind==='vbk') {
    if(!pt.startsWith(SIGNATURE)) throw new Error('Incorrect password or corrupted file.');
    let nb; try{nb=JSON.parse(pt.slice(SIGNATURE.length));}catch(_){throw new Error('Notebook data corrupted.');}
    return normalizeNotebook(nb);
  }
  if(env.kind==='rna') {
    if(!pt.startsWith(LEGACY_SIG)) throw new Error('Incorrect password or corrupted file.');
    let lg; try{lg=JSON.parse(pt.slice(LEGACY_SIG.length));}catch(_){throw new Error('Legacy data corrupted.');}
    // Convert old {title,body} format → new block-based format
    const blocks=[];
    if(lg.body&&lg.body.trim()) blocks.push(makeTextBlock(lg.body));
    else blocks.push(makeTextBlock());
    return normalizeNotebook({
      title:lg.title||'',
      blocks,
      createdAt:lg.savedAt||new Date().toISOString(),
      updatedAt:lg.savedAt||new Date().toISOString(),
    });
  }
  throw new Error('Unknown format.');
}
function normalizeNotebook(nb) {
  // Support old v2 format that used {title, body, drawing, images[]} shape
  let blocks = nb.blocks;
  if(!Array.isArray(blocks)) {
    blocks = [];
    if(typeof nb.body==='string'&&nb.body) blocks.push(makeTextBlock(nb.body));
    else blocks.push(makeTextBlock());
    if(typeof nb.drawing==='string'&&nb.drawing)
      blocks.push({id:mkid(),type:'draw',dataURL:nb.drawing,w:CANVAS_W,h:CANVAS_H});
    if(Array.isArray(nb.images))
      nb.images.forEach(im=>{ if(im&&im.dataURL) blocks.push(makeImageBlock(im.dataURL,im.name)); });
    if(!blocks.length) blocks.push(makeTextBlock());
  }
  return {
    title:     typeof nb.title==='string'?nb.title:'',
    blocks:    blocks.filter(b=>b&&b.id&&b.type),
    createdAt: nb.createdAt||new Date().toISOString(),
    updatedAt: nb.updatedAt||new Date().toISOString(),
  };
}

/* ------------------------------------------------------------------ *
 * 9. DOCUMENT MODEL — load & sync                                     *
 * ------------------------------------------------------------------ */
function loadNotebookIntoEditor(nb) {
  state.notebook = nb;
  state.drawStates = {};
  el.editorTitle.value = nb.title;
  el.docBody.innerHTML = '';
  // Ensure there's always at least one text block to type into
  if(!nb.blocks.length) nb.blocks.push(makeTextBlock());
  nb.blocks.forEach(block => appendBlockDOM(block));
  refreshStats();
  markSaved();
}

/**
 * Walk the DOM and sync every block's current value back into
 * state.notebook.blocks[]. Also snapshots canvas dataURLs.
 */
function syncEditorIntoState() {
  if(!state.notebook) return;
  state.notebook.title = el.editorTitle.value;
  const domBlocks = Array.from(el.docBody.querySelectorAll('[data-block-id]'));
  const synced = [];
  domBlocks.forEach(el_block => {
    const id = el_block.dataset.blockId;
    const type = el_block.dataset.blockType;
    if(type==='text') {
      const ta = el_block.querySelector('textarea');
      synced.push({id, type:'text', content: ta ? ta.value : ''});
    } else if(type==='draw') {
      const ds = state.drawStates[id];
      const canvas = el_block.querySelector('canvas');
      let dataURL = null;
      if(ds && canvas && !isCanvasBlank(canvas, ds.ctx)) {
        dataURL = canvas.toDataURL('image/png');
      }
      synced.push({id, type:'draw', dataURL, w:CANVAS_W, h:CANVAS_H});
    } else if(type==='image') {
      // image blocks carry their data in the block state
      const existing = state.notebook.blocks.find(b=>b.id===id);
      if(existing) synced.push({...existing});
    }
  });
  state.notebook.blocks = synced.length ? synced : [makeTextBlock()];
  state.notebook.updatedAt = new Date().toISOString();
}

/* ------------------------------------------------------------------ *
 * 10. BLOCK: TEXT                                                     *
 * ------------------------------------------------------------------ */
function appendBlockDOM(block) {
  if(block.type==='text')  renderTextBlock(block);
  if(block.type==='draw')  renderDrawBlock(block);
  if(block.type==='image') renderImageBlock(block);
}

function renderTextBlock(block) {
  const wrap = document.createElement('div');
  wrap.className = 'block-text';
  wrap.dataset.blockId = block.id;
  wrap.dataset.blockType = 'text';

  const ta = document.createElement('textarea');
  ta.value = block.content || '';
  ta.placeholder = 'Start writing here…';
  ta.spellcheck = true;
  // autoGrow after paint so scrollHeight is measured correctly
  requestAnimationFrame(() => autoGrow(ta));
  ta.addEventListener('input', () => { autoGrow(ta); refreshStats(); markDirty(); });
  wrap.appendChild(ta);
  el.docBody.appendChild(wrap);
  return wrap;
}

function autoGrow(ta) {
  ta.style.height = '0';
  const minH = parseInt(getComputedStyle(ta).minHeight, 10) || 64;
  ta.style.height = Math.max(minH, ta.scrollHeight + 2) + 'px';
}

/* ------------------------------------------------------------------ *
 * 11. BLOCK: DRAW                                                     *
 * ------------------------------------------------------------------ */
function renderDrawBlock(block) {
  const wrap = document.createElement('div');
  wrap.className = 'block-draw';
  wrap.dataset.blockId = block.id;
  wrap.dataset.blockType = 'draw';

  // Clone toolbar from template
  const tplContent = el.drawToolbarTpl.content.cloneNode(true);
  const toolbar = tplContent.querySelector('.draw-toolbar');
  wrap.appendChild(toolbar);

  const canvasWrap = document.createElement('div');
  canvasWrap.className = 'canvas-wrap';
  const canvas = document.createElement('canvas');
  canvas.width = CANVAS_W;
  canvas.height = CANVAS_H;
  canvas.setAttribute('aria-label','Drawing canvas');
  canvasWrap.appendChild(canvas);
  wrap.appendChild(canvasWrap);

  el.docBody.appendChild(wrap);

  // Initialise per-block draw state
  const ds = {
    ctx:        canvas.getContext('2d',{willReadFrequently:false}),
    tool:       'brush',
    color:      '#1e1c17',
    size:       3,
    isDrawing:  false,
    lastX:      0,
    lastY:      0,
    undoStack:  [],
    redoStack:  [],
  };
  state.drawStates[block.id] = ds;

  // White fill
  ds.ctx.lineCap='round'; ds.ctx.lineJoin='round';
  ds.ctx.fillStyle='#ffffff'; ds.ctx.fillRect(0,0,CANVAS_W,CANVAS_H);

  // Load existing drawing
  if(block.dataURL) {
    const img=new Image();
    img.onload=()=>{ ds.ctx.drawImage(img,0,0,CANVAS_W,CANVAS_H); pushUndoFor(block.id,canvas); };
    img.src=block.dataURL;
  } else {
    pushUndoFor(block.id,canvas);
  }

  bindToolbar(toolbar, block.id, canvas, ds, wrap);
  bindCanvas(canvas, block.id, ds);
  return wrap;
}

function bindToolbar(toolbar, blockId, canvas, ds, wrap) {
  // Tool buttons
  toolbar.querySelectorAll('.tool-btn[data-tool]').forEach(btn => {
    btn.addEventListener('click', () => {
      toolbar.querySelectorAll('.tool-btn[data-tool]').forEach(b=>{b.classList.remove('is-active');b.setAttribute('aria-checked','false');});
      btn.classList.add('is-active'); btn.setAttribute('aria-checked','true');
      ds.tool = btn.dataset.tool;
    });
  });
  // Colors
  toolbar.querySelectorAll('.color-swatch').forEach(sw => {
    sw.addEventListener('click', () => {
      toolbar.querySelectorAll('.color-swatch').forEach(s=>s.classList.remove('is-active'));
      sw.classList.add('is-active');
      ds.color = sw.dataset.color;
      if(ds.tool==='eraser') {
        const brushBtn=toolbar.querySelector('.tool-btn[data-tool="brush"]');
        if(brushBtn) brushBtn.click();
      }
    });
  });
  // Size slider
  const sizeInput = toolbar.querySelector('.brush-size');
  const sizeLabel = toolbar.querySelector('.size-label');
  sizeInput.addEventListener('input', () => {
    ds.size = parseInt(sizeInput.value,10)||1;
    sizeLabel.textContent = String(ds.size);
  });
  // Undo / redo
  const btnUndo = toolbar.querySelector('.btn-undo');
  const btnRedo = toolbar.querySelector('.btn-redo');
  toolbar.querySelector('.btn-undo').addEventListener('click', ()=>doUndoFor(blockId,canvas,ds,btnUndo,btnRedo));
  toolbar.querySelector('.btn-redo').addEventListener('click', ()=>doRedoFor(blockId,canvas,ds,btnUndo,btnRedo));
  // Clear
  toolbar.querySelector('.btn-clear-canvas').addEventListener('click', () => {
    if(!window.confirm('Clear this drawing?')) return;
    ds.ctx.fillStyle='#ffffff'; ds.ctx.fillRect(0,0,CANVAS_W,CANVAS_H);
    pushUndoFor(blockId,canvas); markDirty();
    updateUndoUI(blockId, btnUndo, btnRedo);
  });
  // Remove block
  toolbar.querySelector('.btn-remove-block').addEventListener('click', () => {
    if(!window.confirm('Remove this drawing block?')) return;
    delete state.drawStates[blockId];
    wrap.remove();
    markDirty();
  });
}

function bindCanvas(canvas, blockId, ds) {
  const getPos = e => {
    const r=canvas.getBoundingClientRect();
    const scX=canvas.width/r.width, scY=canvas.height/r.height;
    const src=(e.touches&&e.touches[0])||e;
    return {x:(src.clientX-r.left)*scX, y:(src.clientY-r.top)*scY};
  };
  const start = e => {
    e.preventDefault();
    const p=getPos(e); ds.isDrawing=true; ds.lastX=p.x; ds.lastY=p.y;
    ds.ctx.beginPath();
    ds.ctx.fillStyle=ds.tool==='eraser'?'#ffffff':ds.color;
    ds.ctx.arc(p.x,p.y,ds.size/2,0,Math.PI*2); ds.ctx.fill();
  };
  const move = e => {
    if(!ds.isDrawing) return; e.preventDefault();
    const p=getPos(e);
    ds.ctx.beginPath();
    ds.ctx.strokeStyle=ds.tool==='eraser'?'#ffffff':ds.color;
    ds.ctx.lineWidth=ds.size;
    ds.ctx.moveTo(ds.lastX,ds.lastY); ds.ctx.lineTo(p.x,p.y); ds.ctx.stroke();
    ds.lastX=p.x; ds.lastY=p.y;
  };
  const end = () => {
    if(!ds.isDrawing) return; ds.isDrawing=false;
    pushUndoFor(blockId, canvas); markDirty();
  };
  canvas.addEventListener('mousedown',start);
  canvas.addEventListener('mousemove',move);
  window.addEventListener('mouseup',end);
  canvas.addEventListener('mouseleave',end);
  canvas.addEventListener('touchstart',start,{passive:false});
  canvas.addEventListener('touchmove',move,{passive:false});
  canvas.addEventListener('touchend',end);
}

function pushUndoFor(blockId, canvas) {
  const ds=state.drawStates[blockId]; if(!ds) return;
  try {
    ds.undoStack.push(canvas.toDataURL('image/png'));
    if(ds.undoStack.length>UNDO_LIMIT) ds.undoStack.shift();
    ds.redoStack=[];
  } catch(_){}
}
function doUndoFor(blockId, canvas, ds, btnUndo, btnRedo) {
  if(ds.undoStack.length<=1) return;
  ds.redoStack.push(ds.undoStack.pop());
  restoreCanvas(canvas, ds.ctx, ds.undoStack[ds.undoStack.length-1]);
  markDirty(); updateUndoUI(blockId, btnUndo, btnRedo);
}
function doRedoFor(blockId, canvas, ds, btnUndo, btnRedo) {
  if(!ds.redoStack.length) return;
  const url=ds.redoStack.pop(); ds.undoStack.push(url);
  restoreCanvas(canvas, ds.ctx, url);
  markDirty(); updateUndoUI(blockId, btnUndo, btnRedo);
}
function restoreCanvas(canvas, ctx, url) {
  const img=new Image();
  img.onload=()=>{ ctx.clearRect(0,0,canvas.width,canvas.height); ctx.drawImage(img,0,0); };
  img.src=url;
}
function updateUndoUI(blockId, btnUndo, btnRedo) {
  const ds=state.drawStates[blockId]; if(!ds) return;
  btnUndo.disabled=ds.undoStack.length<=1;
  btnRedo.disabled=ds.redoStack.length===0;
}
function isCanvasBlank(canvas, ctx) {
  try {
    const {data}=ctx.getImageData(0,0,canvas.width,canvas.height);
    for(let i=0;i<data.length;i+=4) if(data[i]!==255||data[i+1]!==255||data[i+2]!==255) return false;
    return true;
  } catch(_){ return false; }
}

/* ------------------------------------------------------------------ *
 * 12. BLOCK: IMAGE                                                    *
 * ------------------------------------------------------------------ */
function renderImageBlock(block) {
  const wrap = document.createElement('div');
  wrap.className = 'block-image';
  wrap.dataset.blockId = block.id;
  wrap.dataset.blockType = 'image';

  const img = document.createElement('img');
  img.src = block.dataURL;
  img.alt = block.name||'Attached image';
  img.style.cursor='zoom-in';
  img.addEventListener('click', () => openImageModal(block.id, block.dataURL, block.name));
  wrap.appendChild(img);

  const bar = document.createElement('div');
  bar.className = 'block-image-bar';
  bar.innerHTML = `<span>${block.name||'image'}</span>
    <button type="button">
      <svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 6 6 18M6 6l12 12"/></svg>
      Remove
    </button>`;
  bar.querySelector('button').addEventListener('click', () => {
    if(!window.confirm('Remove this image?')) return;
    wrap.remove(); markDirty();
  });
  wrap.appendChild(bar);
  el.docBody.appendChild(wrap);
  return wrap;
}

/* Insert draw/image block after the last focused text block */
function insertBlockAfterFocused(block) {
  // Find the currently focused/last text block element
  const allTextBlocks = Array.from(el.docBody.querySelectorAll('[data-block-type="text"]'));
  const focused = allTextBlocks.find(b => b.contains(document.activeElement)) || allTextBlocks[allTextBlocks.length-1];

  // Add block data to notebook
  if(!state.notebook.blocks) state.notebook.blocks=[];

  // Find position in notebook.blocks after the focused text block
  let insertAfterEl = focused || null;

  // Add a new text block after the inserted media block (to keep writing)
  const newTextBlock = makeTextBlock();

  if(block.type==='draw') {
    state.notebook.blocks.push(block);
    state.notebook.blocks.push(newTextBlock);
    if(insertAfterEl) {
      const drawWrap = renderDrawBlock(block);
      const textWrap = renderTextBlock(newTextBlock);
      insertAfterEl.after(drawWrap);
      drawWrap.after(textWrap);
      drawWrap.querySelector('canvas').scrollIntoView({behavior:'smooth',block:'nearest'});
    } else {
      renderDrawBlock(block);
      renderTextBlock(newTextBlock);
    }
  } else if(block.type==='image') {
    state.notebook.blocks.push(block);
    state.notebook.blocks.push(newTextBlock);
    if(insertAfterEl) {
      const imgWrap = renderImageBlock(block);
      const textWrap = renderTextBlock(newTextBlock);
      insertAfterEl.after(imgWrap);
      imgWrap.after(textWrap);
      imgWrap.scrollIntoView({behavior:'smooth',block:'nearest'});
    } else {
      renderImageBlock(block);
      renderTextBlock(newTextBlock);
    }
    // focus the new text block
    setTimeout(()=>{ const ta=el.docBody.lastElementChild&&el.docBody.lastElementChild.querySelector('textarea'); if(ta)ta.focus(); },60);
  }
  markDirty();
}

/* ------------------------------------------------------------------ *
 * 13. STATS                                                           *
 * ------------------------------------------------------------------ */
function refreshStats() {
  let text='';
  el.docBody.querySelectorAll('[data-block-type="text"] textarea').forEach(ta=>{ text+=' '+ta.value; });
  text=text.trim();
  const words=text?text.split(/\s+/).length:0;
  const chars=text.length;
  const mins=Math.max(1,Math.round(words/220));
  el.statWords.textContent=words.toLocaleString();
  el.statChars.textContent=chars.toLocaleString();
  el.statRead.textContent=words===0?'<1 min':(mins===1?'~1 min':'~'+mins+' min');
}

/* ------------------------------------------------------------------ *
 * 14. DIRTY / SAVE INDICATOR                                          *
 * ------------------------------------------------------------------ */
function markDirty() {
  state.dirty=true;
  updateSaveIndicator();
  clearTimeout(state.autosaveTimer);
  state.autosaveTimer=setTimeout(syncEditorIntoState,AUTOSAVE_MS);
}
function markSaved() {
  state.dirty=false;
  updateSaveIndicator();
}
function updateSaveIndicator() {
  if(!state.notebook){el.saveIndicator.textContent='';return;}
  if(state.dirty){
    el.saveIndicator.textContent='Unsaved';
    el.saveIndicator.className='save-indicator is-unsaved';
  } else {
    el.saveIndicator.textContent='Saved';
    el.saveIndicator.className='save-indicator is-saved';
  }
}

/* ------------------------------------------------------------------ *
 * 15. PANIC LOCK                                                      *
 * ------------------------------------------------------------------ */
async function doPanicLock() {
  if(!state.notebook||!state.password) return;
  syncEditorIntoState();
  try {
    const {salt,iv,ciphertext}=await encryptPayload(SIGNATURE+JSON.stringify(state.notebook),state.password);
    state.panicVault={salt,iv,ciphertext};
  } catch(e) { toast('Panic lock failed.','error'); return; }

  state.notebook=null; state.password=null; state.dirty=false;
  state.drawStates={};
  clearTimeout(state.autosaveTimer);
  el.editorTitle.value=''; el.docBody.innerHTML='';
  refreshStats(); updateSaveIndicator();

  el.panicStatus.textContent=''; el.panicStatus.className='status-line';
  el.panicPassword.value='';
  el.panicOverlay.hidden=false; el.panicOverlay.setAttribute('aria-hidden','false');
  setTimeout(()=>el.panicPassword.focus(),50);
}
async function doPanicUnlock(e) {
  e&&e.preventDefault();
  if(!state.panicVault){hidePanic();return;}
  const pw=el.panicPassword.value; if(!pw) return;
  el.panicStatus.textContent='Unlocking…'; el.panicStatus.className='status-line info';
  try {
    const pt=await decryptPayload(state.panicVault.ciphertext,pw,state.panicVault.salt,state.panicVault.iv);
    if(!pt.startsWith(SIGNATURE)) throw new Error('bad sig');
    const nb=normalizeNotebook(JSON.parse(pt.slice(SIGNATURE.length)));
    state.password=pw; state.panicVault=null; el.panicPassword.value='';
    loadNotebookIntoEditor(nb);
    hidePanic();
    toast('Vaultbook restored.','success');
  } catch(_) {
    el.panicStatus.textContent='Incorrect password.';
    el.panicStatus.className='status-line error';
    el.panicPassword.select();
  }
}
function hidePanic() {
  el.panicOverlay.hidden=true;
  el.panicOverlay.setAttribute('aria-hidden','true');
}

/* ------------------------------------------------------------------ *
 * 16. SAVE                                                            *
 * ------------------------------------------------------------------ */
async function doSave() {
  if(!state.notebook||!state.password) return;
  syncEditorIntoState();
  try {
    el.saveIndicator.textContent='Encrypting…'; el.saveIndicator.className='save-indicator';
    const blob=await buildVbkBlob(state.notebook,state.password);
    const fname=sanitizeFilename(state.notebook.title||'Untitled')+'.vbk';
    downloadBlob(blob,fname);
    state.isImportedLegacy=false;
    el.importNotice.hidden=true;
    markSaved();
    toast('Saved: '+fname,'success');
  } catch(e) { console.error(e); toast('Save failed.','error'); updateSaveIndicator(); }
}

/* ------------------------------------------------------------------ *
 * 17. UNLOCK FLOW                                                     *
 * ------------------------------------------------------------------ */
function bindOpenScreen() {
  el.btnBrowseFile.addEventListener('click',()=>el.fileInput.click());
  el.dropzone.addEventListener('click',()=>el.fileInput.click());
  el.dropzone.addEventListener('keydown',e=>{ if(e.key==='Enter'||e.key===' '){e.preventDefault();el.fileInput.click();} });
  el.fileInput.addEventListener('change',e=>{ const f=e.target.files&&e.target.files[0]; if(f) acceptFile(f); });
  ['dragenter','dragover'].forEach(ev=>el.dropzone.addEventListener(ev,e=>{e.preventDefault();el.dropzone.classList.add('is-dragover');}));
  ['dragleave','drop'].forEach(ev=>el.dropzone.addEventListener(ev,e=>{e.preventDefault();el.dropzone.classList.remove('is-dragover');}));
  el.dropzone.addEventListener('drop',e=>{ const f=e.dataTransfer&&e.dataTransfer.files&&e.dataTransfer.files[0]; if(f) acceptFile(f); });
  el.unlockForm.addEventListener('submit',doUnlock);
}
async function acceptFile(file) {
  if(!/\.(vbk|rna)$/i.test(file.name||'')){ toast('Please choose a .vbk or .rna file.','error'); return; }
  try {
    const buf=new Uint8Array(await file.arrayBuffer());
    const env=parseEnvelope(buf);
    state.pendingFile=buf; state.pendingFormat=env.kind;
    el.dzFilename.textContent=(env.kind==='rna'?'Legacy file: ':'Vaultbook: ')+file.name;
    el.unlockForm.hidden=false;
    el.unlockStatus.textContent=''; el.unlockStatus.className='status-line';
    setTimeout(()=>el.unlockPassword.focus(),50);
  } catch(e) { el.unlockForm.hidden=true; toast(e.message,'error'); }
}
async function doUnlock(e) {
  e.preventDefault(); if(!state.pendingFile) return;
  const pw=el.unlockPassword.value; if(!pw) return;
  el.unlockStatus.textContent='Decrypting…'; el.unlockStatus.className='status-line info';
  try {
    const env=parseEnvelope(state.pendingFile);
    const nb=await decryptToNotebook(env,pw);
    state.password=pw; state.isImportedLegacy=(env.kind==='rna');
    state.pendingFile=null; el.unlockPassword.value='';
    showScreen('editor');
    loadNotebookIntoEditor(nb);
    el.importNotice.hidden=!state.isImportedLegacy;
    toast(state.isImportedLegacy?'Legacy file imported. Save to convert.':'Vaultbook unlocked.','success');
  } catch(e) {
    el.unlockStatus.textContent=e.message||'Incorrect password.';
    el.unlockStatus.className='status-line error';
    el.unlockPassword.select();
  }
}

/* ------------------------------------------------------------------ *
 * 18. IMAGE MODAL                                                     *
 * ------------------------------------------------------------------ */
function openImageModal(blockId, dataURL, name) {
  state.modalBlockId=blockId;
  el.modalImg.src=dataURL; el.modalImg.alt=name||'';
  el.imageModal.hidden=false; el.imageModal.setAttribute('aria-hidden','false');
}
function closeImageModal() {
  el.imageModal.hidden=true; el.imageModal.setAttribute('aria-hidden','true');
  el.modalImg.src=''; state.modalBlockId=null;
}
function bindModal() {
  document.querySelectorAll('[data-modal-close]').forEach(x=>x.addEventListener('click',closeImageModal));
  el.btnRemoveImage.addEventListener('click',()=>{
    if(!state.modalBlockId) return;
    const wrap=el.docBody.querySelector(`[data-block-id="${state.modalBlockId}"]`);
    if(wrap) wrap.remove();
    markDirty(); closeImageModal(); toast('Image removed.');
  });
  document.addEventListener('keydown',e=>{ if(e.key==='Escape'&&!el.imageModal.hidden) closeImageModal(); });
}

/* ------------------------------------------------------------------ *
 * 19. EXPORTS                                                         *
 * ------------------------------------------------------------------ */
async function exportPDF() {
  if(!state.notebook) return;
  syncEditorIntoState();
  toast('Building PDF…');
  try {
    const {jsPDF}=window.jspdf;
    const doc=new jsPDF({unit:'pt',format:'a4',compress:true});
    const pageW=doc.internal.pageSize.getWidth();
    const pageH=doc.internal.pageSize.getHeight();
    const margin=54, contentW=pageW-margin*2;
    let y=margin;

    const title=state.notebook.title||'Untitled Vaultbook';
    doc.setFont('helvetica','bold'); doc.setFontSize(22);
    const tLines=doc.splitTextToSize(title,contentW);
    doc.text(tLines,margin,y+18); y+=18*tLines.length+10;
    doc.setFont('helvetica','normal'); doc.setFontSize(9); doc.setTextColor(120);
    doc.text('Exported from Vaultbook · '+new Date().toLocaleString(),margin,y);
    y+=16; doc.setDrawColor(210); doc.line(margin,y,pageW-margin,y); y+=18;
    doc.setTextColor(30);

    for(const block of state.notebook.blocks) {
      if(block.type==='text'&&block.content&&block.content.trim()) {
        doc.setFont('helvetica','normal'); doc.setFontSize(11);
        const lines=doc.splitTextToSize(block.content,contentW);
        for(const line of lines) {
          if(y>pageH-margin){doc.addPage();y=margin;}
          doc.text(line,margin,y); y+=15;
        }
        y+=8;
      } else if(block.type==='draw'&&block.dataURL) {
        const iw=contentW, ih=iw*(CANVAS_H/CANVAS_W);
        if(y+ih+30>pageH-margin){doc.addPage();y=margin;}
        doc.setFont('helvetica','bold'); doc.setFontSize(10);
        doc.text('Sketch',margin,y); y+=10;
        doc.addImage(block.dataURL,'PNG',margin,y,iw,ih); y+=ih+16;
      } else if(block.type==='image'&&block.dataURL) {
        const dim=await getImageSize(block.dataURL);
        let iw=dim.w, ih=dim.h;
        if(iw>contentW){ih=ih*(contentW/iw);iw=contentW;}
        const avail=pageH-margin-y-20;
        if(ih>avail){
          if(ih>pageH-margin*2){iw=iw*((pageH-margin*2)/ih);ih=pageH-margin*2;}
          doc.addPage();y=margin;
        }
        const fmt=/^data:image\/(png|jpe?g|webp);/i.exec(block.dataURL);
        const type=fmt?fmt[1].toUpperCase().replace('JPG','JPEG').replace('JPEG','JPEG'):'PNG';
        try{doc.addImage(block.dataURL,type,margin,y,iw,ih);}catch(_){}
        y+=ih+14;
      }
    }

    const fname=sanitizeFilename(title)+'.pdf';
    doc.save(fname);
    toast('PDF saved: '+fname,'success');
  } catch(e) { console.error(e); toast('PDF export failed.','error'); }
}
function getImageSize(dataURL) {
  return new Promise(res=>{ const img=new Image(); img.onload=()=>res({w:img.naturalWidth,h:img.naturalHeight}); img.onerror=()=>res({w:400,h:300}); img.src=dataURL; });
}
function exportTXT() {
  if(!state.notebook) return;
  syncEditorIntoState();
  const hasMedia=state.notebook.blocks.some(b=>b.type!=='text');
  if(hasMedia&&!window.confirm('Drawings and images will not be included in the TXT. Continue?')) return;
  const parts=[];
  parts.push(state.notebook.title||'Untitled Vaultbook');
  parts.push('='.repeat(Math.min(60,(state.notebook.title||'Untitled Vaultbook').length)));
  parts.push('');
  state.notebook.blocks.forEach(b=>{ if(b.type==='text') parts.push(b.content||''); });
  parts.push(''); parts.push('---');
  parts.push('Exported from Vaultbook · '+new Date().toLocaleString());
  const blob=new Blob([parts.join('\n')],{type:'text/plain;charset=utf-8'});
  const fname=sanitizeFilename(state.notebook.title||'Untitled')+'.txt';
  downloadBlob(blob,fname);
  toast('Text saved: '+fname,'success');
}

/* ------------------------------------------------------------------ *
 * 20. KEYBOARD SHORTCUTS                                              *
 * ------------------------------------------------------------------ */
function bindShortcuts() {
  document.addEventListener('keydown', e => {
    const mod=e.ctrlKey||e.metaKey;
    if(mod&&(e.key==='d'||e.key==='D')){e.preventDefault();toggleTheme();return;}
    if(state.currentScreen!=='editor'||!state.notebook) return;
    if(mod&&(e.key==='s'||e.key==='S')){e.preventDefault();doSave();return;}
    if(mod&&(e.key==='l'||e.key==='L')){e.preventDefault();doPanicLock();return;}
  });
}

/* ------------------------------------------------------------------ *
 * 21. INIT                                                            *
 * ------------------------------------------------------------------ */
function bindHome() {
  el.btnNew.addEventListener('click',()=>{
    resetPwSetup(); showScreen('password'); setTimeout(()=>el.pwNew.focus(),50);
  });
  el.btnOpen.addEventListener('click',()=>{ resetOpenScreen(); showScreen('open'); });
}
function resetPwSetup() {
  el.pwSetupForm.reset();
  el.pwStrength.className='pw-strength';
  el.pwStrength.querySelector('.pw-strength-label').textContent='Enter a password';
  el.pwMatchHint.textContent=''; el.pwMatchHint.className='field-hint';
  el.pwSetupStatus.textContent=''; el.pwSetupStatus.className='status-line';
}
function bindPasswordSetup() {
  el.pwNew.addEventListener('input',()=>{updateStrength();updateMatchHint();});
  el.pwConfirm.addEventListener('input',updateMatchHint);
  el.pwSetupForm.addEventListener('submit',e=>{
    e.preventDefault();
    const [a,b]=[el.pwNew.value,el.pwConfirm.value];
    el.pwSetupStatus.className='status-line'; el.pwSetupStatus.textContent='';
    if(!a){el.pwSetupStatus.textContent='Please enter a password.';el.pwSetupStatus.className='status-line error';return;}
    if(a.length<4){el.pwSetupStatus.textContent='Too short — use at least 4 characters.';el.pwSetupStatus.className='status-line error';return;}
    if(a!==b){el.pwSetupStatus.textContent='Passwords do not match.';el.pwSetupStatus.className='status-line error';return;}
    state.password=a; state.notebook=makeEmptyNotebook(); state.isImportedLegacy=false;
    el.pwNew.value=''; el.pwConfirm.value='';
    showScreen('editor');
    loadNotebookIntoEditor(state.notebook);
    setTimeout(()=>{ const ta=el.docBody.querySelector('textarea'); if(ta)ta.focus(); },80);
    toast('New Vaultbook ready. Start writing.','success');
  });
}
function bindEditorBar() {
  el.btnEditorHome.addEventListener('click',()=>goHome());
  el.btnSave.addEventListener('click',doSave);
  el.btnPanic.addEventListener('click',doPanicLock);
  el.themeToggle.addEventListener('click',toggleTheme);
  el.btnInsertDraw.addEventListener('click',()=>{
    const block=makeDrawBlock();
    insertBlockAfterFocused(block);
  });
  el.btnInsertImage.addEventListener('click',()=>el.imageInput.click());
  el.imageInput.addEventListener('change',async e=>{
    const file=e.target.files&&e.target.files[0]; el.imageInput.value='';
    if(!file) return;
    if(!file.type.startsWith('image/')){toast('Not a valid image.','error');return;}
    if(file.size>5*1024*1024&&!window.confirm(`Large image (${Math.round(file.size/1024/1024)} MB). Continue?`)) return;
    const dataURL=await new Promise((res,rej)=>{const fr=new FileReader();fr.onload=()=>res(fr.result);fr.onerror=()=>rej(fr.error);fr.readAsDataURL(file);}).catch(()=>null);
    if(!dataURL){toast('Could not read image.','error');return;}
    const block=makeImageBlock(dataURL,file.name);
    insertBlockAfterFocused(block);
    toast('Image inserted.');
  });
  // export menu
  el.btnExportMenu.addEventListener('click',e=>{
    e.stopPropagation();
    const open=!el.exportMenu.hidden;
    el.exportMenu.hidden=open;
    el.btnExportMenu.setAttribute('aria-expanded',String(!open));
  });
  document.addEventListener('click',()=>{ if(!el.exportMenu.hidden){el.exportMenu.hidden=true;el.btnExportMenu.setAttribute('aria-expanded','false');} });
  el.exportMenu.addEventListener('click',e=>{
    const btn=e.target.closest('.menu-item'); if(!btn) return;
    if(btn.dataset.action==='export-pdf') exportPDF();
    if(btn.dataset.action==='export-txt') exportTXT();
  });
  // title
  el.editorTitle.addEventListener('input',markDirty);
}
function bindGlobal() {
  document.querySelectorAll('[data-goto="home"]').forEach(b=>b.addEventListener('click',()=>goHome({confirm:false})));
  document.addEventListener('click',e=>{
    const t=e.target.closest('.pw-toggle'); if(!t) return;
    const inp=document.getElementById(t.dataset.target); if(!inp) return;
    inp.type=inp.type==='password'?'text':'password';
  });
}
function bindPanic() {
  el.panicForm.addEventListener('submit',doPanicUnlock);
  el.btnPanicDiscard.addEventListener('click',()=>{
    if(!window.confirm("Discard and go home? If you didn't save, notebook contents will be lost.")) return;
    state.panicVault=null; hidePanic(); goHome({confirm:false});
  });
}

function init() {
  initTheme();
  bindGlobal();
  bindHome();
  bindPasswordSetup();
  bindOpenScreen();
  bindEditorBar();
  bindModal();
  bindPanic();
  bindShortcuts();
  window.addEventListener('beforeunload',e=>{ if(state.dirty||state.panicVault){e.preventDefault();e.returnValue='';} });
}

if(document.readyState==='loading') document.addEventListener('DOMContentLoaded',init);
else init();
