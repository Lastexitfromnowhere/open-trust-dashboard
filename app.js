'use strict';

/* ═══════════════════════════════════════════════════════════════════════════
   SHARED HELPERS
═══════════════════════════════════════════════════════════════════════════ */

const hexEncode = buf =>
  Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2,'0')).join('');

const base64urlDecode = str => {
  str = str.replace(/-/g,'+').replace(/_/g,'/');
  while (str.length % 4) str += '=';
  return Uint8Array.from(atob(str), c => c.charCodeAt(0));
};

const base64urlEncode = bytes => {
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g,'-').replace(/\//g,'_').replace(/=/g,'');
};

function nowUTC() {
  return new Date().toISOString().replace(/\.\d{3}Z$/, 'Z');
}

function formatSize(n) {
  if (n >= 1e9) return (n/1e9).toFixed(1)+' GB';
  if (n >= 1e6) return (n/1e6).toFixed(1)+' MB';
  if (n >= 1e3) return (n/1e3).toFixed(1)+' KB';
  return n+' B';
}

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

/* ═══════════════════════════════════════════════════════════════════════════
   TAB SWITCHING
═══════════════════════════════════════════════════════════════════════════ */

const tabVerify    = document.getElementById('tabVerify');
const tabSign      = document.getElementById('tabSign');
const tabAttest    = document.getElementById('tabAttest');
const tabRequests  = document.getElementById('tabRequests');
const tabExplore   = document.getElementById('tabExplore');
const verifyTab    = document.getElementById('verifyTab');
const signTab      = document.getElementById('signTab');
const attestTab    = document.getElementById('attestTab');
const requestsTab  = document.getElementById('requestsTab');
const exploreTab   = document.getElementById('exploreTab');

// Requests browse consts — declared here so fetchRequests() (called from switchTab) can access them
const reqRegistryInput   = document.getElementById('reqRegistryInput');
const btnRefreshRequests = document.getElementById('btnRefreshRequests');
const reqSpinner         = document.getElementById('reqSpinner');
const reqBtnText         = document.getElementById('reqBtnText');
const reqList            = document.getElementById('reqList');
const reqEmpty           = document.getElementById('reqEmpty');
const reqError           = document.getElementById('reqError');

let argon2Ready    = false;
let requestsLoaded = false;

tabVerify.addEventListener('click',   () => switchTab('verify'));
tabSign.addEventListener('click',     () => switchTab('sign'));
tabAttest.addEventListener('click',   () => switchTab('attest'));
tabRequests.addEventListener('click', () => switchTab('requests'));
tabExplore.addEventListener('click',  () => switchTab('explore'));

async function switchTab(tab) {
  [verifyTab, signTab, attestTab, requestsTab, exploreTab].forEach(el => el.classList.add('hidden'));
  [tabVerify, tabSign, tabAttest, tabRequests, tabExplore].forEach(el => el.classList.remove('active'));

  if (tab === 'sign') {
    signTab.classList.remove('hidden');
    tabSign.classList.add('active');
  } else if (tab === 'attest') {
    attestTab.classList.remove('hidden');
    tabAttest.classList.add('active');
    if (!argon2Ready) loadArgon2();
  } else if (tab === 'requests') {
    requestsTab.classList.remove('hidden');
    tabRequests.classList.add('active');
    if (!requestsLoaded) { requestsLoaded = true; fetchRequests(); }
  } else if (tab === 'explore') {
    exploreTab.classList.remove('hidden');
    tabExplore.classList.add('active');
  } else {
    verifyTab.classList.remove('hidden');
    tabVerify.classList.add('active');
  }
}

function loadArgon2() {
  return new Promise((resolve, reject) => {
    if (window.argon2) { argon2Ready = true; resolve(); return; }
    const s = document.createElement('script');
    s.src = 'https://cdn.jsdelivr.net/npm/argon2-browser@1.18.0/dist/argon2-bundled.min.js';
    s.onload = () => { argon2Ready = true; resolve(); };
    s.onerror = () => reject(new Error('Failed to load Argon2 library'));
    document.head.appendChild(s);
  });
}

/* ═══════════════════════════════════════════════════════════════════════════
   VERIFY TAB
═══════════════════════════════════════════════════════════════════════════ */

const verifyState = { binaryFile: null, provenanceFile: null, registryOn: false };

const dropZone       = document.getElementById('dropZone');
const fileInput      = document.getElementById('fileInput');
const filesList      = document.getElementById('filesList');
const registryInput  = document.getElementById('registryInput');
const registryToggle = document.getElementById('registryToggle');
const btnVerify      = document.getElementById('btnVerify');
const progressWrap   = document.getElementById('progressWrap');
const progressFill   = document.getElementById('progressFill');
const progressLabel  = document.getElementById('progressLabel');
const results        = document.getElementById('results');
const checksList     = document.getElementById('checksList');
const badgeWrap      = document.getElementById('badgeWrap');

async function readFileAsArrayBuffer(file, onProgress) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onprogress = e => { if (e.lengthComputable && onProgress) onProgress(e.loaded, e.total); };
    reader.onload  = e => resolve(e.target.result);
    reader.onerror = () => reject(reader.error);
    reader.readAsArrayBuffer(file);
  });
}

async function sha256ofBytes(bytes) {
  return hexEncode(await crypto.subtle.digest('SHA-256', bytes));
}

async function detectFileType(file) {
  try {
    const obj = JSON.parse(await file.slice(0, 4096).text());
    if (obj.schema_version && obj.artifact && obj.signature) return 'provenance';
    return 'unknown';
  } catch { return 'binary'; }
}

async function handleFiles(files) {
  for (const file of files) {
    const type = await detectFileType(file);
    if (type === 'provenance') verifyState.provenanceFile = file;
    else verifyState.binaryFile = file;
  }
  renderFilesPills();
  updateVerifyBtn();
}

function renderFilesPills() {
  filesList.innerHTML = '';
  if (verifyState.binaryFile)    filesList.innerHTML += filePill(verifyState.binaryFile, 'binary', '⬡');
  if (verifyState.provenanceFile) filesList.innerHTML += filePill(verifyState.provenanceFile, 'provenance', '📄');
}

function filePill(f, type, icon) {
  return `<div class="file-pill type-${type}"><span class="dot"></span>${icon} ${f.name} <span style="opacity:.5">(${formatSize(f.size)})</span></div>`;
}

function updateVerifyBtn() {
  btnVerify.disabled = !(verifyState.binaryFile && verifyState.provenanceFile);
}

dropZone.addEventListener('dragover', e => { e.preventDefault(); dropZone.classList.add('drag-over'); });
dropZone.addEventListener('dragleave', () => dropZone.classList.remove('drag-over'));
dropZone.addEventListener('drop', e => { e.preventDefault(); dropZone.classList.remove('drag-over'); handleFiles([...e.dataTransfer.files]); });
fileInput.addEventListener('change', () => handleFiles([...fileInput.files]));
registryToggle.addEventListener('click', () => {
  verifyState.registryOn = !verifyState.registryOn;
  registryToggle.classList.toggle('on', verifyState.registryOn);
});

async function hashFile(file) {
  progressWrap.classList.add('visible');
  progressLabel.textContent = 'Computing SHA-256 + SHA-512…';
  progressFill.style.width = '0%';
  const buffer = await readFileAsArrayBuffer(file, (loaded, total) => {
    progressFill.style.width = (loaded / total * 85).toFixed(0) + '%';
    progressLabel.textContent = `Hashing… ${formatSize(loaded)} / ${formatSize(total)}`;
  });
  progressLabel.textContent = 'Finalizing digests…';
  progressFill.style.width = '90%';
  const [s256, s512] = await Promise.all([
    crypto.subtle.digest('SHA-256', buffer),
    crypto.subtle.digest('SHA-512', buffer),
  ]);
  progressFill.style.width = '100%';
  await sleep(200);
  progressWrap.classList.remove('visible');
  return { sha256: hexEncode(s256), sha512: hexEncode(s512) };
}

async function verifyEd25519(pubkeyB64url, payloadStr, sigB64url) {
  try {
    const key = await crypto.subtle.importKey('raw', base64urlDecode(pubkeyB64url), {name:'Ed25519'}, false, ['verify']);
    return await crypto.subtle.verify({name:'Ed25519'}, key, base64urlDecode(sigB64url), new TextEncoder().encode(payloadStr));
  } catch(e) {
    if (e.name === 'NotSupportedError' || e.name === 'DOMException') return null;
    throw e;
  }
}

async function fetchFromGitHub(repo, fingerprint, sha256) {
  const url = `https://api.github.com/repos/${repo}/contents/keys/${fingerprint}/signatures/${sha256}.json`;
  const res = await fetch(url, { headers: { Accept: 'application/vnd.github.v3+json' } });
  if (!res.ok) return null;
  const data = await res.json();
  return JSON.parse(atob(data.content.replace(/\n/g,'')));
}

btnVerify.addEventListener('click', async () => {
  btnVerify.classList.add('loading'); btnVerify.disabled = true;
  results.classList.remove('visible'); checksList.innerHTML = ''; badgeWrap.innerHTML = '';
  try { await runVerification(); }
  catch(err) { addCheck('fail', 'Unexpected error', err.message); }
  finally { btnVerify.classList.remove('loading'); btnVerify.disabled = false; results.classList.add('visible'); }
});

async function runVerification() {
  let prov;
  try { prov = JSON.parse(await verifyState.provenanceFile.text()); }
  catch { addCheck('fail', 'Invalid provenance.json', 'The file could not be parsed as JSON. Make sure you dropped the correct file.'); return; }

  const { sha256, sha512 } = await hashFile(verifyState.binaryFile);

  const sha256ok = sha256 === prov.artifact?.sha256;
  addCheck(sha256ok?'ok':'fail', sha256ok?'SHA-256 integrity verified':'SHA-256 integrity failed',
    sha256ok ? 'The hash matches the one signed by the developer.'
             : 'The binary was modified after signing. Do not install this file.',
    [{ label:'Computed', value:sha256, match:sha256ok }, { label:'Signed', value:prov.artifact?.sha256??'—', match:sha256ok }]);
  if (!sha256ok) { finalizeBadge(prov,0,false); return; }

  const sha512ok = sha512 === prov.artifact?.sha512;
  addCheck(sha512ok?'ok':'fail', sha512ok?'SHA-512 integrity verified':'SHA-512 integrity failed',
    sha512ok ? 'Secondary check passed as well.' : 'SHA-512 hash mismatch — the file is compromised.',
    sha512ok ? [{label:sha512.slice(0,32)+'…',value:'',match:true}] : []);

  let fpOk = false;
  try {
    fpOk = (await sha256ofBytes(base64urlDecode(prov.identity?.pubkey_ed25519??''))) === prov.identity?.pubkey_fingerprint;
    addCheck(fpOk?'ok':'fail', fpOk?'Key fingerprint consistent':'Key fingerprint mismatch',
      fpOk ? 'The public key matches the fingerprint declared in the manifest.'
           : 'The manifest was tampered with — key and fingerprint no longer match.');
  } catch {
    addCheck('fail','Malformed public key','Unable to decode the public key from the manifest.');
    finalizeBadge(prov,0,false); return;
  }

  const sigPayload = `${prov.artifact.sha256}|${prov.artifact.sha512}|${prov.signature?.timestamp}`;
  const sigValid   = await verifyEd25519(prov.identity?.pubkey_ed25519, sigPayload, prov.signature?.value);
  if (sigValid === null) {
    addCheck('warn','Ed25519 signature (not verified)',
      'Your browser does not support Ed25519 via WebCrypto (requires Chrome 113+, Firefox 116+, Safari 17+).\nUse the open-trust CLI for full verification.');
  } else {
    addCheck(sigValid?'ok':'fail', sigValid?'Ed25519 signature valid':'Ed25519 signature INVALID',
      sigValid ? `Signed by ${prov.identity?.display_name??'unknown'} on ${prov.signature?.timestamp??'?'}`
               : 'The cryptographic signature is invalid — the manifest has been forged.\nDo not install this binary.');
    if (!sigValid) { finalizeBadge(prov,0,false); return; }
  }

  const attestations = prov.attestations ?? [];
  const threshold    = prov.trust_chain?.threshold ?? 2;
  let validAtts = 0; const attDetails = [];
  for (const att of attestations) {
    const valid = await verifyEd25519(att.attester_pubkey, `${prov.artifact.sha256}|${att.statement}|${att.timestamp}`, att.signature);
    if (valid === true) validAtts++;
    attDetails.push({...att, valid});
  }
  if (attestations.length === 0) {
    addCheck('warn','No peer attestations','This binary has not yet been validated by peers. Trust level: SELF-SIGNED.');
  } else {
    const ok = validAtts >= threshold;
    addCheck(ok?'ok':'warn',
      ok ? `Attestations verified (${validAtts}/${threshold})` : `Insufficient attestations (${validAtts}/${threshold} required)`,
      ok ? `Trust threshold reached — this artifact is <span style="color:var(--green);font-weight:700">TRUSTED</span>.`
         : `${threshold-validAtts} more peer attestation(s) needed to reach TRUSTED status.`);
  }

  const repo = registryInput.value.trim();
  if (verifyState.registryOn && repo) {
    try {
      const remote = await fetchFromGitHub(repo, prov.identity.pubkey_fingerprint, sha256);
      if (!remote)                          addCheck('warn','Not found in registry',`No published entry in ${repo} for this hash.\nPublish with: open-trust publish --registry git@github.com:${repo}.git`);
      else if (remote.artifact?.sha256 !== sha256) addCheck('fail','Registry mismatch','The hash in the registry does not match the local file. Security alert.');
      else                                  addCheck('ok','Community registry confirmed',`Hash matches the published entry in ${repo}.`);
    } catch(e) { addCheck('warn','Registry unreachable',`Could not contact the GitHub API: ${e.message}`); }
  } else if (verifyState.registryOn && !repo) {
    addCheck('skip','Registry not configured','Enter a GitHub repository URL to enable online verification.');
  }

  finalizeBadge(prov, validAtts, true, attDetails, threshold);
}

function addCheck(status, title, detail, hashes=[]) {
  const icons = {ok:'✓',fail:'✗',warn:'!',skip:'–'};
  const colors = {ok:'var(--green)',fail:'var(--red)',warn:'var(--amber)',skip:'var(--text-muted)'};
  const delay = checksList.children.length * 80;
  const row = document.createElement('div');
  row.className = 'check-row'; row.style.animationDelay = delay+'ms';
  const hashesHTML = hashes.map(h => h.value
    ? `<div style="margin-top:6px;"><span style="font-size:10px;color:var(--text-muted)">${h.label}: </span><code class="hash-value ${h.match?'match':'mismatch'}">${h.value}</code></div>`
    : `<span style="font-size:11px;color:var(--text-muted)">${h.label}</span>`).join('');
  row.innerHTML = `<div class="check-icon ${status}">${icons[status]}</div>
    <div class="check-content">
      <div class="check-title" style="color:${colors[status]}">${title}</div>
      <div class="check-detail">${detail.replace(/\n/g,'<br>')}</div>
      ${hashesHTML}
    </div>`;
  checksList.appendChild(row);
}

function finalizeBadge(prov, validAtts, checksOk, attDetails=[], threshold=2) {
  const name=prov.identity?.display_name??'Unknown', artName=prov.artifact?.name??'',
        artVer=prov.artifact?.version??'', fp=prov.identity?.pubkey_fingerprint??'',
        ts=prov.signature?.timestamp??'', proofs=prov.identity?.social_proofs??[];
  let level,levelLabel,icon;
  if (!checksOk)             { level='unknown'; levelLabel='INVALID';       icon='✗'; }
  else if (validAtts>=threshold) { level='trusted'; levelLabel='TRUSTED';       icon='✓'; }
  else if (validAtts>0)      { level='peer';    levelLabel='PEER-ATTESTED'; icon='◐'; }
  else if (proofs.length>0)  { level='self';    levelLabel='SELF-SIGNED';   icon='◉'; }
  else                       { level='unknown'; levelLabel='UNKNOWN';       icon='?'; }

  const pIcons={github:'🐙',mastodon:'🐘',keybase:'🔑',gitlab:'🦊',twitter:'🐦',x:'✖'};
  const socialHTML = proofs.map(sp=>`<a class="social-chip" href="${sp.proof_url}" target="_blank" rel="noopener"><span class="platform-icon">${pIcons[sp.platform?.toLowerCase()]??'🌐'}</span>${sp.platform} · ${sp.handle}</a>`).join('');
  const attsHTML = attDetails.length===0
    ? '<p style="font-size:11px;color:var(--text-muted)">No attestations.</p>'
    : attDetails.map(att=>`<div class="attestation-item">
        <span class="${att.valid===true?'att-valid':att.valid===false?'att-invalid':''}">${att.valid===true?'✓':att.valid===false?'✗':'~'}</span>
        <span class="att-scope">${att.scope??""}</span>
        <span class="att-statement">${att.statement??""}</span>
        <button class="fp-chip" onclick="openFpModal('${att.attester_fingerprint}',event)" style="font-size:10px;">${att.attester_fingerprint?.slice(0,12)??''}…</button>
      </div>`).join('');

  badgeWrap.innerHTML = `<div class="trust-badge">
    <div class="badge-header ${level}">
      <div class="badge-icon">${level==='trusted'?'🛡️':level==='peer'?'🔍':level==='self'?'🔏':'⚠️'}</div>
      <div class="badge-meta">
        <div class="badge-developer">${name}</div>
        <div class="badge-artifact mono">${artName} ${artVer} · ${ts.slice(0,10)}</div>
      </div>
      <div class="badge-level">${icon} ${levelLabel}</div>
    </div>
    <div class="badge-body">
      ${proofs.length>0?`<div class="badge-section"><div class="badge-section-title">Social identity</div><div class="social-list">${socialHTML}</div></div>`:''}
      <div class="badge-section"><div class="badge-section-title">Peer attestations (${validAtts} / ${threshold} required)</div>${attsHTML}</div>
      <div class="badge-section">
        <div class="badge-section-title">Key fingerprint</div>
        <div class="fp-row"><span class="fp-value mono">${fp}</span><button class="copy-btn" onclick="copyFP('${fp}')">copy</button></div>
        <p style="font-size:11px;color:var(--text-muted);margin-top:6px;">Cross-check this fingerprint against the developer's public profile to confirm their identity.</p>
      </div>
    </div>
  </div>`;
}

function copyFP(fp) {
  navigator.clipboard.writeText(fp).then(() => {
    const btn = document.querySelector('.copy-btn');
    if (btn) { btn.textContent='copied!'; setTimeout(()=>btn.textContent='copy',2000); }
  });
}

// Ed25519 browser support hint
(async () => {
  try { await crypto.subtle.importKey('raw',new Uint8Array(32),{name:'Ed25519'},false,['verify']); }
  catch {
    const hint = document.createElement('p');
    hint.style.cssText='text-align:center;font-size:11px;color:var(--amber);padding:8px 0';
    hint.textContent='⚠ Your browser does not support Ed25519 SubtleCrypto — signature verification will be skipped. Use Chrome 113+, Firefox 116+, or Safari 17+.';
    document.querySelector('.hero')?.appendChild(hint);
  }
})();

/* ═══════════════════════════════════════════════════════════════════════════
   ATTEST TAB
═══════════════════════════════════════════════════════════════════════════ */

const attestState = { keystore: null };

const issueInput        = document.getElementById('issueInput');
const issuePreview      = document.getElementById('issuePreview');
const keyDropZone       = document.getElementById('keyDropZone');
const keyFileInput      = document.getElementById('keyFileInput');
const keyInfo           = document.getElementById('keyInfo');
const keyInfoName       = document.getElementById('keyInfoName');
const keyInfoFp         = document.getElementById('keyInfoFp');
const removeKeyBtn      = document.getElementById('removeKeyBtn');
const orDivider         = document.getElementById('orDivider');
const keygenSection     = document.getElementById('keygenSection');
const btnShowKeygen     = document.getElementById('btnShowKeygen');
const keygenForm        = document.getElementById('keygenForm');
const keygenName        = document.getElementById('keygenName');
const keygenPass        = document.getElementById('keygenPass');
const keygenPassConfirm = document.getElementById('keygenPassConfirm');
const btnGenerate       = document.getElementById('btnGenerate');
const attestStatement   = document.getElementById('attestStatement');
const attestScope       = document.getElementById('attestScope');
const attestPass        = document.getElementById('attestPass');
const attestToken       = document.getElementById('attestToken');
const btnAttest         = document.getElementById('btnAttest');
const attestProgressWrap= document.getElementById('attestProgressWrap');
const attestProgressFill= document.getElementById('attestProgressFill');
const attestProgressLabel=document.getElementById('attestProgressLabel');
const attestResult      = document.getElementById('attestResult');

// ── Issue URL input ───────────────────────────────────────────────────────
function parseIssueURL(url) {
  const m = url.trim().match(/^https:\/\/github\.com\/([^/]+)\/([^/]+)\/issues\/(\d+)/);
  if (!m) return null;
  return { owner: m[1], repo: m[2], number: parseInt(m[3]) };
}

issueInput.addEventListener('input', () => {
  const parsed = parseIssueURL(issueInput.value);
  if (parsed) {
    issuePreview.textContent = `✓ Issue #${parsed.number} in ${parsed.owner}/${parsed.repo}`;
    issuePreview.classList.remove('hidden');
    issuePreview.style.color = 'var(--accent)';
  } else if (issueInput.value.length > 10) {
    issuePreview.textContent = 'Invalid URL — paste a GitHub issue URL';
    issuePreview.classList.remove('hidden');
    issuePreview.style.color = 'var(--red)';
  } else {
    issuePreview.classList.add('hidden');
  }
  updateAttestBtn();
});

// ── Key drag-and-drop ─────────────────────────────────────────────────────
keyDropZone.addEventListener('dragover', e => { e.preventDefault(); keyDropZone.classList.add('drag-over'); });
keyDropZone.addEventListener('dragleave', () => keyDropZone.classList.remove('drag-over'));
keyDropZone.addEventListener('drop', e => { e.preventDefault(); keyDropZone.classList.remove('drag-over'); if(e.dataTransfer.files[0]) loadKeyFile(e.dataTransfer.files[0]); });
keyFileInput.addEventListener('change', () => { if(keyFileInput.files[0]) loadKeyFile(keyFileInput.files[0]); });

async function loadKeyFile(file) {
  try {
    const ks = JSON.parse(await file.text());
    if (ks.algorithm !== 'argon2id+aes256gcm' || !ks.salt || !ks.ciphertext) {
      throw new Error('Not a valid open-trust key file');
    }
    setKeyLoaded(ks, file.name);
  } catch(e) {
    alert('Invalid key file: ' + e.message);
  }
}

function setKeyLoaded(ks, filename) {
  attestState.keystore = ks;
  keyDropZone.classList.add('hidden');
  orDivider.classList.add('hidden');
  keygenSection.classList.add('hidden');
  keyInfo.classList.remove('hidden');
  keyInfoName.textContent = filename || 'Key loaded';
  keyInfoFp.textContent = 'Fingerprint: ' + ks.fingerprint.slice(0,16) + '…';
  updateAttestBtn();
}

removeKeyBtn.addEventListener('click', () => {
  attestState.keystore = null;
  keyInfo.classList.add('hidden');
  keyDropZone.classList.remove('hidden');
  orDivider.classList.remove('hidden');
  keygenSection.classList.remove('hidden');
  keyFileInput.value = '';
  updateAttestBtn();
});

// ── Keygen ────────────────────────────────────────────────────────────────
btnShowKeygen.addEventListener('click', () => {
  keygenForm.classList.toggle('hidden');
  btnShowKeygen.textContent = keygenForm.classList.contains('hidden')
    ? '⊕ Generate a new key'
    : '✕ Cancel';
});

btnGenerate.addEventListener('click', async () => {
  const name        = keygenName.value.trim();
  const pass        = keygenPass.value;
  const passConfirm = keygenPassConfirm.value;
  if (!name)             { alert('Enter a display name'); return; }
  if (!pass)             { alert('Enter a passphrase'); return; }
  if (pass !== passConfirm) { alert('Passphrases do not match'); return; }

  btnGenerate.disabled = true;
  btnGenerate.textContent = 'Generating… (this takes a few seconds)';

  try {
    if (!argon2Ready) await loadArgon2();
    const { keystore } = await generateKeyInBrowser(name, pass);

    // Download
    const blob = new Blob([JSON.stringify(keystore, null, 2)], {type:'application/json'});
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href = url; a.download = 'identity.key.json'; a.click();
    URL.revokeObjectURL(url);

    // Auto-load
    setKeyLoaded(keystore, 'identity.key.json');
    keygenForm.classList.add('hidden');

  } catch(e) {
    alert('Key generation failed: ' + e.message);
  } finally {
    btnGenerate.disabled = false;
    btnGenerate.textContent = '⬇ Generate & Download identity.key.json';
  }
});

// ── Attest button state ───────────────────────────────────────────────────
[issueInput, attestStatement, attestPass, attestToken].forEach(el =>
  el.addEventListener('input', updateAttestBtn));

function updateAttestBtn() {
  btnAttest.disabled = !(
    parseIssueURL(issueInput.value) &&
    attestState.keystore &&
    attestStatement.value.trim().length > 0 &&
    attestPass.value.length > 0 &&
    attestToken.value.trim().length > 0
  );
}

// ── Attest flow ───────────────────────────────────────────────────────────
btnAttest.addEventListener('click', async () => {
  btnAttest.classList.add('loading');
  btnAttest.disabled = true;
  attestResult.classList.add('hidden');
  attestProgressWrap.classList.add('visible');
  attestProgressFill.style.width = '0%';

  try {
    await runAttestation();
  } catch(e) {
    showAttestError(e.message);
  } finally {
    btnAttest.classList.remove('loading');
    btnAttest.disabled = false;
    await sleep(400);
    attestProgressWrap.classList.remove('visible');
    attestProgressFill.style.width = '0%';
  }
});

function setAttestProgress(label, pct) {
  attestProgressLabel.textContent = label;
  attestProgressFill.style.width = pct + '%';
}

async function runAttestation() {
  const token     = attestToken.value.trim();
  const statement = attestStatement.value.trim();
  const scope     = attestScope.value;
  const passphrase= attestPass.value;

  // 1. Fetch provenance.json from GitHub issue
  setAttestProgress('Fetching issue from GitHub…', 15);
  const { provenance, owner, repo, number } = await fetchProvenanceFromIssue(issueInput.value, token);

  // 2. Ensure argon2 is loaded
  setAttestProgress('Loading cryptographic library…', 25);
  if (!argon2Ready) await loadArgon2();

  // 3. Decrypt key
  setAttestProgress('Deriving key (Argon2id)… this takes a few seconds', 40);
  let keyData;
  try {
    keyData = await decryptKeystore(attestState.keystore, passphrase);
  } catch {
    throw new Error('Wrong passphrase or corrupted key file. Please try again.');
  }

  // 4. Guards
  if (keyData.fingerprint === provenance.identity.pubkey_fingerprint) {
    throw new Error('Self-attestation is not allowed. You cannot attest your own binary.');
  }
  const alreadyDone = (provenance.attestations || []).some(a => a.attester_fingerprint === keyData.fingerprint);
  if (alreadyDone) {
    throw new Error('You have already attested this binary with this key.');
  }

  // 5. Sign
  setAttestProgress('Signing attestation with Ed25519…', 70);
  const timestamp = nowUTC();
  const sigBytes  = await signAttestation(keyData.privateKey, provenance.artifact.sha256, statement, timestamp);

  // 6. Build attestation + append
  const attestation = {
    attester_pubkey:      base64urlEncode(keyData.pubkeyBytes),
    attester_fingerprint: keyData.fingerprint,
    statement,
    scope,
    signature:  base64urlEncode(sigBytes),
    timestamp,
  };
  const updated = { ...provenance, attestations: [...(provenance.attestations || []), attestation] };

  // 7. Post comment
  setAttestProgress('Posting attestation to GitHub…', 88);
  const commentURL = await postAttestedComment(owner, repo, number, token, updated, keyData.fingerprint);

  setAttestProgress('Done!', 100);
  showAttestSuccess(owner, repo, number, commentURL, keyData.fingerprint);
}

// ── Crypto helpers ────────────────────────────────────────────────────────

async function decryptKeystore(ks, passphrase) {
  const salt       = base64urlDecode(ks.salt);
  const nonce      = base64urlDecode(ks.nonce);
  const ciphertext = base64urlDecode(ks.ciphertext);

  // Argon2id — same params as CLI (time=3, mem=64MiB, parallelism=4, hashLen=32)
  const argon = await argon2.hash({
    pass: passphrase, salt,
    type: argon2.ArgonType.Argon2id,
    time: 3, mem: 65536, parallelism: 4, hashLen: 32,
  });

  // AES-256-GCM decrypt
  const aesKey = await crypto.subtle.importKey('raw', argon.hash, {name:'AES-GCM'}, false, ['decrypt']);
  const seed   = await crypto.subtle.decrypt({name:'AES-GCM', iv: nonce}, aesKey, ciphertext);

  // Import Ed25519 private key via PKCS8 wrapper (seed at bytes 16-47)
  const pkcs8 = new Uint8Array([
    0x30,0x2e,0x02,0x01,0x00,0x30,0x05,0x06,0x03,0x2b,0x65,0x70,0x04,0x22,0x04,0x20,
    ...new Uint8Array(seed)
  ]);
  const privateKey = await crypto.subtle.importKey('pkcs8', pkcs8, {name:'Ed25519'}, false, ['sign']);

  return { privateKey, pubkeyBytes: base64urlDecode(ks.pubkey), fingerprint: ks.fingerprint };
}

async function signAttestation(privateKey, artifactSHA256, statement, timestamp) {
  const payload = new TextEncoder().encode(`${artifactSHA256}|${statement}|${timestamp}`);
  return new Uint8Array(await crypto.subtle.sign({name:'Ed25519'}, privateKey, payload));
}

async function generateKeyInBrowser(displayName, passphrase) {
  // 1. Generate Ed25519 keypair
  const kp = await crypto.subtle.generateKey({name:'Ed25519'}, true, ['sign','verify']);

  // 2. Export public key (32 bytes raw)
  const pubkeyBytes = new Uint8Array(await crypto.subtle.exportKey('raw', kp.publicKey));

  // 3. Extract seed from PKCS8 (bytes 16-47)
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', kp.privateKey));
  const seed  = pkcs8.slice(16, 48);

  // 4. Fingerprint = hex(SHA-256(pubkey))
  const fingerprint = hexEncode(await crypto.subtle.digest('SHA-256', pubkeyBytes));

  // 5. Encrypt seed: Argon2id → AES-256-GCM
  const salt  = crypto.getRandomValues(new Uint8Array(16));
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const argon = await argon2.hash({
    pass: passphrase, salt,
    type: argon2.ArgonType.Argon2id,
    time: 3, mem: 65536, parallelism: 4, hashLen: 32,
  });
  const aesKey     = await crypto.subtle.importKey('raw', argon.hash, {name:'AES-GCM'}, false, ['encrypt']);
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt({name:'AES-GCM', iv: nonce}, aesKey, seed));

  const keystore = {
    version: '1', algorithm: 'argon2id+aes256gcm',
    salt:        base64urlEncode(salt),
    nonce:       base64urlEncode(nonce),
    ciphertext:  base64urlEncode(ciphertext),
    pubkey:      base64urlEncode(pubkeyBytes),
    fingerprint,
    display_name: displayName,
  };

  return { keystore, fingerprint };
}

// ── GitHub API helpers ────────────────────────────────────────────────────

async function fetchProvenanceFromIssue(issueURL, token) {
  const parsed = parseIssueURL(issueURL);
  if (!parsed) throw new Error('Invalid GitHub issue URL');

  const res = await fetch(
    `https://api.github.com/repos/${parsed.owner}/${parsed.repo}/issues/${parsed.number}`,
    { headers: { Authorization: `token ${token}`, Accept: 'application/vnd.github.v3+json' } }
  );
  if (res.status === 401) throw new Error('Invalid GitHub token (401 Unauthorized)');
  if (res.status === 404) throw new Error('Issue not found — check the URL and your token');
  if (!res.ok) throw new Error(`GitHub API error: ${res.status}`);

  const data  = await res.json();
  const match = data.body && data.body.match(/```json\s*\n([\s\S]*?)\n```/);
  if (!match) throw new Error('No provenance.json found in the issue body');

  let provenance;
  try { provenance = JSON.parse(match[1]); }
  catch(e) { throw new Error('Failed to parse provenance.json from issue: ' + e.message); }
  if (!provenance.artifact || !provenance.identity) throw new Error('The JSON in the issue is not a valid provenance.json');

  return { provenance, owner: parsed.owner, repo: parsed.repo, number: parsed.number };
}

async function postAttestedComment(owner, repo, number, token, updatedProvenance, attesterFp) {
  const provJSON = JSON.stringify(updatedProvenance, null, 2);
  const body =
    `## ✅ Attestation by \`${attesterFp.slice(0,16)}…\`\n\n` +
    `I have reviewed and attested this binary.\n\n` +
    `<details>\n<summary>📄 Updated provenance.json — send this back to the developer</summary>\n\n` +
    '```json\n' + provJSON + '\n```\n\n</details>';

  const res = await fetch(
    `https://api.github.com/repos/${owner}/${repo}/issues/${number}/comments`,
    {
      method: 'POST',
      headers: { Authorization: `token ${token}`, Accept: 'application/vnd.github.v3+json', 'Content-Type': 'application/json' },
      body: JSON.stringify({ body })
    }
  );
  if (!res.ok) throw new Error(`Failed to post comment: ${res.status}`);
  return (await res.json()).html_url;
}

// ── Result display ────────────────────────────────────────────────────────

function showAttestSuccess(owner, repo, number, commentURL, fingerprint) {
  attestResult.classList.remove('hidden');
  attestResult.innerHTML = `
    <div class="attest-success">
      <div class="attest-success-icon">✓</div>
      <div>
        <div class="attest-success-title">Attestation published!</div>
        <div class="attest-success-detail">
          Your signature was computed locally and posted as a comment on issue #${number} in ${owner}/${repo}.
          <br>The developer can now copy the updated provenance.json from your comment.
        </div>
        <a href="${commentURL}" target="_blank" class="attest-link">View comment on GitHub →</a>
      </div>
    </div>`;
}

function showAttestError(message) {
  attestResult.classList.remove('hidden');
  attestResult.innerHTML = `
    <div class="check-row" style="border:none;padding:0">
      <div class="check-icon fail">✗</div>
      <div class="check-content">
        <div class="check-title" style="color:var(--red)">Attestation failed</div>
        <div class="check-detail">${message}</div>
      </div>
    </div>`;
}

// ── REQUESTS TAB — Submit a request ──────────────────────────────────────

const submitReqToggle   = document.getElementById('submitReqToggle');
const submitReqBody     = document.getElementById('submitReqBody');
const submitReqArrow    = document.getElementById('submitReqArrow');
const reqProvDrop       = document.getElementById('reqProvDrop');
const reqProvInput      = document.getElementById('reqProvInput');
const reqProvInfo       = document.getElementById('reqProvInfo');
const reqProvSummary    = document.getElementById('reqProvSummary');
const reqProvDetail     = document.getElementById('reqProvDetail');
const reqSubmitRegistry = document.getElementById('reqSubmitRegistry');
const reqSubmitToken    = document.getElementById('reqSubmitToken');
const reqSubmitMessage  = document.getElementById('reqSubmitMessage');
const btnSubmitReq      = document.getElementById('btnSubmitReq');
const submitReqSpinner  = document.getElementById('submitReqSpinner');
const submitReqBtnText  = document.getElementById('submitReqBtnText');
const submitReqResult   = document.getElementById('submitReqResult');

let submitProvenance = null;

// Toggle expand/collapse
submitReqToggle.addEventListener('click', () => {
  const open = !submitReqBody.classList.contains('hidden');
  submitReqBody.classList.toggle('hidden', open);
  submitReqArrow.textContent = open ? '▶' : '▼';
});

// Drag & drop provenance.json onto submit zone
reqProvDrop.addEventListener('dragover', e => { e.preventDefault(); reqProvDrop.classList.add('drag-over'); });
reqProvDrop.addEventListener('dragleave', () => reqProvDrop.classList.remove('drag-over'));
reqProvDrop.addEventListener('drop', e => {
  e.preventDefault(); reqProvDrop.classList.remove('drag-over');
  const f = e.dataTransfer.files[0];
  if (f) loadSubmitProv(f);
});
reqProvInput.addEventListener('change', () => { if (reqProvInput.files[0]) loadSubmitProv(reqProvInput.files[0]); });

function loadSubmitProv(file) {
  const reader = new FileReader();
  reader.onload = e => {
    try {
      const p = JSON.parse(e.target.result);
      if (!p.artifact || !p.identity) throw new Error('Not a valid provenance.json');
      submitProvenance = p;
      reqProvSummary.textContent = `${p.artifact.name} v${p.artifact.version} — by ${p.identity.display_name}`;
      reqProvDetail.textContent  = `SHA-256: ${p.artifact.sha256.slice(0,32)}…  ·  Fingerprint: ${p.identity.pubkey_fingerprint.slice(0,16)}…`;
      reqProvInfo.classList.remove('hidden');
      reqProvDrop.style.display = 'none';
      checkSubmitReady();
    } catch(err) {
      alert('Invalid provenance.json: ' + err.message);
    }
  };
  reader.readAsText(file);
}

function checkSubmitReady() {
  btnSubmitReq.disabled = !(submitProvenance && reqSubmitToken.value.trim() && reqSubmitRegistry.value.trim());
}
reqSubmitToken.addEventListener('input', checkSubmitReady);
reqSubmitRegistry.addEventListener('input', checkSubmitReady);

btnSubmitReq.addEventListener('click', async () => {
  const token    = reqSubmitToken.value.trim();
  const slug     = reqSubmitRegistry.value.trim();
  const message  = reqSubmitMessage.value.trim();
  const p        = submitProvenance;

  submitReqSpinner.style.display = '';
  submitReqBtnText.textContent   = 'Opening issue…';
  btnSubmitReq.disabled          = true;
  submitReqResult.classList.add('hidden');

  try {
    const title = `[ATTEST REQUEST] ${p.artifact.name} v${p.artifact.version} — by ${p.identity.display_name}`;
    const date  = (p.signature && p.signature.timestamp || '').slice(0, 10);
    const fp    = p.identity.pubkey_fingerprint;
    const msgSection = message ? `\n> **Note from developer:** ${message}\n` : '';

    const body =
`## Attestation Request
${msgSection}
| | |
|---|---|
| **App** | ${p.artifact.name} v${p.artifact.version} |
| **Developer** | ${p.identity.display_name} |
| **Fingerprint** | \`${fp}\` |
| **SHA-256** | \`${p.artifact.sha256}\` |
| **Signed on** | ${date} |

---

### How to attest

1. Go to [open-trust-dashboard](https://lastexitfromnowhere.github.io/open-trust-dashboard/) → **REQUESTS** tab
2. Click **Attest →** next to this request
3. Drop your \`key.json\` (or generate one in-browser)
4. Sign with your passphrase — the updated \`provenance.json\` is posted here automatically

> This binary needs **${(p.trust_chain && p.trust_chain.threshold) || 2} attestation(s)** to reach TRUSTED status.
> You only need the \`provenance.json\` — **never** share your private key.

---

<details>
<summary>📄 provenance.json (click to expand)</summary>

\`\`\`json
${JSON.stringify(p, null, 2)}
\`\`\`

</details>`;

    const res = await fetch(`https://api.github.com/repos/${slug}/issues`, {
      method: 'POST',
      headers: {
        Authorization: `token ${token}`,
        Accept: 'application/vnd.github.v3+json',
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ title, body })
    });

    if (res.status === 401) throw new Error('GitHub token invalid or expired (401)');
    if (res.status === 403) throw new Error('Token lacks issues:write / repo scope (403)');
    if (res.status === 404) throw new Error(`Repo "${slug}" not found or is private (404)`);
    if (!res.ok) throw new Error(`GitHub API error: ${res.status}`);

    const issue = await res.json();
    submitReqResult.classList.remove('hidden');
    submitReqResult.innerHTML = `
      <div class="attest-success">
        <div class="attest-success-icon">✓</div>
        <div>
          <div class="attest-success-title">Issue #${issue.number} created!</div>
          <div class="attest-success-detail">Your request is now visible in the REQUESTS list. Share this link to get attestations faster.</div>
          <a href="${issue.html_url}" target="_blank" class="attest-link">View issue on GitHub →</a>
        </div>
      </div>`;
    // Refresh the list below
    requestsLoaded = false;
    fetchRequests();

  } catch(err) {
    submitReqResult.classList.remove('hidden');
    submitReqResult.innerHTML = `<div style="color:var(--red);font-size:12px;">✗ ${escHtml(err.message)}</div>`;
  } finally {
    submitReqSpinner.style.display = 'none';
    submitReqBtnText.textContent   = '▶ \u00a0OPEN ISSUE';
    btnSubmitReq.disabled          = false;
  }
});

// ── SIGN wizard ───────────────────────────────────────────────────────────

// Accordion steps
document.querySelectorAll('.sign-step-header').forEach(header => {
  header.addEventListener('click', () => {
    const step = document.getElementById(header.dataset.step);
    const isOpen = step.classList.contains('open');
    // Close all, open clicked
    document.querySelectorAll('.sign-step').forEach(s => s.classList.remove('open'));
    if (!isOpen) step.classList.add('open');
  });
});

// Copy buttons
document.querySelectorAll('.btn-copy').forEach(btn => {
  btn.addEventListener('click', e => {
    e.stopPropagation();
    const block = document.getElementById(btn.dataset.cmd);
    const text  = block.innerText.replace(/^Copy$/m, '').trim();
    navigator.clipboard.writeText(text).then(() => {
      btn.textContent = '✓ Copied';
      btn.classList.add('copied');
      setTimeout(() => { btn.textContent = 'Copy'; btn.classList.remove('copied'); }, 1800);
    });
  });
});

// Live command update helpers
function signVal(id, val) { const el = document.getElementById(id); if (el) el.textContent = val || el.dataset.placeholder || ''; }
function q(v) { return v.includes(' ') ? `"${v}"` : v; }

// Step 1 — directory
document.getElementById('s1Dir').addEventListener('input', function() {
  const d = this.value.trim() || '~/open-trust-cli';
  signVal('c1dir',  d);
  signVal('c1dir2', d);
});

// Step 3 — sign fields
['s3Name','s3Ver','s3File','s3Key','s3Thresh'].forEach(id => {
  document.getElementById(id).addEventListener('input', updateCmd3);
  document.getElementById(id).addEventListener('change', updateCmd3);
});
function updateCmd3() {
  const name   = document.getElementById('s3Name').value.trim()   || 'MyApp';
  const ver    = document.getElementById('s3Ver').value.trim()    || '1.0.0';
  const file   = document.getElementById('s3File').value.trim()   || './myapp.exe';
  const key    = document.getElementById('s3Key').value.trim()    || './my-name.key.json';
  const thresh = document.getElementById('s3Thresh').value;
  signVal('c3name',   q(name));
  signVal('c3ver',    q(ver));
  signVal('c3file',   file);
  signVal('c3key',    key);
  signVal('c3thresh', thresh);
  // Sync threshold to step 5 summary
  signVal('s5ThreshDisplay', thresh);
}

// Step 4 — token + registry
document.getElementById('s4Token').addEventListener('input', function() {
  const t = this.value.trim() || 'ghp_xxxxxxxxxxxx';
  signVal('c4tokWin',  `"${t}"`);
  signVal('c4tokUnix', `"${t}"`);
  // Sync to shared token
  syncToken(this.value.trim());
});
document.getElementById('s4Registry').addEventListener('input', function() {
  const r = this.value.trim() || 'https://github.com/Lastexitfromnowhere/open-trust-registry.git';
  signVal('c4reg',     r);
  signVal('c4regUnix', r);
});

// Pre-fill token from localStorage into step 4 when tab opens
tabSign.addEventListener('click', () => {
  const saved = localStorage.getItem(STORAGE_KEY);
  if (saved && !document.getElementById('s4Token').value) {
    document.getElementById('s4Token').value = saved;
    signVal('c4tokWin',  `"${saved}"`);
    signVal('c4tokUnix', `"${saved}"`);
  }
});

// ── GitHub token — shared localStorage across all tabs ────────────────────

const STORAGE_KEY = 'ot_github_token';

const attestTokenToggle   = document.getElementById('attestTokenToggle');
const attestTokenRememberRow = document.getElementById('attestTokenRememberRow');
const reqTokenToggle      = document.getElementById('reqTokenToggle');
const reqTokenRememberRow = document.getElementById('reqTokenRememberRow');

// Load saved token on startup
(function loadSavedToken() {
  const saved = localStorage.getItem(STORAGE_KEY);
  if (!saved) return;
  attestToken.value       = saved;
  reqSubmitToken.value    = saved;
  attestTokenToggle.classList.add('on');
  reqTokenToggle.classList.add('on');
  checkSubmitReady();
})();

// Sync both token fields together
function syncToken(value) {
  attestToken.value    = value;
  reqSubmitToken.value = value;
  checkSubmitReady();
  // If "remember" is on in either toggle, persist
  if (attestTokenToggle.classList.contains('on') || reqTokenToggle.classList.contains('on')) {
    if (value) localStorage.setItem(STORAGE_KEY, value);
    else       localStorage.removeItem(STORAGE_KEY);
  }
}

attestToken.addEventListener('input', () => syncToken(attestToken.value));
reqSubmitToken.addEventListener('input', () => syncToken(reqSubmitToken.value));

// Remember toggles
attestTokenRememberRow.addEventListener('click', () => {
  const on = attestTokenToggle.classList.toggle('on');
  reqTokenToggle.classList.toggle('on', on);
  if (on && attestToken.value) localStorage.setItem(STORAGE_KEY, attestToken.value);
  else localStorage.removeItem(STORAGE_KEY);
});
reqTokenRememberRow.addEventListener('click', () => {
  const on = reqTokenToggle.classList.toggle('on');
  attestTokenToggle.classList.toggle('on', on);
  if (on && reqSubmitToken.value) localStorage.setItem(STORAGE_KEY, reqSubmitToken.value);
  else localStorage.removeItem(STORAGE_KEY);
});

// ── REQUESTS TAB — Browse list ────────────────────────────────────────────

btnRefreshRequests.addEventListener('click', () => {
  requestsLoaded = true;
  fetchRequests();
});

async function fetchRequests() {
  const slug = reqRegistryInput.value.trim();
  if (!slug) return;

  // UI: loading state
  reqSpinner.style.display = '';
  reqBtnText.textContent   = 'Loading…';
  btnRefreshRequests.disabled = true;
  reqList.innerHTML = '';
  reqEmpty.classList.add('hidden');
  reqError.classList.add('hidden');

  try {
    const res = await fetch(
      `https://api.github.com/repos/${slug}/issues?state=open&per_page=100`,
      { headers: { Accept: 'application/vnd.github.v3+json' } }
    );
    if (!res.ok) {
      if (res.status === 404) throw new Error(`Repository "${slug}" not found or is private.`);
      throw new Error(`GitHub API error: ${res.status}`);
    }

    const issues = await res.json();
    // Filter: only [ATTEST REQUEST] issues
    const reqs = issues.filter(i => i.title.startsWith('[ATTEST REQUEST]'));

    if (reqs.length === 0) {
      reqEmpty.classList.remove('hidden');
    } else {
      reqs.forEach(issue => reqList.appendChild(buildReqCard(issue)));
    }
  } catch (err) {
    reqError.textContent = err.message;
    reqError.classList.remove('hidden');
  } finally {
    reqSpinner.style.display = 'none';
    reqBtnText.textContent   = '↻ \u00a0REFRESH';
    btnRefreshRequests.disabled = false;
  }
}

// Parse title: "[ATTEST REQUEST] AppName v1.0.0 — by DisplayName"
function parseReqTitle(title) {
  const m = title.match(/^\[ATTEST REQUEST\]\s+(.+?)\s+v([^\s—]+)\s+[—-]+\s+by\s+(.+)$/i);
  if (m) return { name: m[1], version: m[2], developer: m[3] };
  // Fallback: strip prefix
  const stripped = title.replace(/^\[ATTEST REQUEST\]\s*/i, '');
  return { name: stripped, version: '', developer: '' };
}

function timeAgo(isoDate) {
  const diff = Date.now() - new Date(isoDate).getTime();
  const d = Math.floor(diff / 86400000);
  if (d === 0) return 'today';
  if (d === 1) return 'yesterday';
  if (d < 30)  return `${d} days ago`;
  const m = Math.floor(d / 30);
  return `${m} month${m>1?'s':''} ago`;
}

function buildReqCard(issue) {
  const { name, version, developer } = parseReqTitle(issue.title);
  const comments  = issue.comments;
  const date      = timeAgo(issue.created_at);
  const issueURL  = issue.html_url;

  // Badge: if comments > 0, show count, else show "Needs attestations"
  const badgeHTML = comments > 0
    ? `<span class="req-pill done">✓ ${comments} attestation${comments>1?'s':''}</span>`
    : `<span class="req-pill need">⏳ No attestations yet</span>`;

  const card = document.createElement('div');
  card.className = 'req-card';
  card.innerHTML = `
    <div class="req-icon">📦</div>
    <div class="req-body">
      <div class="req-name">
        ${escHtml(name)}${version ? `<span class="req-version">v${escHtml(version)}</span>` : ''}
      </div>
      <div class="req-meta">
        ${developer ? `<span>👤 ${escHtml(developer)}</span>` : ''}
        <span>🕐 ${date}</span>
        <span>🔗 issue #${issue.number}</span>
      </div>
      <div class="req-actions">
        ${badgeHTML}
        <button class="btn-attest-req" data-url="${escHtml(issueURL)}">Attest →</button>
        <a href="${escHtml(issueURL)}" target="_blank" class="req-github-link">View on GitHub ↗</a>
      </div>
    </div>`;

  card.querySelector('.btn-attest-req').addEventListener('click', () => {
    // Pre-fill the ATTEST tab issue URL and switch to it
    document.getElementById('issueInput').value = issueURL;
    document.getElementById('issueInput').dispatchEvent(new Event('input'));
    switchTab('attest');
    // Scroll to top
    window.scrollTo({ top: 0, behavior: 'smooth' });
  });

  return card;
}

function escHtml(str) {
  return String(str)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;')
    .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

// ── EXPLORE — Trust Graph ────────────────────────────────────────────────

let exploreGraph = null;

const exploreSlug    = document.getElementById('exploreSlug');
const btnLoadExplore = document.getElementById('btnLoadExplore');
const exploreStatus  = document.getElementById('exploreStatus');
const exploreError   = document.getElementById('exploreError');
const exploreArtifacts = document.getElementById('exploreArtifacts');
const exploreCommunity = document.getElementById('exploreCommunity');
const artifactList   = document.getElementById('artifactList');
const communityGrid  = document.getElementById('communityGrid');

btnLoadExplore.addEventListener('click', loadExplore);

async function loadExplore() {
  const slug  = exploreSlug.value.trim();
  if (!slug) return;
  const token = localStorage.getItem(STORAGE_KEY) || '';

  btnLoadExplore.disabled = true;
  btnLoadExplore.textContent = 'Loading…';
  exploreStatus.classList.remove('hidden');
  exploreError.classList.add('hidden');
  exploreArtifacts.classList.add('hidden');
  exploreCommunity.classList.add('hidden');
  artifactList.innerHTML = '';
  communityGrid.innerHTML = '';

  try {
    exploreStatus.textContent = 'Fetching registry index…';
    const headers = { Accept: 'application/vnd.github.v3+json' };
    if (token) headers.Authorization = `token ${token}`;

    const repoRes = await fetch(`https://api.github.com/repos/${slug}`, { headers });
    if (!repoRes.ok) throw new Error(`Repo not found or private: ${slug}`);
    const repoData = await repoRes.json();
    const branch = repoData.default_branch || 'main';

    const treeRes = await fetch(`https://api.github.com/repos/${slug}/git/trees/HEAD?recursive=1`, { headers });
    if (!treeRes.ok) throw new Error(`Failed to fetch registry tree: ${treeRes.status}`);
    const treeData = await treeRes.json();
    if (treeData.truncated) {
      exploreStatus.textContent = '⚠️ Registry is very large — showing partial results. Use a token for best results.';
    }

    const identityPaths = treeData.tree.filter(f => /^keys\/[^/]+\/identity\.json$/.test(f.path)).map(f => f.path);
    const sigPaths      = treeData.tree.filter(f => /^keys\/[^/]+\/signatures\/.+\.json$/.test(f.path)).map(f => f.path);

    if (sigPaths.length === 0) {
      exploreStatus.textContent = 'No signed artifacts found in this registry yet.';
      btnLoadExplore.disabled = false;
      btnLoadExplore.textContent = '↻ RELOAD';
      return;
    }

    const rawBase = `https://raw.githubusercontent.com/${slug}/${branch}`;
    exploreStatus.textContent = `Fetching ${identityPaths.length} identities + ${sigPaths.length} artifacts…`;

    async function fetchJSON(p) {
      const res = await fetch(`${rawBase}/${p}`);
      if (!res.ok) return null;
      return res.json().catch(() => null);
    }

    async function batchFetch(paths, batchSize = 20) {
      const results = [];
      for (let i = 0; i < paths.length; i += batchSize) {
        const batch = await Promise.all(paths.slice(i, i + batchSize).map(fetchJSON));
        results.push(...batch);
        if (i + batchSize < paths.length) {
          exploreStatus.textContent = `Fetching… ${Math.min(i + batchSize, paths.length)}/${paths.length}`;
        }
      }
      return results;
    }

    const [rawIdentities, rawArtifacts] = await Promise.all([
      batchFetch(identityPaths),
      batchFetch(sigPaths)
    ]);

    const graph = { identities: {}, artifacts: [] };

    for (const id of rawIdentities.filter(Boolean)) {
      graph.identities[id.pubkey_fingerprint] = {
        ...id, artifactsSigned: [], attestationsGiven: [], devScore: 0, attesterScore: 0,
      };
    }

    for (const prov of rawArtifacts.filter(Boolean)) {
      graph.artifacts.push(prov);
      const fp   = prov.identity?.pubkey_fingerprint;
      const atts = prov.attestations ?? [];
      if (fp && !graph.identities[fp]) {
        graph.identities[fp] = {
          display_name: prov.identity.display_name || fp.slice(0,12)+'…',
          pubkey_fingerprint: fp, pubkey_ed25519: prov.identity.pubkey_ed25519,
          social_proofs: prov.identity.social_proofs || [],
          artifactsSigned: [], attestationsGiven: [], devScore: 0, attesterScore: 0,
        };
      }
      if (fp && graph.identities[fp]) {
        graph.identities[fp].artifactsSigned.push(prov);
        graph.identities[fp].devScore += atts.length;
      }
      for (const att of atts) {
        const afp = att.attester_fingerprint;
        if (!afp) continue;
        if (!graph.identities[afp]) {
          graph.identities[afp] = {
            display_name: afp.slice(0,12)+'…', pubkey_fingerprint: afp,
            artifactsSigned: [], attestationsGiven: [], devScore: 0, attesterScore: 0,
          };
        }
        graph.identities[afp].attestationsGiven.push({ artifact: prov, attestation: att });
        graph.identities[afp].attesterScore += 1;
      }
    }

    exploreGraph = graph;
    exploreStatus.classList.add('hidden');
    renderExplore(graph);

  } catch(err) {
    exploreStatus.classList.add('hidden');
    exploreError.textContent = '✗ ' + err.message;
    exploreError.classList.remove('hidden');
  } finally {
    btnLoadExplore.disabled = false;
    btnLoadExplore.textContent = '↻ RELOAD';
  }
}

function trustLevel(atts, threshold) {
  if (atts >= threshold) return { label: 'TRUSTED',    cls: 'trusted' };
  if (atts > 0)          return { label: 'PENDING',    cls: 'pending' };
  return                        { label: 'UNVERIFIED', cls: 'unverif' };
}

function renderExplore(graph) {
  artifactList.innerHTML = '';
  const sorted = [...graph.artifacts].sort((a,b) =>
    (b.attestations?.length||0) - (a.attestations?.length||0));

  for (const prov of sorted) {
    const atts      = prov.attestations ?? [];
    const threshold = prov.trust_chain?.threshold ?? 2;
    const lvl       = trustLevel(atts.length, threshold);
    const fp        = prov.identity?.pubkey_fingerprint ?? '';
    const devName   = prov.identity?.display_name ?? 'Unknown';
    const progress  = Math.min(100, Math.round((atts.length / threshold) * 100));
    const date      = (prov.signature?.timestamp || '').slice(0,10);
    const attestorChips = atts.map(a =>
      `<button class="fp-chip" onclick="openFpModal('${a.attester_fingerprint}',event)">${a.attester_fingerprint.slice(0,12)}…</button>`
    ).join(' ');
    const card = document.createElement('div');
    card.className = 'artifact-card';
    card.innerHTML = `
      <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:12px;flex-wrap:wrap;">
        <div style="flex:1;min-width:0;">
          <div style="font-family:var(--title);font-size:13px;font-weight:700;color:#fff;letter-spacing:.06em;margin-bottom:3px;">
            ${escHtml(prov.artifact.name)}
            <span style="color:var(--accent);font-weight:400;font-family:var(--mono);font-size:11px;margin-left:8px;">v${escHtml(prov.artifact.version||'—')}</span>
          </div>
          <div style="font-size:11px;color:var(--text-muted);margin-bottom:8px;">
            by <button class="fp-chip" onclick="openFpModal('${fp}',event)" style="margin-left:2px;">${escHtml(devName)}</button>
            · ${date}
          </div>
          <div style="font-size:10px;color:var(--text-muted);font-family:var(--mono);margin-bottom:10px;">
            sha256: ${prov.artifact.sha256.slice(0,32)}…
          </div>
          <div class="att-progress-wrap">
            <div class="att-progress" style="width:${progress}%"></div>
          </div>
          <div style="font-size:10px;color:var(--text-muted);margin-top:4px;margin-bottom:${atts.length?'8px':'0'};">
            ${atts.length} / ${threshold} attestation${threshold>1?'s':''}
          </div>
          ${atts.length ? `<div style="display:flex;flex-wrap:wrap;gap:5px;margin-top:4px;">${attestorChips}</div>` : ''}
        </div>
        <span class="trust-lvl ${lvl.cls}">${lvl.label}</span>
      </div>`;
    artifactList.appendChild(card);
  }
  exploreArtifacts.classList.remove('hidden');

  communityGrid.innerHTML = '';
  const members = Object.values(graph.identities)
    .sort((a,b) => (b.devScore + b.attesterScore) - (a.devScore + a.attesterScore));

  members.forEach((id, idx) => {
    const totalScore = id.devScore + id.attesterScore;
    const stars = totalScore >= 10 ? '★★★' : totalScore >= 4 ? '★★☆' : totalScore >= 1 ? '★☆☆' : '☆☆☆';
    const fp = id.pubkey_fingerprint;
    const card = document.createElement('div');
    card.className = 'community-card';
    card.innerHTML = `
      <div style="display:flex;align-items:center;gap:12px;">
        <div style="font-family:var(--title);font-size:18px;color:rgba(74,222,128,0.25);font-weight:900;min-width:28px;">#${idx+1}</div>
        <div style="flex:1;min-width:0;">
          <div style="font-family:var(--title);font-size:11px;font-weight:700;color:#fff;letter-spacing:.06em;margin-bottom:2px;">${escHtml(id.display_name||fp.slice(0,16)+'…')}</div>
          <div style="font-family:var(--mono);font-size:10px;color:var(--text-muted);">
            <button class="fp-chip" onclick="openFpModal('${fp}',event)">${fp.slice(0,16)}…</button>
          </div>
        </div>
        <div style="text-align:right;flex-shrink:0;">
          <div style="color:var(--accent);font-size:13px;letter-spacing:.05em;">${stars}</div>
          <div style="font-size:10px;color:var(--text-muted);margin-top:2px;">score ${totalScore}</div>
        </div>
      </div>
      <div style="display:flex;gap:16px;margin-top:10px;font-size:11px;color:var(--text-muted);">
        <span>📦 ${id.artifactsSigned.length} signed</span>
        <span>✓ ${id.attestationsGiven.length} attested</span>
        ${id.first_seen ? `<span>📅 since ${id.first_seen.slice(0,10)}</span>` : ''}
      </div>`;
    communityGrid.appendChild(card);
  });
  exploreCommunity.classList.remove('hidden');
}

// ── Fingerprint modal ──────────────────────────────────────────────────────

const fpModal        = document.getElementById('fpModal');
const fpModalClose   = document.getElementById('fpModalClose');
const fpModalContent = document.getElementById('fpModalContent');

fpModalClose.addEventListener('click', () => fpModal.classList.add('hidden'));
fpModal.addEventListener('click', e => { if (e.target === fpModal) fpModal.classList.add('hidden'); });
document.addEventListener('keydown', e => { if (e.key === 'Escape') fpModal.classList.add('hidden'); });

async function openFpModal(fp, event) {
  if (event) event.stopPropagation();
  fpModalContent.innerHTML = `<div style="text-align:center;padding:20px;color:var(--text-muted);">Loading profile…</div>`;
  fpModal.classList.remove('hidden');

  if (exploreGraph && exploreGraph.identities[fp]) {
    renderFpModal(fp, exploreGraph.identities[fp], exploreGraph);
    return;
  }

  const slug  = (document.getElementById('exploreSlug') || document.getElementById('reqRegistryInput')).value.trim()
              || 'Lastexitfromnowhere/open-trust-registry';
  const token = localStorage.getItem(STORAGE_KEY) || '';
  try {
    const headers = { Accept: 'application/vnd.github.v3+json' };
    if (token) headers.Authorization = `token ${token}`;
    const repoRes = await fetch(`https://api.github.com/repos/${slug}`, { headers });
    const branch  = repoRes.ok ? (await repoRes.json()).default_branch : 'main';
    const rawBase = `https://raw.githubusercontent.com/${slug}/${branch}`;

    const idRes   = await fetch(`${rawBase}/keys/${fp}/identity.json`);
    const id      = idRes.ok ? await idRes.json() : null;
    const identity = id || { display_name: fp.slice(0,16)+'…', pubkey_fingerprint: fp, artifactsSigned: [], attestationsGiven: [] };
    identity.artifactsSigned   = identity.artifactsSigned   || [];
    identity.attestationsGiven = identity.attestationsGiven || [];
    renderFpModal(fp, identity, null);
  } catch(err) {
    fpModalContent.innerHTML = `<div style="color:var(--red);font-size:12px;">Failed to load profile: ${escHtml(err.message)}</div>`;
  }
}

function renderFpModal(fp, id, graph) {
  const totalScore = (id.devScore||0) + (id.attesterScore||0);
  const stars = totalScore >= 10 ? '★★★' : totalScore >= 4 ? '★★☆' : totalScore >= 1 ? '★☆☆' : '☆☆☆';

  const signedHTML = (id.artifactsSigned||[]).map(p =>
    `<div style="font-size:11px;padding:5px 0;border-bottom:1px solid var(--border);color:var(--text-dim);">
      📦 <strong>${escHtml(p.artifact?.name||'?')}</strong> v${escHtml(p.artifact?.version||'?')}
      <span style="color:var(--text-muted);margin-left:8px;">${(p.attestations?.length||0)} attestation(s)</span>
    </div>`).join('') || '<div style="font-size:11px;color:var(--text-muted);">No published artifacts.</div>';

  const givenHTML = (id.attestationsGiven||[]).map(({artifact, attestation}) =>
    `<div style="font-size:11px;padding:5px 0;border-bottom:1px solid var(--border);color:var(--text-dim);">
      ✓ <strong>${escHtml(artifact?.artifact?.name||'?')}</strong>
      <span style="color:var(--text-muted);margin-left:6px;">&quot;${escHtml(attestation?.statement||'')}&quot;</span>
    </div>`).join('') || '<div style="font-size:11px;color:var(--text-muted);">No attestations given yet.</div>';

  const socialHTML = (id.social_proofs||[]).map(sp =>
    `<a href="${escHtml(sp.proof_url)}" target="_blank" style="font-size:11px;color:var(--accent);text-decoration:none;display:block;margin-bottom:3px;">
      🌐 ${escHtml(sp.platform)} · ${escHtml(sp.handle)}</a>`).join('');

  fpModalContent.innerHTML = `
    <div style="font-family:var(--title);font-size:14px;font-weight:900;color:#fff;letter-spacing:.10em;margin-bottom:4px;">
      ${escHtml(id.display_name || fp.slice(0,16)+'…')}
    </div>
    <div style="font-size:10px;color:var(--text-muted);font-family:var(--mono);word-break:break-all;margin-bottom:16px;">${fp}</div>
    <div style="display:flex;gap:20px;margin-bottom:20px;flex-wrap:wrap;">
      <div style="text-align:center;">
        <div style="font-size:20px;color:var(--accent);">${stars}</div>
        <div style="font-size:10px;color:var(--text-muted);">Trust Score ${totalScore}</div>
      </div>
      <div style="font-size:11px;color:var(--text-muted);display:flex;flex-direction:column;gap:4px;justify-content:center;">
        <span>📦 ${(id.artifactsSigned||[]).length} artifacts signed</span>
        <span>✓ ${(id.attestationsGiven||[]).length} attestations given</span>
        ${id.first_seen ? `<span>📅 Member since ${id.first_seen.slice(0,10)}</span>` : ''}
      </div>
    </div>
    ${socialHTML ? `<div style="margin-bottom:16px;">${socialHTML}</div>` : ''}
    <div style="font-size:10px;text-transform:uppercase;letter-spacing:.12em;color:var(--text-muted);margin-bottom:8px;">Artifacts Signed</div>
    <div style="margin-bottom:16px;">${signedHTML}</div>
    ${graph ? `<div style="font-size:10px;text-transform:uppercase;letter-spacing:.12em;color:var(--text-muted);margin-bottom:8px;">Attestations Given</div>
    <div>${givenHTML}</div>` : `<div style="font-size:11px;color:var(--text-muted);margin-top:8px;">Load the <strong>EXPLORE</strong> tab for full attestation history.</div>`}
  `;
}

