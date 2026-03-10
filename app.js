const TRUSTED_HOSTS = ['localhost', '127.0.0.1', 'udaycodespace.github.io', 'www.udaycodespace.com'];
const ISSUER_REGISTRY_PATH = './trusted_issuers.json';
const RESULT_STORE_KEY = 'credify_verify_result_v4';
const EMBEDDED_ISSUER_REGISTRY = {
  'did:edu:gprec': {
    name: 'GPREC',
    algorithm: 'PS256',
    publicKeyPem: `-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAkF5v1ym4AlzX8csMwGhZ
UsXG9MpOOc+vExW561RDcRjjMNBBVF2KHzkhJOKYCSBJwvpJ+IhoWf42tzuhzBY9
8Rrb6heKxaI5PmLDS+pOR16ynZvFulfNItYbo17R+XaTd55ftz3wMmn3nzvvkIxV
Madi7BPJ8s8Y1TR23M76w0WNN4s69z7qdUt21g6LMfwh1bJul2ycaaGNVB1kUIgx
mUGE+YWU8UHLzmcPE7PaVMEfzH96lI1FdEXD2F6dHNRU3T/YGJ2YZA6lCkFi4Bpf
R2CVrtuYNijGk162N9C60oSCzu8UYTI5vwBePmf9R84dlk8Qv0Lv8vUWbxIhoIaX
BFROegACcCBHtENUg4ahktR4G/JbBWSvl35fE9hZku6j3KQJbRDs1h/dbgAfBoLT
gdBftQqxXNRyzrfVT0GtSstnMiPW/AZTtiSxMYoEWyC0u45c59iXfB+NUpliq8lI
Ct7g+alzO6yfFzb3trQjCAiqjaS44FLzxcCO47KzRWZ+DR5qAizkjyCthr6nvsMY
rh7Emujzbg1e8nCfqDPzJT7FAh6Zq7UasMJHQ+1XdTI4rW3s+VSIaIgO1R+/fSoP
mPKXP8/7sUyxRMo/X/dimGQzpaT12DerfFbmVcTaiTPNBnSqR3T7AibUAD4Yg0es
FogAXPXaoh235wypYfOujM0CAwEAAQ==
-----END PUBLIC KEY-----`
  }
};

const page = document.body.dataset.page || 'unknown';
const codeReader = typeof ZXing !== 'undefined' ? new ZXing.BrowserQRCodeReader() : null;
let activeControls = null;
let trustedIssuers = {};

function $(id) {
  return document.getElementById(id);
}

function escapeHtml(text) {
  return String(text ?? 'N/A')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function formatValue(value) {
  if (Array.isArray(value)) {
    return value.length ? value.join(', ') : 'None';
  }
  return value ?? 'N/A';
}

function decodeBase64Url(str) {
  const padded = str + '='.repeat((4 - (str.length % 4)) % 4);
  const b64 = padded.replace(/-/g, '+').replace(/_/g, '/');
  return atob(b64);
}

function bytesFromBase64Url(str) {
  return Uint8Array.from(decodeBase64Url(str), ch => ch.charCodeAt(0));
}

function toUtf8Bytes(text) {
  return new TextEncoder().encode(text);
}

function pemToArrayBuffer(pem) {
  const b64 = pem.replace(/-----BEGIN PUBLIC KEY-----|-----END PUBLIC KEY-----|\s+/g, '');
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

async function sha256Hex(text) {
  const digest = await crypto.subtle.digest('SHA-256', toUtf8Bytes(text));
  return Array.from(new Uint8Array(digest)).map(byte => byte.toString(16).padStart(2, '0')).join('');
}

async function decodeQdPayload(qd) {
  const bytes = bytesFromBase64Url(qd);
  const decoder = new TextDecoder('utf-8');

  try {
    const payloadText = decoder.decode(bytes);
    return { payloadText, parsed: JSON.parse(payloadText) };
  } catch {
    // Continue to gzip path.
  }

  if (typeof DecompressionStream === 'function') {
    const stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream('gzip'));
    const decompressed = await new Response(stream).arrayBuffer();
    const payloadText = decoder.decode(new Uint8Array(decompressed));
    return { payloadText, parsed: JSON.parse(payloadText) };
  }

  if (typeof pako !== 'undefined' && typeof pako.ungzip === 'function') {
    const payloadText = pako.ungzip(bytes, { to: 'string' });
    return { payloadText, parsed: JSON.parse(payloadText) };
  }

  throw new Error('This browser cannot decompress the QR payload.');
}

function parseQrPayload(payload) {
  const text = String(payload || '').trim();
  if (!text) {
    throw new Error('The QR payload is empty.');
  }

  let url;
  try {
    url = new URL(text);
  } catch {
    throw new Error('The QR did not contain a valid verification URL.');
  }

  if (!['http:', 'https:'].includes(url.protocol)) {
    throw new Error('The QR must contain an HTTP or HTTPS verification URL.');
  }

  const id = url.searchParams.get('id');
  const qk = url.searchParams.get('qk');
  const qd = url.searchParams.get('qd');

  if (!id || !qk || !qd) {
    throw new Error('The verification URL is missing one of: id, qk, or qd.');
  }

  return {
    credentialId: id,
    qk,
    qd,
    sourceUrl: url.toString(),
    sourceHost: url.hostname.toLowerCase(),
    hostTrusted: TRUSTED_HOSTS.includes(url.hostname.toLowerCase())
  };
}

async function loadIssuerRegistry() {
  try {
    const response = await fetch(ISSUER_REGISTRY_PATH, { cache: 'no-cache' });
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }
    const data = await response.json();
    trustedIssuers = {
      ...EMBEDDED_ISSUER_REGISTRY,
      ...(data.issuers || {})
    };
  } catch {
    trustedIssuers = { ...EMBEDDED_ISSUER_REGISTRY };
  }
}

function getHashByteLength(hashName) {
  return { 'SHA-256': 32, 'SHA-384': 48, 'SHA-512': 64 }[hashName] || 32;
}

function getSaltLengthCandidates(publicKey) {
  const hashName = publicKey?.algorithm?.hash?.name || 'SHA-256';
  const hashBytes = getHashByteLength(hashName);
  const candidates = [hashBytes];
  const modulusLength = publicKey?.algorithm?.modulusLength;

  if (Number.isFinite(modulusLength)) {
    const emLen = Math.ceil((modulusLength - 1) / 8);
    const legacyMaxSalt = emLen - hashBytes - 2;
    if (legacyMaxSalt > 0) {
      candidates.push(legacyMaxSalt);
    }
  }

  return [...new Set(candidates)];
}

async function verifyRsaPssSignature(publicKey, signatureBytes, signingInputBytes) {
  for (const saltLength of getSaltLengthCandidates(publicKey)) {
    const ok = await crypto.subtle.verify(
      { name: 'RSA-PSS', saltLength },
      publicKey,
      signatureBytes,
      signingInputBytes
    );

    if (ok) {
      return {
        ok: true,
        saltLength,
        profile: saltLength === 32 ? 'ps256-standard' : 'ps256-legacy-max-salt'
      };
    }
  }

  return { ok: false, profile: 'unverified' };
}

async function verifyJwsToken(qk, payloadText, expectedCid) {
  const parts = String(qk || '').split('.');
  if (parts.length !== 3) {
    return {
      ok: false,
      reason: 'Legacy token format detected. This verifier expects the hosted QR JWS format.'
    };
  }

  try {
    const [headerB64, payloadB64, signatureB64] = parts;
    const header = JSON.parse(decodeBase64Url(headerB64));
    const payload = JSON.parse(decodeBase64Url(payloadB64));
    const issuerId = payload.iss;
    const issuer = trustedIssuers[issuerId];

    if (!issuer?.publicKeyPem) {
      return {
        ok: false,
        issuerId,
        reason: `Trusted issuer configuration missing for ${issuerId || 'unknown issuer'}.`
      };
    }

    const publicKey = await crypto.subtle.importKey(
      'spki',
      pemToArrayBuffer(issuer.publicKeyPem),
      { name: 'RSA-PSS', hash: 'SHA-256' },
      false,
      ['verify']
    );

    const verification = await verifyRsaPssSignature(
      publicKey,
      bytesFromBase64Url(signatureB64),
      toUtf8Bytes(`${headerB64}.${payloadB64}`)
    );

    if (!verification.ok) {
      return {
        ok: false,
        issuerId,
        issuerName: issuer.name || issuerId,
        reason: 'Signature mismatch against the trusted issuer key.'
      };
    }

    if (expectedCid && payload.cid && String(payload.cid) !== String(expectedCid)) {
      return {
        ok: false,
        issuerId,
        issuerName: issuer.name || issuerId,
        reason: 'Credential ID mismatch between the signed payload and the link.'
      };
    }

    if (payload.pd && payloadText) {
      const qdHash = await sha256Hex(payloadText);
      if (qdHash !== payload.pd) {
        return {
          ok: false,
          issuerId,
          issuerName: issuer.name || issuerId,
          reason: 'Payload digest mismatch. The QR contents appear altered.'
        };
      }
    }

    return {
      ok: true,
      issuerId,
      issuerName: issuer.name || issuerId,
      algorithm: header.alg || issuer.algorithm || 'PS256',
      signatureProfile: verification.profile,
      reason: verification.profile === 'ps256-standard'
        ? 'Offline signature validation passed.'
        : 'Offline signature validation passed using legacy issuer compatibility.'
    };
  } catch (error) {
    return {
      ok: false,
      reason: `Token verification error: ${String(error)}`.slice(0, 220)
    };
  }
}

async function verifyPayload(payload, sourceTag) {
  const parsed = parseQrPayload(payload);
  const decodedQd = await decodeQdPayload(parsed.qd);
  const offlineCheck = await verifyJwsToken(parsed.qk, decodedQd.payloadText, parsed.credentialId);

  return {
    decoded: decodedQd.parsed,
    offlineCheck,
    sourceTag,
    sourceHost: parsed.sourceHost,
    hostTrusted: parsed.hostTrusted,
    verificationUrl: parsed.sourceUrl,
    verifiedAt: new Date().toISOString()
  };
}

function storeResult(resultState) {
  sessionStorage.setItem(RESULT_STORE_KEY, JSON.stringify(resultState));
}

function readStoredResult() {
  try {
    const raw = sessionStorage.getItem(RESULT_STORE_KEY);
    return raw ? JSON.parse(raw) : null;
  } catch {
    return null;
  }
}

async function persistAndRedirect(payload, sourceTag) {
  const resultState = await verifyPayload(payload, sourceTag);
  storeResult(resultState);
  window.location.assign('./result.html');
}

function setFeedback(id, text, tone) {
  const node = $(id);
  if (!node) {
    return;
  }

  const tones = {
    idle: 'mt-4 rounded-lg border border-slate-200 bg-white px-4 py-3 text-sm text-slate-600',
    info: 'mt-4 rounded-lg border border-primary/20 bg-primary/5 px-4 py-3 text-sm text-primary',
    success: 'mt-4 rounded-lg border border-emerald-200 bg-emerald-50 px-4 py-3 text-sm text-emerald-700',
    error: 'mt-4 rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700'
  };

  node.className = tones[tone] || tones.idle;
  node.textContent = text;
}

function renderErrorState(title, message) {
  const heading = $('resultHeading');
  const badge = $('statusBadge');
  const card = $('resultCard');

  if (heading) heading.textContent = title;
  if (badge) {
    badge.className = 'inline-flex items-center rounded-full border border-red-200 bg-red-50 px-3 py-1 text-[11px] font-bold uppercase tracking-[0.08em] text-red-700';
    badge.textContent = 'Invalid';
  }
  if (card) {
    card.innerHTML = `
      <section class="rounded-lg border border-red-200 bg-white p-6">
        <h2 class="text-xl font-semibold text-slate-900">${escapeHtml(title)}</h2>
        <p class="mt-3 text-sm leading-6 text-slate-600">${escapeHtml(message)}</p>
      </section>
    `;
  }
}

function detailItem(label, value) {
  return `
    <div class="rounded-lg border border-slate-200 bg-white p-4">
      <div class="text-[11px] font-semibold uppercase tracking-[0.08em] text-slate-500">${escapeHtml(label)}</div>
      <div class="mt-2 break-words text-sm font-medium leading-6 text-slate-900">${escapeHtml(formatValue(value))}</div>
    </div>
  `;
}

function renderResultState(resultState) {
  const { decoded, offlineCheck, sourceTag, sourceHost, hostTrusted, verificationUrl, verifiedAt } = resultState;
  const ok = Boolean(offlineCheck?.ok);
  const heading = $('resultHeading');
  const badge = $('statusBadge');
  const card = $('resultCard');

  if (heading) {
    heading.textContent = ok ? 'Credential verified' : 'Verification needs review';
  }

  if (badge) {
    badge.className = ok
      ? 'inline-flex items-center rounded-full border border-emerald-200 bg-emerald-50 px-3 py-1 text-[11px] font-bold uppercase tracking-[0.08em] text-emerald-700'
      : 'inline-flex items-center rounded-full border border-amber-200 bg-amber-50 px-3 py-1 text-[11px] font-bold uppercase tracking-[0.08em] text-amber-700';
    badge.textContent = ok ? 'Verified' : 'Review';
  }

  if (!card) {
    return;
  }

  card.innerHTML = `
    <section class="rounded-lg border border-slate-200 bg-white p-6">
      <div class="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
        <div class="max-w-3xl">
          <div class="text-[11px] font-bold uppercase tracking-[0.08em] text-primary">Verification summary</div>
          <h2 class="mt-2 text-2xl font-semibold text-slate-900">${ok ? 'Offline issuer validation passed' : 'Offline issuer validation failed'}</h2>
          <p class="mt-3 text-sm leading-6 text-slate-600">${escapeHtml(offlineCheck?.reason || 'No verification details available.')}</p>
        </div>
        <div class="rounded-lg border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-slate-600">
          Verified at<br />
          <span class="font-medium text-slate-900">${escapeHtml(new Date(verifiedAt).toLocaleString())}</span>
        </div>
      </div>

      <div class="mt-5 grid gap-3 md:grid-cols-2 xl:grid-cols-4">
        ${detailItem('Issuer', offlineCheck?.issuerName || offlineCheck?.issuerId || 'Unknown')}
        ${detailItem('Algorithm', offlineCheck?.algorithm || 'PS256')}
        ${detailItem('Source', sourceTag || 'Unknown')}
        ${detailItem('Host', `${hostTrusted ? 'Trusted' : 'Unlisted'}: ${sourceHost || 'Unknown'}`)}
      </div>
    </section>

    <section class="rounded-lg border border-slate-200 bg-white p-6">
      <div class="flex flex-col gap-4 md:flex-row md:items-end md:justify-between">
        <div>
          <div class="text-[11px] font-bold uppercase tracking-[0.08em] text-primary">Credential ID</div>
          <div id="credentialIdValue" class="mt-2 break-all rounded-lg border border-slate-200 bg-slate-50 px-4 py-3 font-mono text-sm text-slate-900">${escapeHtml(decoded.cid || 'N/A')}</div>
        </div>
        <div class="flex flex-wrap gap-3">
          <button id="copyCredentialBtn" type="button" class="rounded-lg bg-primary px-4 py-3 text-sm font-semibold text-white">Copy Credential ID</button>
          <a href="${escapeHtml(verificationUrl || './index.html')}" target="_blank" rel="noreferrer" class="rounded-lg border border-slate-300 bg-white px-4 py-3 text-sm font-semibold text-slate-700">Open Source Link</a>
        </div>
      </div>
    </section>

    <section class="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
      ${detailItem('Name', decoded.name)}
      ${detailItem('Student ID', decoded.studentId)}
      ${detailItem('Degree', decoded.degree)}
      ${detailItem('Department', decoded.department)}
      ${detailItem('Student Status', decoded.studentStatus)}
      ${detailItem('College', decoded.college)}
      ${detailItem('University', decoded.university)}
      ${detailItem('CGPA', decoded.cgpa)}
      ${detailItem('Graduation Year', decoded.graduationYear)}
      ${detailItem('Batch', decoded.batch)}
      ${detailItem('Conduct', decoded.conduct)}
      ${detailItem('Backlog Count', decoded.backlogCount ?? '0')}
      ${detailItem('Courses', decoded.courses)}
      ${detailItem('Backlogs', decoded.backlogs)}
      ${detailItem('Issue Date', decoded.issueDate)}
      ${detailItem('Semester', decoded.semester)}
      ${detailItem('Year', decoded.year)}
      ${detailItem('Section', decoded.section)}
      ${detailItem('IPFS CID', decoded.ipfsCid)}
    </section>
  `;

  const copyButton = $('copyCredentialBtn');
  if (copyButton) {
    copyButton.addEventListener('click', async () => {
      try {
        await navigator.clipboard.writeText(decoded.cid || '');
        copyButton.textContent = 'Copied';
      } catch {
        copyButton.textContent = 'Copy failed';
      }
      setTimeout(() => {
        copyButton.textContent = 'Copy Credential ID';
      }, 1200);
    });
  }
}

function getLandingPayloadFromUrl() {
  const params = new URLSearchParams(window.location.search);
  if (!params.get('id') || !params.get('qk') || !params.get('qd')) {
    return null;
  }
  return window.location.href;
}

async function initResultPage() {
  await loadIssuerRegistry();

  const landingPayload = getLandingPayloadFromUrl();
  if (landingPayload) {
    try {
      const resultState = await verifyPayload(landingPayload, 'direct-link');
      storeResult(resultState);
      renderResultState(resultState);
      return;
    } catch (error) {
      renderErrorState('Verification failed', String(error));
      return;
    }
  }

  const stored = readStoredResult();
  if (stored) {
    renderResultState(stored);
    return;
  }

  renderErrorState('No verification loaded', 'Open this page from a QR, image upload, or pasted verification URL.');
}

function stopScanner(video) {
  if (activeControls && typeof activeControls.stop === 'function') {
    try {
      activeControls.stop();
    } catch {
      // Ignore scanner stop error.
    }
  }
  activeControls = null;

  const stream = video?.srcObject;
  if (stream?.getTracks) {
    stream.getTracks().forEach(track => {
      try {
        track.stop();
      } catch {
        // Ignore track stop error.
      }
    });
  }

  if (video) {
    video.srcObject = null;
  }
}

async function initScanPage() {
  await loadIssuerRegistry();

  const startBtn = $('startScanBtn');
  const stopBtn = $('stopScanBtn');
  const camera = $('camera');

  startBtn?.addEventListener('click', async () => {
    if (!codeReader || activeControls) {
      return;
    }

    startBtn.disabled = true;
    stopBtn.disabled = false;
    setFeedback('scanFeedback', 'Opening camera and waiting for a QR...', 'info');

    const prefersRearCamera = Boolean(window.matchMedia && window.matchMedia('(pointer: coarse)').matches);
    const constraints = {
      video: {
        facingMode: prefersRearCamera ? { ideal: 'environment' } : { ideal: 'user' }
      }
    };

    const onResult = async result => {
      if (!result?.text) {
        return;
      }

      stopScanner(camera);
      setFeedback('scanFeedback', 'QR captured. Redirecting to result...', 'success');
      try {
        await persistAndRedirect(result.text, 'camera-scan');
      } catch (error) {
        setFeedback('scanFeedback', String(error), 'error');
        startBtn.disabled = false;
        stopBtn.disabled = true;
      }
    };

    try {
      if (typeof codeReader.decodeFromConstraints === 'function') {
        activeControls = await codeReader.decodeFromConstraints(constraints, camera, onResult);
      } else {
        activeControls = await codeReader.decodeFromVideoDevice(null, camera, onResult);
      }
    } catch (error) {
      stopScanner(camera);
      startBtn.disabled = false;
      stopBtn.disabled = true;
      setFeedback('scanFeedback', `Camera error: ${String(error)}`, 'error');
    }
  });

  stopBtn?.addEventListener('click', () => {
    stopScanner(camera);
    startBtn.disabled = false;
    stopBtn.disabled = true;
    setFeedback('scanFeedback', 'Camera stopped.', 'idle');
  });
}

async function decodeImageWithJsQr(image) {
  if (typeof jsQR === 'undefined') {
    throw new Error('QR image decode fallback unavailable in this browser.');
  }

  const attempts = [
    { scale: 1, threshold: null },
    { scale: 2, threshold: null },
    { scale: 3, threshold: null },
    { scale: 2, threshold: 180 },
    { scale: 3, threshold: 160 }
  ];

  for (const attempt of attempts) {
    const canvas = document.createElement('canvas');
    canvas.width = Math.max(1, Math.floor(image.naturalWidth * attempt.scale));
    canvas.height = Math.max(1, Math.floor(image.naturalHeight * attempt.scale));
    const context = canvas.getContext('2d', { willReadFrequently: true });
    context.imageSmoothingEnabled = false;
    context.drawImage(image, 0, 0, canvas.width, canvas.height);
    const imageData = context.getImageData(0, 0, canvas.width, canvas.height);

    if (attempt.threshold !== null) {
      for (let i = 0; i < imageData.data.length; i += 4) {
        const avg = (imageData.data[i] + imageData.data[i + 1] + imageData.data[i + 2]) / 3;
        const value = avg > attempt.threshold ? 255 : 0;
        imageData.data[i] = value;
        imageData.data[i + 1] = value;
        imageData.data[i + 2] = value;
      }
      context.putImageData(imageData, 0, 0);
    }

    const decoded = jsQR(imageData.data, imageData.width, imageData.height, {
      inversionAttempts: 'attemptBoth'
    });

    if (decoded?.data) {
      return decoded.data;
    }
  }

  throw new Error('No readable QR was found in the uploaded image.');
}

async function decodeQrFromImageFile(file) {
  if (!file) {
    throw new Error('Choose a QR image first.');
  }

  let imageUrl = null;
  try {
    imageUrl = URL.createObjectURL(file);
    const image = new Image();
    image.src = imageUrl;

    await new Promise((resolve, reject) => {
      image.onload = resolve;
      image.onerror = reject;
    });

    if (codeReader) {
      try {
        const result = await codeReader.decodeFromImageElement(image);
        if (result?.text) {
          return result.text;
        }
      } catch {
        // Continue to jsQR fallback.
      }
    }

    return await decodeImageWithJsQr(image);
  } finally {
    if (imageUrl) {
      URL.revokeObjectURL(imageUrl);
    }
  }
}

async function initUploadPage() {
  await loadIssuerRegistry();

  const qrFile = $('qrFile');
  const dropzone = $('uploadDropzone');

  async function handleFile(file) {
    try {
      setFeedback('uploadFeedback', 'Reading QR image...', 'info');
      const payload = await decodeQrFromImageFile(file);
      setFeedback('uploadFeedback', 'QR found. Redirecting to result...', 'success');
      await persistAndRedirect(payload, 'image-upload');
    } catch (error) {
      setFeedback('uploadFeedback', String(error), 'error');
    }
  }

  qrFile?.addEventListener('change', event => {
    const file = event.target.files?.[0];
    handleFile(file);
  });

  if (dropzone) {
    ['dragenter', 'dragover'].forEach(eventName => {
      dropzone.addEventListener(eventName, event => {
        event.preventDefault();
        dropzone.classList.add('border-primary');
      });
    });

    ['dragleave', 'drop'].forEach(eventName => {
      dropzone.addEventListener(eventName, event => {
        event.preventDefault();
        dropzone.classList.remove('border-primary');
      });
    });

    dropzone.addEventListener('drop', event => {
      const file = event.dataTransfer?.files?.[0];
      handleFile(file);
    });
  }
}

async function initLinkPage() {
  await loadIssuerRegistry();

  const input = $('qrLinkInput');
  const button = $('verifyLinkBtn');

  async function submit() {
    const link = String(input?.value || '').trim();
    if (!link) {
      setFeedback('linkFeedback', 'Enter the verification URL first.', 'error');
      return;
    }

    try {
      setFeedback('linkFeedback', 'Verifying URL and redirecting to result...', 'info');
      await persistAndRedirect(link, 'manual-link');
    } catch (error) {
      setFeedback('linkFeedback', String(error), 'error');
    }
  }

  button?.addEventListener('click', submit);
}

document.addEventListener('DOMContentLoaded', async () => {
  if (page === 'scan') {
    await initScanPage();
  } else if (page === 'upload') {
    await initUploadPage();
  } else if (page === 'link') {
    await initLinkPage();
  } else if (page === 'result') {
    await initResultPage();
  }
});
