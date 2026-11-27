(() => {
  "use strict";

  const STORAGE_KEY = "outsider_trusted_clients_v1";
  const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
  const BECH32_GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
  const textEncoder = new TextEncoder();

  function concatBytes(...parts) {
    let total = 0;
    for (const p of parts) total += p.length;
    const out = new Uint8Array(total);
    let offset = 0;
    for (const p of parts) {
      out.set(p, offset);
      offset += p.length;
    }
    return out;
  }

  function b64uEncode(bytes) {
    const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
    let binary = "";
    for (let i = 0; i < u8.length; i++) {
      binary += String.fromCharCode(u8[i]);
    }
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  }

  function b64uDecode(str) {
    if (typeof str !== "string" || !/^[A-Za-z0-9_-]*$/.test(str)) {
      throw new Error("Invalid base64url string");
    }
    const pad = (4 - (str.length % 4)) % 4;
    const base64 = str.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat(pad);
    const binary = atob(base64);
    const out = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      out[i] = binary.charCodeAt(i);
    }
    return out;
  }

  function bech32Polymod(values) {
    let chk = 1;
    for (const v of values) {
      const top = chk >>> 25;
      chk = ((chk & 0x1ffffff) << 5) ^ v;
      for (let i = 0; i < 5; i++) {
        if ((top >>> i) & 1) {
          chk ^= BECH32_GEN[i];
        }
      }
    }
    return chk >>> 0;
  }

  function bech32HrpExpand(hrp) {
    const out = [];
    for (let i = 0; i < hrp.length; i++) out.push(hrp.charCodeAt(i) >>> 5);
    out.push(0);
    for (let i = 0; i < hrp.length; i++) out.push(hrp.charCodeAt(i) & 31);
    return out;
  }

  function bech32CreateChecksum(hrp, data5) {
    const values = bech32HrpExpand(hrp).concat(data5, [0, 0, 0, 0, 0, 0]);
    const polymod = bech32Polymod(values) ^ 1; // BIP-173 Bech32 constant (1), as required by age v1.
    const out = [];
    for (let i = 0; i < 6; i++) {
      out.push((polymod >>> (5 * (5 - i))) & 31);
    }
    return out;
  }

  function convertBits(bytes, fromBits, toBits, pad) {
    let acc = 0;
    let bits = 0;
    const maxv = (1 << toBits) - 1;
    const out = [];
    for (const b of bytes) {
      acc = (acc << fromBits) | b;
      bits += fromBits;
      while (bits >= toBits) {
        bits -= toBits;
        out.push((acc >>> bits) & maxv);
      }
    }
    if (pad && bits > 0) {
      out.push((acc << (toBits - bits)) & maxv);
    }
    return out;
  }

  function generateAgeSecretKey(randomBytesOverride) {
    let raw;
    if (randomBytesOverride !== undefined) {
      raw = randomBytesOverride instanceof Uint8Array
        ? new Uint8Array(randomBytesOverride)
        : new Uint8Array(randomBytesOverride);
      if (raw.length !== 32) {
        throw new Error("age secret key requires exactly 32 random bytes");
      }
    } else {
      raw = crypto.getRandomValues(new Uint8Array(32));
    }
    const hrp = "age-secret-key-";
    const data5 = convertBits(raw, 8, 5, true);
    const checksum = bech32CreateChecksum(hrp, data5);
    raw.fill(0);
    let encoded = `${hrp}1`;
    for (const v of data5) encoded += BECH32_CHARSET[v];
    for (const v of checksum) encoded += BECH32_CHARSET[v];
    return encoded.toUpperCase();
  }

  function isSopsKeygenCommand(cmdSummary) {
    if (typeof cmdSummary !== "string") return false;
    return cmdSummary.startsWith("[sops:init ") || cmdSummary.startsWith("[register-sops-key] ");
  }

  function encodeStr(s) {
    const bytes = textEncoder.encode(s || "");
    const out = new Uint8Array(4 + bytes.length);
    new DataView(out.buffer).setUint32(0, bytes.length, false);
    out.set(bytes, 4);
    return out;
  }

  function encodeContextBytes(ctx) {
    return concatBytes(
      textEncoder.encode("outsider-ctx-v1"),
      Uint8Array.of(0),
      encodeStr(ctx.name),
      encodeStr(ctx.reason),
      encodeStr(ctx.command_summary)
    );
  }

  async function computeContextHash(ctx) {
    const bytes = encodeContextBytes(ctx);
    const digest = await crypto.subtle.digest("SHA-256", bytes);
    return new Uint8Array(digest);
  }

  function buildSignInput(idPkBytes, pkReqBytes, contextHashBytes, requestTs, ttlSecs, nonceBytes) {
    if (idPkBytes.length !== 32) throw new Error("id_pk must be 32 bytes");
    if (pkReqBytes.length !== 32) throw new Error("pk_req must be 32 bytes");
    if (contextHashBytes.length !== 32) throw new Error("context_hash must be 32 bytes");
    if (nonceBytes.length !== 16) throw new Error("request_nonce must be 16 bytes");
    if (!Number.isSafeInteger(requestTs) || requestTs < 0) throw new Error("invalid request_ts");
    if (!Number.isInteger(ttlSecs) || ttlSecs < 0 || ttlSecs > 0xffffffff) throw new Error("invalid ttl_secs");

    const tsBuf = new Uint8Array(8);
    new DataView(tsBuf.buffer).setBigUint64(0, BigInt(requestTs), false);
    const ttlBuf = new Uint8Array(4);
    new DataView(ttlBuf.buffer).setUint32(0, ttlSecs, false);

    return concatBytes(
      textEncoder.encode("outsider-req-v1"),
      Uint8Array.of(0),
      idPkBytes,
      pkReqBytes,
      contextHashBytes,
      tsBuf,
      ttlBuf,
      nonceBytes
    );
  }

  async function computeFingerprint(idPkBytes) {
    if (idPkBytes.length !== 32) throw new Error("id_pk must be 32 bytes");
    const input = concatBytes(textEncoder.encode("outsider-id-fp-v1"), idPkBytes);
    const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", input));
    const head = digest.slice(0, 5);
    let bits = 0;
    let value = 0;
    let b32 = "";
    for (const b of head) {
      value = (value << 8) | b;
      bits += 8;
      while (bits >= 5) {
        b32 += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
        bits -= 5;
      }
    }
    if (bits > 0) {
      b32 += BASE32_ALPHABET[(value << (5 - bits)) & 31];
    }
    return `${b32.slice(0, 4)}-${b32.slice(4, 8)}`;
  }

  async function verifyRequestSignature(req) {
    const idPkBytes = b64uDecode(req.id_pk);
    const pkReqBytes = b64uDecode(req.pk_req);
    const nonceBytes = b64uDecode(req.request_nonce);
    const sigBytes = b64uDecode(req.sig);
    if (sigBytes.length !== 64) {
      return { valid: false, contextHash: null, idPkBytes: null, pkReqBytes: null };
    }
    const contextHash = await computeContextHash(req.context);
    const signInput = buildSignInput(
      idPkBytes,
      pkReqBytes,
      contextHash,
      req.request_ts,
      req.ttl_secs,
      nonceBytes
    );
    const pubKey = await crypto.subtle.importKey(
      "raw",
      idPkBytes,
      { name: "Ed25519" },
      false,
      ["verify"]
    );
    const valid = await crypto.subtle.verify({ name: "Ed25519" }, pubKey, sigBytes, signInput);
    return { valid, contextHash, idPkBytes, pkReqBytes };
  }

  function buildAad(sessionId, contextHashBytes) {
    return concatBytes(
      textEncoder.encode("outsider-v1"),
      Uint8Array.of(0),
      textEncoder.encode(sessionId),
      Uint8Array.of(0),
      contextHashBytes
    );
  }

  async function encryptSecretEnvelope(secretValue, sessionId, pkReqBytes, contextHashBytes, testOverrides) {
    if (pkReqBytes.length !== 32) throw new Error("pk_req must be 32 bytes");
    if (contextHashBytes.length !== 32) throw new Error("context_hash must be 32 bytes");

    let ephemeralPair;
    if (testOverrides && testOverrides.ephemeralKeyPair) {
      ephemeralPair = testOverrides.ephemeralKeyPair;
    } else {
      ephemeralPair = await crypto.subtle.generateKey({ name: "X25519" }, true, ["deriveBits"]);
    }

    const epkBytes = new Uint8Array(await crypto.subtle.exportKey("raw", ephemeralPair.publicKey));
    const pkReqKey = await crypto.subtle.importKey("raw", pkReqBytes, { name: "X25519" }, false, []);
    const ss = new Uint8Array(
      await crypto.subtle.deriveBits({ name: "X25519", public: pkReqKey }, ephemeralPair.privateKey, 256)
    );
    if (ss.length !== 32 || ss.every((b) => b === 0)) {
      throw new Error("Non-contributory X25519 shared secret");
    }

    const hkdfKey = await crypto.subtle.importKey("raw", ss, "HKDF", false, ["deriveKey"]);
    const salt = textEncoder.encode(sessionId);
    const info = concatBytes(textEncoder.encode("outsider-v1-aead-key"), pkReqBytes, epkBytes);
    const aeadKey = await crypto.subtle.deriveKey(
      { name: "HKDF", hash: "SHA-256", salt, info },
      hkdfKey,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt"]
    );

    const aad = buildAad(sessionId, contextHashBytes);
    const nonce = (testOverrides && testOverrides.nonce) ? testOverrides.nonce : crypto.getRandomValues(new Uint8Array(12));
    const plaintextBytes = textEncoder.encode(JSON.stringify({ v: 1, secret: secretValue }));

    const ciphertext = new Uint8Array(
      await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: nonce, additionalData: aad, tagLength: 128 },
        aeadKey,
        plaintextBytes
      )
    );

    ss.fill(0);
    plaintextBytes.fill(0);

    return {
      v: 1,
      epk: b64uEncode(epkBytes),
      nonce: b64uEncode(nonce),
      ciphertext: b64uEncode(ciphertext),
    };
  }

  function evaluateTofu(entries, idPkB64u, clientName) {
    const byKey = entries.find((e) => e.id_pk === idPkB64u);
    if (byKey) {
      return { state: "trusted", entry: byKey };
    }
    const byName = entries.find((e) => e.name === clientName);
    if (byName) {
      return { state: "conflict", existing: byName };
    }
    return { state: "untrusted" };
  }

  function loadTrustedClients() {
    try {
      const raw = window.localStorage.getItem(STORAGE_KEY);
      if (!raw) return [];
      const parsed = JSON.parse(raw);
      return Array.isArray(parsed) ? parsed : [];
    } catch {
      return [];
    }
  }

  function saveTrustedClients(entries) {
    window.localStorage.setItem(STORAGE_KEY, JSON.stringify(entries));
  }

  async function checkWebCryptoSupport() {
    if (!globalThis.crypto || !globalThis.crypto.subtle) return false;
    try {
      await crypto.subtle.generateKey({ name: "Ed25519" }, false, ["sign", "verify"]);
      await crypto.subtle.generateKey({ name: "X25519" }, false, ["deriveBits"]);
      return true;
    } catch {
      return false;
    }
  }

  function parseApprovePath(pathname) {
    const m = /^\/approve\/([^/]+)\/([^/]+)\/?$/.exec(pathname);
    if (!m) return null;
    return {
      nameSlug: decodeURIComponent(m[1]),
      approveToken: decodeURIComponent(m[2]),
    };
  }

  // Expose pure protocol/TOFU/keygen functions for automated Node.js verification.
  globalThis.__OUTSIDER_CRYPTO__ = {
    b64uEncode,
    b64uDecode,
    generateAgeSecretKey,
    isSopsKeygenCommand,
    encodeContextBytes,
    computeContextHash,
    buildSignInput,
    computeFingerprint,
    verifyRequestSignature,
    buildAad,
    encryptSecretEnvelope,
    evaluateTofu,
    parseApprovePath,
  };

  if (typeof document === "undefined") {
    return;
  }

  document.addEventListener("DOMContentLoaded", async () => {
    const countdownEl = document.getElementById("countdown");
    const alertBox = document.getElementById("alert-box");
    const tofuBox = document.getElementById("tofu-box");
    const tofuMessage = document.getElementById("tofu-message");
    const trustBtn = document.getElementById("trust-btn");
    const contextSection = document.getElementById("context-section");
    const formSection = document.getElementById("form-section");

    const ctxDeviceEl = document.getElementById("ctx-device");
    const ctxNameEl = document.getElementById("ctx-name");
    const ctxReasonEl = document.getElementById("ctx-reason");
    const ctxCommandEl = document.getElementById("ctx-command");

    const usernameInput = document.getElementById("username");
    const secretSingle = document.getElementById("secret-single");
    const secretMulti = document.getElementById("secret-multi");
    const secretLabel = document.getElementById("secret-label");
    const copyNameBtn = document.getElementById("copy-name-btn");
    const pasteBtn = document.getElementById("paste-btn");
    const genAgeBtn = document.getElementById("gen-age-btn");
    const ageSaveBox = document.getElementById("age-save-box");
    const copyAgeBtn = document.getElementById("copy-age-btn");
    const ageSavedCheckbox = document.getElementById("age-saved-checkbox");
    const toggleModeBtn = document.getElementById("toggle-mode-btn");
    const submitBtn = document.getElementById("submit-btn");
    const secretForm = document.getElementById("secret-form");

    const trustedCountEl = document.getElementById("trusted-count");
    const trustedListEl = document.getElementById("trusted-list");
    const trustedEmptyEl = document.getElementById("trusted-empty");

    let activeState = null; // { approveToken, req, contextHash, pkReqBytes, fp, trusted, locked }
    let multilineMode = false;
    let generatedAgeKey = null;
    let timerId = null;

    function showAlert(message, kind) {
      alertBox.hidden = false;
      alertBox.className = kind === "ok" ? "status-ok" : kind === "warn" ? "status-warn" : "status-err";
      alertBox.textContent = message;
    }

    function clearAlert() {
      alertBox.hidden = true;
      alertBox.textContent = "";
    }

    function clearGeneratedAgeGuard() {
      generatedAgeKey = null;
      if (ageSaveBox) ageSaveBox.hidden = true;
      if (ageSavedCheckbox) ageSavedCheckbox.checked = false;
    }

    function lockForm(reasonText) {
      if (activeState) activeState.locked = true;
      submitBtn.disabled = true;
      secretSingle.disabled = true;
      secretMulti.disabled = true;
      pasteBtn.disabled = true;
      if (genAgeBtn) genAgeBtn.disabled = true;
      if (copyAgeBtn) copyAgeBtn.disabled = true;
      if (ageSavedCheckbox) ageSavedCheckbox.disabled = true;
      clearGeneratedAgeGuard();
      toggleModeBtn.disabled = true;
      trustBtn.hidden = true;
      if (timerId !== null) {
        clearInterval(timerId);
        timerId = null;
      }
      if (reasonText) {
        countdownEl.textContent = reasonText;
      }
    }

    function updateSubmitEnabled() {
      if (!activeState || activeState.locked || !activeState.trusted) {
        submitBtn.disabled = true;
        return;
      }
      if (generatedAgeKey !== null && (!ageSavedCheckbox || !ageSavedCheckbox.checked)) {
        submitBtn.disabled = true;
        return;
      }
      submitBtn.disabled = false;
    }

    function syncGeneratedAgeGuardWithInput() {
      if (generatedAgeKey === null) return;
      const activeInput = multilineMode ? secretMulti : secretSingle;
      if (activeInput.value !== generatedAgeKey) {
        clearGeneratedAgeGuard();
        updateSubmitEnabled();
      }
    }

    function renderTrustedList() {
      const entries = loadTrustedClients();
      trustedCountEl.textContent = String(entries.length);
      trustedListEl.textContent = "";
      trustedEmptyEl.hidden = entries.length > 0;

      for (const entry of entries) {
        const li = document.createElement("li");
        const label = document.createElement("span");
        const when = entry.trusted_at ? new Date(entry.trusted_at).toLocaleString() : "";
        label.textContent = `${entry.name} (${entry.fp})${when ? " — " + when : ""} `;
        const removeBtn = document.createElement("button");
        removeBtn.type = "button";
        removeBtn.textContent = "移除";
        removeBtn.addEventListener("click", () => {
          const next = loadTrustedClients().filter((e) => e.id_pk !== entry.id_pk);
          saveTrustedClients(next);
          renderTrustedList();
          if (activeState && !activeState.locked) {
            refreshTofuBanner();
          }
        });
        li.appendChild(label);
        li.appendChild(removeBtn);
        trustedListEl.appendChild(li);
      }
    }

    function refreshTofuBanner() {
      const entries = loadTrustedClients();
      const res = evaluateTofu(entries, activeState.req.id_pk, activeState.req.client_name);
      tofuBox.hidden = false;

      if (res.state === "trusted") {
        activeState.trusted = true;
        tofuBox.className = "status-ok";
        tofuMessage.textContent = `✓ 已验证信任设备：${res.entry.name}（指纹 ${activeState.fp}）`;
        trustBtn.hidden = true;
      } else if (res.state === "conflict") {
        activeState.trusted = false;
        tofuBox.className = "status-err";
        tofuMessage.textContent =
          `高危告警：设备名「${activeState.req.client_name}」的公钥发生突变！` +
          `本地记录指纹为 ${res.existing.fp}，本次请求指纹为 ${activeState.fp}。` +
          `已阻止提交，请先核实并在下方「本地已信任设备」移除旧公钥后再重试。`;
        trustBtn.hidden = true;
      } else {
        activeState.trusted = false;
        tofuBox.className = "status-warn";
        tofuMessage.textContent =
          `首次遇到的申请端设备：${activeState.req.client_name}（公钥指纹：${activeState.fp}）。` +
          `请与终端显示核对无误后点击下方按钮信任。`;
        trustBtn.hidden = false;
      }
      updateSubmitEnabled();
    }

    renderTrustedList();

    const supported = await checkWebCryptoSupport();
    if (!supported) {
      countdownEl.textContent = "浏览器不支持原生 WebCrypto";
      showAlert(
        "当前浏览器不支持原生 WebCrypto Ed25519 / X25519，请使用 Safari 17+、Chrome 133+ 或 Firefox 130+ 打开此页面。",
        "err"
      );
      return;
    }

    const parsedPath = parseApprovePath(window.location.pathname);
    if (!parsedPath) {
      countdownEl.textContent = "无效的审批链接";
      showAlert("审批路径格式不正确，请从通知中的原始链接打开。", "err");
      return;
    }

    // Scrub approve_token from the address bar while preserving /approve/<name_slug>/ for Bitwarden prefix match.
    try {
      window.history.replaceState(null, "", `/approve/${encodeURIComponent(parsedPath.nameSlug)}/`);
    } catch {
      // Ignore if restricted by browser context.
    }

    let reqData;
    try {
      const resp = await fetch(`/v1/approve/${encodeURIComponent(parsedPath.approveToken)}`, {
        method: "GET",
        cache: "no-store",
        credentials: "same-origin",
      });
      if (!resp.ok) {
        const errBody = await resp.json().catch(() => ({}));
        const reason = errBody.error || `HTTP ${resp.status}`;
        countdownEl.textContent = "请求不可用";
        showAlert(`无法加载审批请求：${reason}`, "err");
        return;
      }
      reqData = await resp.json();
    } catch (err) {
      countdownEl.textContent = "网络错误";
      showAlert(`拉取审批请求失败：${err.message}`, "err");
      return;
    }

    if (reqData.v !== 1) {
      countdownEl.textContent = "协议版本不支持";
      showAlert(`不支持的协议版本：v=${reqData.v}`, "err");
      return;
    }

    if (reqData.status !== "pending") {
      const statusText = {
        approved: "此请求已被批准发送。",
        consumed: "此请求已被申请端消费完成。",
        cancelled: "此请求已被申请端取消。",
        expired: "此请求已过期。",
      }[reqData.status] || `请求状态：${reqData.status}`;
      countdownEl.textContent = statusText;
      showAlert(statusText, "warn");
      return;
    }

    const expiresAtMs = Date.parse(reqData.expires_at);
    if (!Number.isFinite(expiresAtMs) || Date.now() >= expiresAtMs) {
      countdownEl.textContent = "请求已过期";
      showAlert("该审批请求已过期，请关闭此页面。", "warn");
      return;
    }

    let verifyRes;
    try {
      verifyRes = await verifyRequestSignature(reqData);
    } catch (err) {
      countdownEl.textContent = "签名校验异常";
      showAlert(`请求签名校验失败（疑似被篡改）：${err.message}`, "err");
      return;
    }

    if (!verifyRes.valid) {
      countdownEl.textContent = "签名校验失败";
      showAlert("安全阻断：申请端 Ed25519 签名验证失败，公钥或上下文可能遭到篡改！", "err");
      return;
    }

    const fp = await computeFingerprint(verifyRes.idPkBytes);

    activeState = {
      approveToken: parsedPath.approveToken,
      req: reqData,
      contextHash: verifyRes.contextHash,
      pkReqBytes: verifyRes.pkReqBytes,
      fp,
      trusted: false,
      locked: false,
    };

    ctxDeviceEl.textContent = `${reqData.client_name}（指纹 ${fp}）`;
    ctxNameEl.textContent = reqData.context.name;
    ctxReasonEl.textContent = reqData.context.reason || "（未填写）";
    ctxCommandEl.textContent = reqData.context.command_summary || "（无命令摘要）";
    usernameInput.value = reqData.context.name;

    if (genAgeBtn && isSopsKeygenCommand(reqData.context.command_summary)) {
      genAgeBtn.hidden = false;
    }

    contextSection.hidden = false;
    formSection.hidden = false;

    refreshTofuBanner();

    function updateCountdown() {
      const remaining = Math.ceil((expiresAtMs - Date.now()) / 1000);
      if (remaining <= 0) {
        lockForm("请求已过期");
        showAlert("该审批请求已超时过期，可关闭此页面。", "warn");
        return;
      }
      countdownEl.textContent = `剩余有效时间：${remaining} 秒`;
    }
    updateCountdown();
    timerId = setInterval(updateCountdown, 1000);

    trustBtn.addEventListener("click", () => {
      if (!activeState || activeState.locked) return;
      const entries = loadTrustedClients();
      const check = evaluateTofu(entries, activeState.req.id_pk, activeState.req.client_name);
      if (check.state === "conflict") {
        refreshTofuBanner();
        return;
      }
      if (check.state === "untrusted") {
        entries.push({
          id_pk: activeState.req.id_pk,
          name: activeState.req.client_name,
          fp: activeState.fp,
          trusted_at: new Date().toISOString(),
        });
        saveTrustedClients(entries);
      }
      renderTrustedList();
      refreshTofuBanner();
    });

    copyNameBtn.addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(reqData.context.name);
        copyNameBtn.textContent = "已复制";
        setTimeout(() => { copyNameBtn.textContent = "复制名称"; }, 1500);
      } catch {
        showAlert("无法访问剪贴板，请手动复制密钥名称。", "warn");
      }
    });

    if (genAgeBtn) {
      genAgeBtn.addEventListener("click", () => {
        if (!activeState || activeState.locked) return;
        if (multilineMode) {
          toggleModeBtn.click();
        }
        const key = generateAgeSecretKey();
        secretSingle.value = key;
        generatedAgeKey = key;
        if (ageSaveBox) ageSaveBox.hidden = false;
        if (ageSavedCheckbox) ageSavedCheckbox.checked = false;
        clearAlert();
        updateSubmitEnabled();
      });
    }

    if (copyAgeBtn) {
      copyAgeBtn.addEventListener("click", async () => {
        if (!generatedAgeKey) return;
        try {
          await navigator.clipboard.writeText(generatedAgeKey);
          copyAgeBtn.textContent = "已复制私钥";
          setTimeout(() => { copyAgeBtn.textContent = "复制生成的私钥"; }, 1500);
        } catch {
          showAlert("无法访问剪贴板，请手动复制输入框中的私钥。", "warn");
        }
      });
    }

    if (ageSavedCheckbox) {
      ageSavedCheckbox.addEventListener("change", () => {
        updateSubmitEnabled();
      });
    }

    secretSingle.addEventListener("input", syncGeneratedAgeGuardWithInput);
    secretMulti.addEventListener("input", syncGeneratedAgeGuardWithInput);

    toggleModeBtn.addEventListener("click", () => {
      multilineMode = !multilineMode;
      if (multilineMode) {
        secretMulti.value = secretSingle.value;
        secretSingle.value = "";
        secretSingle.hidden = true;
        secretSingle.disabled = true;
        secretSingle.required = false;
        secretMulti.hidden = false;
        secretMulti.disabled = false;
        secretMulti.required = true;
        secretLabel.htmlFor = "secret-multi";
        toggleModeBtn.textContent = "切换为单行密码";
        secretMulti.focus();
      } else {
        secretSingle.value = secretMulti.value;
        secretMulti.value = "";
        secretMulti.hidden = true;
        secretMulti.disabled = true;
        secretMulti.required = false;
        secretSingle.hidden = false;
        secretSingle.disabled = false;
        secretSingle.required = true;
        secretLabel.htmlFor = "secret-single";
        toggleModeBtn.textContent = "切换为多行输入";
        secretSingle.focus();
      }
    });

    pasteBtn.addEventListener("click", async () => {
      try {
        const text = await navigator.clipboard.readText();
        if (!text) return;
        if (text.includes("\n") && !multilineMode) {
          toggleModeBtn.click();
        }
        const target = multilineMode ? secretMulti : secretSingle;
        target.value = text;
        syncGeneratedAgeGuardWithInput();
        clearAlert();
      } catch {
        showAlert("浏览器拒绝读取剪贴板，请直接在输入框内长按粘贴。", "warn");
      }
    });

    secretForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      if (!activeState || activeState.locked || !activeState.trusted) return;
      if (generatedAgeKey !== null && (!ageSavedCheckbox || !ageSavedCheckbox.checked)) {
        showAlert("请先将生成的 age 私钥保存到密码管理器并勾选确认框。", "warn");
        return;
      }

      const activeInput = multilineMode ? secretMulti : secretSingle;
      let secretVal = activeInput.value;
      if (!secretVal) {
        showAlert("请输入密钥内容。", "warn");
        return;
      }

      submitBtn.disabled = true;
      clearAlert();

      try {
        const envelope = await encryptSecretEnvelope(
          secretVal,
          activeState.req.session_id,
          activeState.pkReqBytes,
          activeState.contextHash
        );
        secretVal = "";

        const resp = await fetch(`/v1/approve/${encodeURIComponent(activeState.approveToken)}`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(envelope),
          cache: "no-store",
          credentials: "same-origin",
        });

        activeInput.value = "";
        secretSingle.value = "";
        secretMulti.value = "";

        if (!resp.ok) {
          const errBody = await resp.json().catch(() => ({}));
          const reason = errBody.error || `HTTP ${resp.status}`;
          if (resp.status === 409 || resp.status === 410 || resp.status === 404) {
            lockForm("请求已失效");
          } else {
            updateSubmitEnabled();
          }
          showAlert(`发送失败：${reason}`, "err");
          return;
        }

        lockForm("已加密发送");
        showAlert("已通过端到端加密发送至申请端，可安全关闭此页面。", "ok");
      } catch (err) {
        secretVal = "";
        updateSubmitEnabled();
        showAlert(`加密或发送失败：${err.message}`, "err");
      }
    });
  });
})();
