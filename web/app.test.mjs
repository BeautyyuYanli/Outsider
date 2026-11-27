import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const vectors = JSON.parse(
  fs.readFileSync(path.resolve(__dirname, "../protocol/test-vectors.json"), "utf8")
);

// Execute web/app.js in Node (document is undefined, so only pure crypto/TOFU/keygen hooks register).
await import("./app.js");
const api = globalThis.__OUTSIDER_CRYPTO__;
assert.ok(api, "app.js should expose __OUTSIDER_CRYPTO__");

function hexToBytes(h) {
  return new Uint8Array(Buffer.from(h, "hex"));
}
function bytesToHex(b) {
  return Buffer.from(b).toString("hex");
}

test("context_hash matches protocol/test-vectors.json", async () => {
  for (const v of vectors.context_vectors) {
    const bytes = api.encodeContextBytes({
      name: v.name,
      reason: v.reason,
      command_summary: v.command_summary,
    });
    assert.equal(bytesToHex(bytes), v.context_bytes_hex, v.label);
    const hash = await api.computeContextHash({
      name: v.name,
      reason: v.reason,
      command_summary: v.command_summary,
    });
    assert.equal(bytesToHex(hash), v.context_hash_hex, v.label);
    assert.equal(api.b64uEncode(hash), v.context_hash_b64u, v.label);
  }
});

test("fingerprint matches protocol/test-vectors.json", async () => {
  const fp = await api.computeFingerprint(api.b64uDecode(vectors.identity.id_pk_b64u));
  assert.equal(fp, vectors.identity.id_fp);
});

test("Ed25519 request signature verification matches test vectors and rejects tampering", async () => {
  const ctx = vectors.context_vectors.find((c) => c.label === vectors.request_signature.context_label);
  const req = {
    v: 1,
    id_pk: vectors.request_signature.id_pk_b64u,
    pk_req: vectors.request_signature.pk_req_b64u,
    request_ts: vectors.request_signature.request_ts,
    ttl_secs: vectors.request_signature.ttl_secs,
    request_nonce: vectors.request_signature.request_nonce_b64u,
    context: {
      name: ctx.name,
      reason: ctx.reason,
      command_summary: ctx.command_summary,
    },
    sig: vectors.request_signature.sig_b64u,
  };

  const ok = await api.verifyRequestSignature(req);
  assert.equal(ok.valid, true);
  assert.equal(bytesToHex(ok.contextHash), ctx.context_hash_hex);

  // Tamper context reason -> must fail verification.
  const tampered = { ...req, context: { ...req.context, reason: "Evil reason" } };
  const bad = await api.verifyRequestSignature(tampered);
  assert.equal(bad.valid, false);
});

test("E2EE encryption matches deterministic vector in protocol/test-vectors.json", async () => {
  const ev = vectors.e2ee;
  const ctx = vectors.context_vectors.find((c) => c.label === ev.context_label);

  const epkSeed = hexToBytes(ev.sk_epk_hex);
  const pkcs8 = Buffer.concat([Buffer.from("302e020100300506032b656e04220420", "hex"), epkSeed]);
  const privKey = await crypto.subtle.importKey("pkcs8", pkcs8, { name: "X25519" }, true, ["deriveBits"]);
  const pubKey = await crypto.subtle.importKey("raw", api.b64uDecode(ev.epk_b64u), { name: "X25519" }, true, []);

  const plaintextObj = JSON.parse(ev.plaintext_json);
  const envelope = await api.encryptSecretEnvelope(
    plaintextObj.secret,
    ev.session_id,
    api.b64uDecode(ev.pk_req_b64u),
    hexToBytes(ctx.context_hash_hex),
    {
      ephemeralKeyPair: { privateKey: privKey, publicKey: pubKey },
      nonce: api.b64uDecode(ev.nonce_b64u),
    }
  );

  assert.equal(envelope.v, 1);
  assert.equal(envelope.epk, ev.epk_b64u);
  assert.equal(envelope.nonce, ev.nonce_b64u);
  assert.equal(envelope.ciphertext, ev.ciphertext_b64u);
});

test("TOFU evaluation handles trusted, untrusted, and key conflict", () => {
  const entries = [{ id_pk: "pk-1", name: "macbook", fp: "AAAA-BBBB" }];
  assert.equal(api.evaluateTofu(entries, "pk-1", "macbook").state, "trusted");
  assert.equal(api.evaluateTofu(entries, "pk-2", "devbox").state, "untrusted");
  const conflict = api.evaluateTofu(entries, "pk-2", "macbook");
  assert.equal(conflict.state, "conflict");
  assert.equal(conflict.existing.fp, "AAAA-BBBB");
});

test("parseApprovePath extracts name_slug and approve_token", () => {
  assert.deepEqual(api.parseApprovePath("/approve/prod-db/tok_12345"), {
    nameSlug: "prod-db",
    approveToken: "tok_12345",
  });
  assert.equal(api.parseApprovePath("/approve/only-one"), null);
});

test("generateAgeSecretKey encodes valid BIP-173 age X25519 secret keys", () => {
  const k1 = api.generateAgeSecretKey();
  const k2 = api.generateAgeSecretKey();
  assert.equal(k1.length, 74);
  assert.match(k1, /^AGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}$/);
  assert.notEqual(k1, k2);

  // Deterministic BIP-173 vectors (verified against filippo.io/age in Go tests).
  const zeroKey = api.generateAgeSecretKey(new Uint8Array(32));
  assert.equal(zeroKey, "AGE-SECRET-KEY-1QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ8H00W3");

  const seq = new Uint8Array(32);
  for (let i = 0; i < 32; i++) seq[i] = i + 1;
  assert.equal(
    api.generateAgeSecretKey(seq),
    "AGE-SECRET-KEY-1QYPQXPQ9QCRSSZG2PVXQ6RS0ZQG3YYC5Z5TPWXQERGD3C8G7RUSQGPQYEE"
  );

  assert.throws(() => api.generateAgeSecretKey(new Uint8Array(16)));
});

test("isSopsKeygenCommand matches only SOPS enrollment commands", () => {
  assert.equal(api.isSopsKeygenCommand("[sops:init ~/.secrets.enc.yaml]"), true);
  assert.equal(api.isSopsKeygenCommand("[register-sops-key] sops-main"), true);
  assert.equal(api.isSopsKeygenCommand("[register-name] github-pat"), false);
  assert.equal(api.isSopsKeygenCommand("[sops:set ~/.secrets.enc.yaml] GH_TOKEN"), false);
  assert.equal(api.isSopsKeygenCommand("gh auth status"), false);
  assert.equal(api.isSopsKeygenCommand(""), false);
});
