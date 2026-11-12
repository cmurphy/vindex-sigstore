// Copyright 2026 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

"use strict";

const CFG = {
  shardType: "hashedrekord",
  shardFormat: "hashedrekord v0.0.2",
  shardLabel: "log2025-1.rekor.sigstore.dev · hashedrekord v0.0.2",
  vindexBaseURL: "",
  inputLogURL: "https://log2025-1.rekor.sigstore.dev/api/v2",
  proxyInputLog: false,
};

const isIdentityShard = () => CFG.shardType === "identity";
const vindexURL = (pathAndQuery) => {
  const base = (CFG.vindexBaseURL || "").replace(/\/+$/, "");
  return base ? `${base}/${pathAndQuery}` : pathAndQuery;
};

const TILE_SIZE = 256;
const PAGE_SIZE = 10;

const OIDS = {
  "build-signer-uri": "1.3.6.1.4.1.57264.1.9",
  "source-repository-uri": "1.3.6.1.4.1.57264.1.12",
  "source-repository-identifier": "1.3.6.1.4.1.57264.1.15",
  "source-repository-owner-uri": "1.3.6.1.4.1.57264.1.16",
  "source-repository-owner-identifier": "1.3.6.1.4.1.57264.1.17",
  "build-config-uri": "1.3.6.1.4.1.57264.1.18",
};

const KNOWN_IDENTITY_CLAIMS = [
  "identity", "issuer", "subject", "context",
  "build-signer-uri", "build-signer-digest",
  "build-config-uri", "build-config-digest",
  "build-trigger", "runner-environment", "run-invocation-uri",
  "source-repository-uri", "source-repository-digest", "source-repository-ref", "source-repository-identifier",
  "source-repository-owner-uri", "source-repository-owner-identifier",
  "source-repository-visibility-at-signing",
];
let knownClaimHashMap = null;

const $ = (id) => document.getElementById(id);

const state = {
  tab: "cert",
  discoveredKeys: [],
  selectedKeyIdx: 0,
  indices: [],
  nextBefore: null,
  page: 0,
  inputLogSize: 0,
  outputLogSize: 0,
  mptRoot: "",
  rawKeysText: "",
  rawValuesText: "",
  snippet: "",
  tileCache: {},
  entrySummaryCache: {},
  activeEntryIdx: null,
  lastComputedKey: "",
};

// ---------- Crypto & formatting helpers ----------

function bytesToHex(bytes) {
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function sha256Bytes(bytes) {
  const buf = await crypto.subtle.digest("SHA-256", bytes);
  return new Uint8Array(buf);
}

async function sha256Hex(bytes) {
  return bytesToHex(await sha256Bytes(bytes));
}

async function doubleSha256Hex(str) {
  const first = await sha256Bytes(new TextEncoder().encode(str));
  return sha256Hex(first);
}

function escapeHTML(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

const fmtInt = (n) => Number(n || 0).toLocaleString("en-US");

// Percent-encodes every UTF-8 byte outside printable non-whitespace ASCII
// (0x21..0x7E) as %XX with uppercase hex, matching the hashedrekord MapFn.
// A literal "%" is left as is.
function percentEncodeKey(str) {
  let out = "";
  for (const b of new TextEncoder().encode(str)) {
    out += b < 0x21 || b > 0x7e
      ? "%" + b.toString(16).toUpperCase().padStart(2, "0")
      : String.fromCharCode(b);
  }
  return out;
}

function validatePrintableKey(key) {
  if (!key || key.length > 1024) {
    throw new Error("Key must be 1..1024 characters");
  }
  for (let i = 0; i < key.length; i++) {
    const c = key.charCodeAt(i);
    if (c < 0x21 || c > 0x7e) {
      throw new Error("Key must contain only printable non-whitespace ASCII characters");
    }
  }
}

function decodePublicKeyDer(input) {
  let cleaned = input
    .replace(/-----BEGIN [^-]+-----/g, "")
    .replace(/-----END [^-]+-----/g, "")
    .replace(/\s+/g, "");
  if (!cleaned) {
    throw new Error("Empty public key input");
  }
  cleaned = cleaned.replace(/-/g, "+").replace(/_/g, "/");
  while (cleaned.length % 4 !== 0) cleaned += "=";
  const bin = atob(cleaned);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

function detectIdentitySPKIAlgorithm(derBytes) {
  const hexHead = bytesToHex(derBytes.subarray(0, Math.min(derBytes.length, 32)));
  if (hexHead.includes("0609608648016503040311")) return "ML-DSA-44";
  if (hexHead.includes("0609608648016503040312")) return "ML-DSA-65";
  if (hexHead.includes("0609608648016503040313")) return "ML-DSA-87";
  if (hexHead.includes("06032b6570")) return "Ed25519";
  throw new Error("Unsupported SPKI public key algorithm for identity v0.0.1 (expected ML-DSA-44/65/87 or Ed25519)");
}

function parseLVP(data) {
  const entries = [];
  let offset = 0;
  while (offset + 2 <= data.length) {
    const len = (data[offset] << 8) | data[offset + 1];
    offset += 2;
    if (offset + len > data.length) break;
    entries.push(data.subarray(offset, offset + len));
    offset += len;
  }
  return entries;
}

function formatTileIndex(n) {
  const s = n.toString();
  const chunks = [];
  for (let i = s.length; i > 0; i -= 3) {
    let chunk = s.substring(Math.max(0, i - 3), i);
    while (chunk.length < 3) chunk = "0" + chunk;
    chunks.unshift(chunk);
  }
  for (let i = 0; i < chunks.length - 1; i++) {
    chunks[i] = "x" + chunks[i];
  }
  return chunks.join("/");
}

// ---------- Query & YAML Snippet Construction ----------

async function buildQuery() {
  const idShard = isIdentityShard();

  if (state.tab === "cert") {
    const subject = $("cert-subject").value;
    const issuer = $("cert-issuer").value;
    const prefix = !idShard && $("cert-prefix").checked;
    $("cert-issuer").disabled = prefix;

    if (!subject) return null;

    let key, isPrefix;
    if (idShard) {
      const idHash = await doubleSha256Hex(subject);
      if (!issuer) {
        key = `${idHash}:`;
        isPrefix = true;
      } else {
        const issHash = await doubleSha256Hex(issuer);
        key = `${idHash}:${issHash}`;
        isPrefix = false;
      }
    } else {
      if (prefix) {
        key = subject;
        isPrefix = true;
      } else if (!issuer) {
        key = `${subject}:`;
        isPrefix = true;
      } else {
        key = `${subject}:${issuer}`;
        isPrefix = false;
      }
      key = percentEncodeKey(key);
      validatePrintableKey(key);
    }

    const yaml = [
      "monitoredValues:",
      "  certIdentities:",
      `    - ${prefix ? "certSubjectPrefix" : "certSubject"}: ${subject}`,
      ...(issuer && !prefix ? ["      issuers:", `        - ${issuer}`] : []),
    ];
    return { key, isPrefix, yaml };
  }

  if (state.tab === "ext") {
    const claimName = $("ext-oid").value;
    const value = $("ext-value").value;
    const issuer = $("ext-issuer").value;
    const prefix = !idShard && $("ext-prefix").checked;
    $("ext-issuer").disabled = prefix;

    if (!value) return null;

    let key, isPrefix;
    if (idShard) {
      const kh = await doubleSha256Hex(claimName);
      const vh = await doubleSha256Hex(value);
      if (!issuer) {
        key = `${kh}:${vh}:`;
        isPrefix = true;
      } else {
        const ih = await doubleSha256Hex(issuer);
        key = `${kh}:${vh}:${ih}`;
        isPrefix = false;
      }
    } else {
      if (prefix) {
        key = `${claimName}:${value}`;
        isPrefix = true;
      } else if (!issuer) {
        key = `${claimName}:${value}:`;
        isPrefix = true;
      } else {
        key = `${claimName}:${value}:${issuer}`;
        isPrefix = false;
      }
      key = percentEncodeKey(key);
      validatePrintableKey(key);
    }

    const matcherLines = !prefix && !issuer
      ? [`        - ${value}`]
      : [
          `        - ${prefix ? "extensionValuePrefixes" : "extensionValues"}: [${value}]`,
          ...(issuer && !prefix ? [`          issuers: [${issuer}]`] : []),
        ];
    const yaml = [
      "monitoredValues:",
      "  oidMatchers:",
      "    fulcioExtensions:",
      `      ${claimName}:`,
      ...matcherLines,
    ];
    return { key, isPrefix, yaml };
  }

  if (state.tab === "key") {
    const raw = $("key-input").value.trim();
    if (!raw) return null;

    let key;
    const isHex = /^[0-9a-fA-F]{64}$/.test(raw);
    if (isHex) {
      key = raw.toLowerCase();
    } else {
      const der = decodePublicKeyDer(raw);
      if (idShard) {
        const alg = detectIdentitySPKIAlgorithm(der);
        const algBytes = new TextEncoder().encode(alg);
        const combined = new Uint8Array(algBytes.length + der.length);
        combined.set(algBytes, 0);
        combined.set(der, algBytes.length);
        key = await sha256Hex(combined);
      } else {
        key = await sha256Hex(der);
      }
    }

    const yaml = idShard && !isHex
      ? ["monitoredValues:", "  publicKeys:", "    - path: /path/to/public_key.pem"]
      : ["monitoredValues:", "  fingerprints:", `    - ${key}`];
    return { key, isPrefix: false, yaml };
  }

  if (state.tab === "raw") {
    const key = $("raw-input").value;
    const isPrefix = $("raw-prefix").checked;
    if (!key) return null;
    validatePrintableKey(key);
    return {
      key,
      isPrefix,
      yaml: [`# Raw VIndex ${isPrefix ? "prefix" : "key"}: ${key}`],
    };
  }

  return null;
}

// ---------- UI Preview & Highlight ----------

function highlightYAML(lines) {
  return lines
    .map((line) => {
      if (line.trim().startsWith("#")) {
        return `<span class="tok-punct">${escapeHTML(line)}</span>`;
      }
      const m = line.match(/^(\s*)(- )?([A-Za-z][\w-]*:(?=\s|$))?(.*)$/);
      if (!m) return escapeHTML(line);
      const [, indent, dash = "", key = "", rest = ""] = m;
      return (
        indent +
        (dash ? `<span class="tok-punct">- </span>` : "") +
        (key ? `<span class="tok-key">${escapeHTML(key)}</span>` : "") +
        (rest ? `<span class="tok-str">${escapeHTML(rest)}</span>` : "")
      );
    })
    .join("\n");
}

function renderSnippet(lines) {
  state.snippet = lines.join("\n") + "\n";
  $("snippet").innerHTML = highlightYAML(lines);
}

async function updatePreview() {
  try {
    const q = await buildQuery();
    if (!q) {
      $("preview-key").textContent = "Enter a query above…";
      $("preview-mode").textContent = "IDLE";
      renderSnippet([
        "# Enter an identity, claim, or public key above to generate a rekor-monitor config snippet.",
      ]);
      return;
    }
    $("preview-key").textContent = q.key;
    $("preview-mode").textContent = q.isPrefix ? "PREFIX" : "EXACT";
    renderSnippet(q.yaml);
  } catch (e) {
    $("preview-key").textContent = `Invalid input: ${e.message}`;
    $("preview-mode").textContent = "INVALID";
  }
}

// ---------- C2SP tlog-vindex Protocol Parsing ----------

function parseKeysResponse(keysBody) {
  const discovered = [];
  const proofSplit = keysBody.split("\n\nc2sp.org/tlog-proof@v1\n");

  if (proofSplit.length >= 1) {
    const keyLines = proofSplit[0].split("\n");
    for (let i = 1; i < keyLines.length; i++) {
      const trimmed = keyLines[i].trim();
      if (!trimmed) continue;
      if (i === 1 && (trimmed === "proof" || trimmed.startsWith("proof "))) continue;
      const parts = trimmed.split(/\s+/);
      if (parts.length >= 2) {
        discovered.push({ key: parts[0], valueRoot: parts[1] });
      }
    }
  }

  let mptRoot = "";
  let inputLogSize = 0;
  let outputLogSize = 0;

  if (proofSplit.length >= 2) {
    const bindStanzas = proofSplit[1].split("\n\n");
    const proofLines = (bindStanzas[0] || "").split("\n");
    for (const l of proofLines) {
      const trimmed = l.trim();
      if (trimmed.startsWith("extra ")) {
        try {
          const rawLeaf = atob(trimmed.slice(6).trim());
          for (const ll of rawLeaf.split("\n")) {
            if (ll.startsWith("mpt-root ")) mptRoot = ll.slice(9).trim();
            else if (ll.startsWith("input-size ")) inputLogSize = parseInt(ll.slice(11).trim(), 10) || 0;
          }
        } catch (err) {
          console.error("Failed to decode extra state leaf:", err);
        }
      }
    }
    if (bindStanzas.length >= 2) {
      const outLines = bindStanzas[1].split("\n");
      if (outLines.length >= 2) {
        outputLogSize = parseInt(outLines[1].trim(), 10) || 0;
      }
    }
  }

  return { discovered, mptRoot, inputLogSize, outputLogSize };
}

function parseValuesResponse(valuesBody) {
  const indices = [];
  let preceding = 0;

  if (valuesBody && valuesBody.trim() !== "") {
    const stanzas = valuesBody.trim().split("\n\n");
    for (const l of (stanzas[0] || "").split("\n")) {
      const trimmed = l.trim();
      if (trimmed.startsWith("preceding ")) {
        preceding = parseInt(trimmed.slice(10).trim(), 10) || 0;
      }
    }
    if (stanzas.length >= 2 && stanzas[1]) {
      for (const l of stanzas[1].split("\n")) {
        const trimmed = l.trim();
        if (trimmed !== "") {
          const val = parseInt(trimmed, 10);
          if (!Number.isNaN(val)) indices.push(val);
        }
      }
    }
  }

  const nextBefore = preceding > 0 && indices.length > 0 ? indices[0] : null;
  indices.reverse();
  return { indices, nextBefore };
}

// ---------- Rendering ----------

const CHECK_SVG =
  '<span class="check" aria-hidden="true"><svg viewBox="0 0 12 12"><path d="M2.5 6.3l2.3 2.3 4.7-5" fill="none" stroke="#fff" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg></span>';

function showBanner(kind, title, captionHTML, items, showProofBtn = false) {
  const banner = $("verify-banner");
  banner.hidden = false;
  banner.className = `verify verify--${kind}`;
  $("verify-heading").textContent = title;
  $("verify-caption").innerHTML = captionHTML || "";
  $("view-raw-proof").hidden = !showProofBtn;
  $("copy-deep-link").hidden = !showProofBtn;
  $("verify-list").innerHTML = (items || [])
    .map((t) => `<li class="verify__item">${CHECK_SVG}<span>${escapeHTML(t)}</span></li>`)
    .join("");
}

function renderKeys() {
  const n = state.discoveredKeys.length;
  $("keys-meta").textContent = n === 1 ? "1 key" : `${fmtInt(n)} keys`;
  $("keys-empty").hidden = n > 0;
  $("keys-table").hidden = n === 0;

  $("keys-body").innerHTML = state.discoveredKeys
    .map((dk, i) => {
      const lastColon = dk.key.lastIndexOf(":");
      let labelHTML;
      if (lastColon > 0 && !isIdentityShard()) {
        const subj = dk.key.slice(0, lastColon + 1);
        const iss = dk.key.slice(lastColon + 1);
        labelHTML = `<span class="key__subject">${escapeHTML(subj)}</span><span class="key__issuer">${escapeHTML(iss || "(empty issuer)")}</span>`;
      } else {
        labelHTML = `<span class="key__subject">${escapeHTML(dk.key)}</span><span class="key__issuer">value-root: ${escapeHTML(dk.valueRoot)}</span>`;
      }
      return `<tr tabindex="0" id="key-row-${i}" aria-selected="${i === state.selectedKeyIdx}" data-index="${i}">
        <td class="key">${labelHTML}</td>
      </tr>`;
    })
    .join("");
}

function renderEntries() {
  const totalLoaded = state.indices.length;
  $("entries-empty").hidden = totalLoaded > 0;
  $("entries-table").hidden = totalLoaded === 0;
  $("pager").hidden = totalLoaded === 0;

  if (totalLoaded === 0) return;

  const pages = Math.max(1, Math.ceil(totalLoaded / PAGE_SIZE));
  state.page = Math.min(state.page, pages - 1);
  const slice = state.indices.slice(state.page * PAGE_SIZE, (state.page + 1) * PAGE_SIZE);

  $("entries-body").innerHTML = slice
    .map((idx) => {
      const tileIdx = Math.floor(idx / TILE_SIZE);
      const offset = idx % TILE_SIZE;
      const defaultLoc = `tile/entries/${formatTileIndex(tileIdx)} [${offset}]`;
      const summary = state.entrySummaryCache[idx] || defaultLoc;
      return `<tr>
        <td class="mono">#${fmtInt(idx)}</td>
        <td class="digest" id="entry-summary-${idx}" title="${escapeHTML(summary)}">${escapeHTML(summary)}</td>
        <td class="link"><button type="button" class="entry-link" data-entry-index="${idx}">Inspect leaf ↗</button></td>
      </tr>`;
    })
    .join("");

  const moreNote = state.nextBefore !== null ? "+" : "";
  $("pager-status").textContent = `Page ${state.page + 1} of ${pages}${moreNote} · ${fmtInt(totalLoaded)}${moreNote} entries`;
  $("pager-newer").disabled = state.page === 0;
  $("pager-older").disabled = state.page >= pages - 1 && state.nextBefore === null;
}

// ---------- Live Network Queries ----------

async function fetchValuesForSelectedKey(appendEarlier = false) {
  const dk = state.discoveredKeys[state.selectedKeyIdx];
  if (!dk || !state.inputLogSize) {
    state.indices = [];
    state.nextBefore = null;
    renderEntries();
    return;
  }

  const before = appendEarlier ? state.nextBefore : state.inputLogSize;
  if (!before) return;

  const valuesUrl = vindexURL(`values?key=${encodeURIComponent(dk.key)}&before=${before}`);
  const resp = await fetch(valuesUrl);
  if (resp.status === 404) {
    if (!appendEarlier) {
      state.indices = [];
      state.nextBefore = null;
    }
    renderEntries();
    return;
  }
  if (!resp.ok) {
    throw new Error(`HTTP ${resp.status} from /values: ${await resp.text()}`);
  }

  const body = await resp.text();
  state.rawValuesText = body;
  const parsed = parseValuesResponse(body);
  if (appendEarlier) {
    state.indices = state.indices.concat(parsed.indices);
  } else {
    state.indices = parsed.indices;
    state.page = 0;
  }
  state.nextBefore = parsed.nextBefore;
  renderEntries();
}

async function executeSearch(opts = {}) {
  const { updateHash = true, preferredKey = null } = opts;
  let q;
  try {
    q = await buildQuery();
  } catch (e) {
    showBanner("error", "Invalid query", escapeHTML(e.message), []);
    return;
  }
  if (!q) {
    showBanner("empty", "Enter a query", "Provide an identity, claim value, or public key to search.", []);
    return;
  }

  state.lastComputedKey = q.key;
  if (updateHash) syncDeepLinkHash();

  showBanner("loading", "Querying VIndex…", `Looking up <code>${escapeHTML(q.key)}</code>`, []);
  state.rawKeysText = "";
  state.rawValuesText = "";

  try {
    const keysUrl = q.isPrefix
      ? vindexURL(`keys?prefix=${encodeURIComponent(q.key)}`)
      : vindexURL(`keys?key=${encodeURIComponent(q.key)}`);
    const keysResp = await fetch(keysUrl);
    if (!keysResp.ok) {
      throw new Error(`HTTP ${keysResp.status}: ${await keysResp.text()}`);
    }
    const keysBody = await keysResp.text();
    state.rawKeysText = keysBody;

    const parsedKeys = parseKeysResponse(keysBody);
    state.discoveredKeys = parsedKeys.discovered;
    state.mptRoot = parsedKeys.mptRoot;
    state.inputLogSize = parsedKeys.inputLogSize;
    state.outputLogSize = parsedKeys.outputLogSize;
    state.selectedKeyIdx = 0;
    if (preferredKey) {
      const idx = state.discoveredKeys.findIndex((dk) => dk.key === preferredKey);
      if (idx >= 0) state.selectedKeyIdx = idx;
    }
    state.indices = [];
    state.nextBefore = null;
    state.page = 0;

    $("results-section").hidden = false;
    renderKeys();

    const caption = `Index covers Rekor log size <strong>${fmtInt(state.inputLogSize)}</strong> (Output Log size <strong>${fmtInt(state.outputLogSize)}</strong>)`;

    if (state.discoveredKeys.length === 0) {
      renderEntries();
      showBanner(
        "empty",
        q.isPrefix ? "No matching keys (Prefix proof received)" : "Not found (Non-inclusion proof received)",
        caption,
        [],
        true,
      );
      return;
    }

    await fetchValuesForSelectedKey(false);

    const n = state.discoveredKeys.length;
    showBanner(
      "ok",
      "Proof bundle received",
      caption,
      [
        "Output Log inclusion proof",
        q.isPrefix ? `MPT prefix proof — ${n} ${n === 1 ? "key" : "keys"}` : "MPT inclusion proof",
        `Value log compact range (${fmtInt(state.indices.length)}${state.nextBefore !== null ? "+" : ""} entries)`,
      ],
      true,
    );
  } catch (e) {
    console.error(e);
    showBanner("error", "Query failed", escapeHTML(e.message), []);
  }
}

// ---------- Leaf Inspection ----------

async function getKnownClaimHashMap() {
  if (knownClaimHashMap) return knownClaimHashMap;
  const m = {};
  for (const name of KNOWN_IDENTITY_CLAIMS) {
    m[await doubleSha256Hex(name)] = name;
  }
  knownClaimHashMap = m;
  return m;
}

async function decodeLeaf(leafBytes) {
  if (leafBytes.length >= 97 && leafBytes[0] === 0x01 && (leafBytes.length - 97) % 64 === 0) {
    const rot = bytesToHex(leafBytes.subarray(1, 33));
    const msg = bytesToHex(leafBytes.subarray(33, 65));
    const receiptBytes = leafBytes.subarray(leafBytes.length - 32);
    const isZero = receiptBytes.every((b) => b === 0);
    const receipt = isZero ? "0x00 * 32 (no receipt)" : bytesToHex(receiptBytes);
    const claimMap = await getKnownClaimHashMap();

    const kvCount = (leafBytes.length - 97) / 64;
    const lines = [
      `c2sp.org/identity-transparency (version 0x01, ${leafBytes.length} bytes)`,
      `root_of_trust: ${rot}`,
      `message:       ${msg}`,
      `kv_pairs (${kvCount}):`,
    ];
    for (let off = 65; off < leafBytes.length - 32; off += 64) {
      const kh = bytesToHex(leafBytes.subarray(off, off + 32));
      const vh = bytesToHex(leafBytes.subarray(off + 32, off + 64));
      const label = claimMap[kh] ? `${claimMap[kh]} (${kh.slice(0, 12)}…)` : kh;
      lines.push(`  ${label} = ${vh}`);
    }
    lines.push(`receipt:       ${receipt}`);
    return {
      summary: `msg=${msg.slice(0, 16)}… (${kvCount} claims)`,
      pretty: lines.join("\n"),
    };
  }

  const rawText = new TextDecoder("utf-8").decode(leafBytes);
  try {
    const obj = JSON.parse(rawText);
    const digestB64 = obj?.spec?.hashedRekordV002?.data?.digest;
    let summary = rawText.slice(0, 72);
    if (digestB64) {
      const rawDigest = Uint8Array.from(atob(digestB64), (c) => c.charCodeAt(0));
      summary = `sha256:${bytesToHex(rawDigest)}`;
    }
    return { summary, pretty: JSON.stringify(obj, null, 2) };
  } catch {
    return { summary: rawText.slice(0, 72), pretty: rawText };
  }
}

async function fetchTileBundle(formattedTile, partialCount) {
  const base = CFG.proxyInputLog
    ? "inputlog"
    : (CFG.inputLogURL || "").replace(/\/+$/, "");
  let url = `${base}/tile/entries/${formattedTile}`;
  if (partialCount > 0) {
    url += `.p/${partialCount}`;
  }
  if (state.tileCache[url]) return state.tileCache[url];

  let resp = await fetch(url);
  if (!resp.ok && partialCount > 0) {
    url = `${base}/tile/entries/${formattedTile}`;
    resp = await fetch(url);
  }
  if (!resp.ok) throw new Error(`HTTP ${resp.status} fetching ${url}`);
  const entries = parseLVP(new Uint8Array(await resp.arrayBuffer()));
  state.tileCache[url] = entries;
  return entries;
}

async function ensureInputLogSize() {
  if (state.inputLogSize > 0) return;
  try {
    const resp = await fetch(vindexURL("keys?key=_"));
    if (resp.ok) {
      const parsed = parseKeysResponse(await resp.text());
      if (parsed.inputLogSize > 0) {
        state.inputLogSize = parsed.inputLogSize;
        state.outputLogSize = parsed.outputLogSize;
        state.mptRoot = parsed.mptRoot;
      }
    }
  } catch (err) {
    console.warn("Unable to pre-fetch inputLogSize:", err);
  }
}

async function inspectLeaf(idx, updateHash = true) {
  state.activeEntryIdx = idx;
  if (updateHash) syncDeepLinkHash();

  openModal("Rekor Log Entry", `#${fmtInt(idx)}`, "Fetching entry bundle…", true);

  if (state.inputLogSize === 0) {
    await ensureInputLogSize();
  }

  const tileIdx = Math.floor(idx / TILE_SIZE);
  const formattedTile = formatTileIndex(tileIdx);
  const isFullTile = (tileIdx + 1) * TILE_SIZE <= state.inputLogSize;
  const partialCount = !isFullTile && state.inputLogSize > 0 ? state.inputLogSize % TILE_SIZE : 0;

  try {
    const entries = await fetchTileBundle(formattedTile, partialCount);
    const offset = idx % TILE_SIZE;
    if (offset >= entries.length) {
      throw new Error(`Entry #${idx} not found in bundle`);
    }

    const decoded = await decodeLeaf(entries[offset]);
    state.entrySummaryCache[idx] = decoded.summary;
    const summaryEl = $(`entry-summary-${idx}`);
    if (summaryEl) {
      summaryEl.textContent = decoded.summary;
      summaryEl.title = decoded.summary;
    }
    openModal("Rekor Log Entry", `#${fmtInt(idx)}`, decoded.pretty, true);
  } catch (e) {
    openModal("Rekor Log Entry", `#${fmtInt(idx)}`, `Failed to fetch leaf: ${e.message}`, true);
  }
}

// ---------- Stateless Deep Links (#... hash fragment) ----------

function buildDeepLinkParams() {
  const params = new URLSearchParams();
  if (state.tab === "cert") {
    const subject = $("cert-subject").value;
    const issuer = $("cert-issuer").value;
    const prefix = !isIdentityShard() && $("cert-prefix").checked;
    if (subject) {
      params.set("tab", "cert");
      params.set("subject", subject);
      if (issuer && !prefix) params.set("issuer", issuer);
      if (prefix) params.set("prefix", "1");
    }
  } else if (state.tab === "ext") {
    const claim = $("ext-oid").value;
    const value = $("ext-value").value;
    const issuer = $("ext-issuer").value;
    const prefix = !isIdentityShard() && $("ext-prefix").checked;
    if (value) {
      params.set("tab", "ext");
      params.set("claim", claim);
      params.set("value", value);
      if (issuer && !prefix) params.set("issuer", issuer);
      if (prefix) params.set("prefix", "1");
    }
  } else if (state.tab === "key") {
    if (state.lastComputedKey) {
      params.set("tab", "key");
      params.set("key", state.lastComputedKey);
    }
  } else if (state.tab === "raw") {
    const raw = $("raw-input").value;
    if (raw) {
      params.set("tab", "raw");
      params.set("key", raw);
      if ($("raw-prefix").checked) params.set("prefix", "1");
    }
  }

  if (state.discoveredKeys.length > 1 && state.selectedKeyIdx > 0) {
    const sel = state.discoveredKeys[state.selectedKeyIdx];
    if (sel) params.set("selected", sel.key);
  }
  if (state.activeEntryIdx !== null) {
    params.set("entry", String(state.activeEntryIdx));
  }
  return params;
}

function syncDeepLinkHash() {
  const str = buildDeepLinkParams().toString();
  const nextURL = str ? `${location.pathname}${location.search}#${str}` : `${location.pathname}${location.search}`;
  history.replaceState(null, "", nextURL);
}

async function restoreFromDeepLink() {
  const rawHash = location.hash.replace(/^#/, "");
  if (!rawHash) return;
  const params = new URLSearchParams(rawHash);

  const tab = params.get("tab");
  const selectedKey = params.get("selected");
  const entryParam = params.get("entry");
  let hasSearchQuery = false;

  if (tab && ["cert", "ext", "key", "raw"].includes(tab)) {
    selectTab(tab);
    if (tab === "cert" && params.get("subject")) {
      $("cert-subject").value = params.get("subject");
      $("cert-issuer").value = params.get("issuer") || "";
      $("cert-prefix").checked = !isIdentityShard() && params.get("prefix") === "1";
      hasSearchQuery = true;
    } else if (tab === "ext" && params.get("value")) {
      const claim = params.get("claim");
      if (claim && OIDS[claim]) $("ext-oid").value = claim;
      $("ext-value").value = params.get("value");
      $("ext-issuer").value = params.get("issuer") || "";
      $("ext-prefix").checked = !isIdentityShard() && params.get("prefix") === "1";
      hasSearchQuery = true;
    } else if (tab === "key" && params.get("key")) {
      $("key-input").value = params.get("key");
      hasSearchQuery = true;
    } else if (tab === "raw" && params.get("key")) {
      $("raw-input").value = params.get("key");
      $("raw-prefix").checked = params.get("prefix") === "1";
      hasSearchQuery = true;
    }
  }

  await updatePreview();

  if (hasSearchQuery) {
    await executeSearch({ updateHash: false, preferredKey: selectedKey });
  }
  if (entryParam !== null && /^\d+$/.test(entryParam)) {
    await inspectLeaf(Number(entryParam), false);
  } else if (!$("modal-backdrop").hidden) {
    $("modal-backdrop").hidden = true;
    state.activeEntryIdx = null;
  }
}

async function copyCurrentDeepLink(btnEl, defaultLabel) {
  syncDeepLinkHash();
  try {
    await navigator.clipboard.writeText(location.href);
    btnEl.textContent = "Copied!";
  } catch {
    btnEl.textContent = "Copy failed";
  }
  setTimeout(() => {
    btnEl.textContent = defaultLabel;
  }, 1600);
}

// ---------- Modal & Events ----------

function openModal(title, badge, content, isEntry = false) {
  $("modal-title").textContent = title;
  $("modal-badge").textContent = badge;
  $("modal-content").textContent = content;
  $("copy-modal-link").hidden = !isEntry;
  $("modal-backdrop").hidden = false;
}

function closeModal() {
  $("modal-backdrop").hidden = true;
  if (state.activeEntryIdx !== null) {
    state.activeEntryIdx = null;
    syncDeepLinkHash();
  }
}

function selectTab(name) {
  state.tab = name;
  for (const t of ["cert", "ext", "key", "raw"]) {
    const on = t === name;
    $(`tab-${t}`).setAttribute("aria-selected", String(on));
    $(`tab-${t}`).tabIndex = on ? 0 : -1;
    $(`panel-${t}`).hidden = !on;
  }
  updatePreview();
}

function applyShardConfig() {
  $("shard-badge-text").textContent = CFG.shardLabel;
  const idShard = isIdentityShard();
  $("cert-prefix-wrap").hidden = idShard;
  $("ext-prefix-wrap").hidden = idShard;

  if (idShard) {
    $("cert-prefix").checked = false;
    $("ext-prefix").checked = false;
    $("cert-hint").textContent =
      "identity v0.0.1 shards double-hash OIDC attributes (SHA-256²). Exact identity + issuer and “Any issuer” queries are supported; partial value prefixes are unavailable.";
    $("ext-hint").textContent =
      "Claims are indexed by claim name (e.g. source-repository-uri) using double SHA-256 digests.";
    $("key-hint").textContent =
      "PEM public keys (ML-DSA-44/65/87 or Ed25519) are hashed in your browser as SHA-256(\"<algorithm>\" || SPKI DER).";
  } else {
    $("cert-hint").textContent =
      "Values are matched with exact case (no normalization). Leave OIDC issuer blank to match across all issuers, or enable Prefix match to scan a URI prefix.";
    $("ext-hint").textContent =
      "Fulcio extensions are indexed as <claim name>:<value>:<issuer>. Leave OIDC issuer blank to match any issuer.";
    $("key-hint").textContent =
      "PEM public keys are hashed in your browser as hex(SHA-256(SPKI DER)).";
  }
}

async function init() {
  try {
    const resp = await fetch("config.json", { cache: "no-store" });
    if (resp.ok) {
      Object.assign(CFG, await resp.json());
    }
  } catch (err) {
    console.warn("Using default UI config:", err);
  }
  applyShardConfig();
  await updatePreview();
  await restoreFromDeepLink();
}

document.querySelectorAll(".tab").forEach((btn) => {
  btn.addEventListener("click", () => selectTab(btn.id.replace("tab-", "")));
  btn.addEventListener("keydown", (e) => {
    const order = ["cert", "ext", "key", "raw"];
    const i = order.indexOf(state.tab);
    if (e.key === "ArrowRight" || e.key === "ArrowLeft") {
      const next = order[(i + (e.key === "ArrowRight" ? 1 : order.length - 1)) % order.length];
      selectTab(next);
      $(`tab-${next}`).focus();
    }
  });
});

document.querySelectorAll(".preset-chip").forEach((chip) => {
  chip.addEventListener("click", () => {
    const target = $(chip.dataset.target);
    target.value = chip.dataset.value;
    updatePreview();
  });
});

$("key-file").addEventListener("change", (e) => {
  const file = e.target.files && e.target.files[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = () => {
    $("key-input").value = reader.result;
    updatePreview();
  };
  reader.readAsText(file);
});

for (const id of [
  "cert-subject", "cert-issuer", "cert-prefix",
  "ext-oid", "ext-value", "ext-issuer", "ext-prefix",
  "key-input", "raw-input", "raw-prefix",
]) {
  $(id).addEventListener("input", updatePreview);
  $(id).addEventListener("change", updatePreview);
}

$("search-form").addEventListener("submit", (e) => {
  e.preventDefault();
  executeSearch();
});

$("keys-body").addEventListener("click", async (e) => {
  const row = e.target.closest("tr[data-index]");
  if (!row) return;
  state.selectedKeyIdx = Number(row.dataset.index);
  syncDeepLinkHash();
  renderKeys();
  try {
    await fetchValuesForSelectedKey(false);
  } catch (err) {
    showBanner("error", "Failed to load entries", escapeHTML(err.message), []);
  }
});

$("keys-body").addEventListener("keydown", (e) => {
  if (e.key !== "Enter" && e.key !== " ") return;
  const row = e.target.closest("tr[data-index]");
  if (!row) return;
  e.preventDefault();
  row.click();
});

$("entries-body").addEventListener("click", (e) => {
  const btn = e.target.closest("button[data-entry-index]");
  if (!btn) return;
  inspectLeaf(Number(btn.dataset.entryIndex));
});

$("pager-newer").addEventListener("click", () => {
  state.page = Math.max(0, state.page - 1);
  renderEntries();
});

$("pager-older").addEventListener("click", async () => {
  const loadedPages = Math.ceil(state.indices.length / PAGE_SIZE);
  if (state.page + 1 < loadedPages) {
    state.page += 1;
    renderEntries();
    return;
  }
  if (state.nextBefore !== null) {
    try {
      await fetchValuesForSelectedKey(true);
      state.page += 1;
      renderEntries();
    } catch (err) {
      showBanner("error", "Pagination failed", escapeHTML(err.message), []);
    }
  }
});

$("copy-deep-link").addEventListener("click", () => {
  copyCurrentDeepLink($("copy-deep-link"), "Copy link");
});

$("copy-modal-link").addEventListener("click", () => {
  copyCurrentDeepLink($("copy-modal-link"), "Copy entry link");
});

window.addEventListener("hashchange", () => {
  restoreFromDeepLink();
});

$("view-raw-proof").addEventListener("click", () => {
  const combined = [state.rawKeysText, state.rawValuesText].filter(Boolean).join("\n\n--- /values ---\n\n");
  openModal("Raw C2SP tlog-vindex Response", CFG.shardFormat, combined || "(empty)");
});

$("modal-close").addEventListener("click", closeModal);
$("modal-backdrop").addEventListener("click", (e) => {
  if (e.target === $("modal-backdrop")) closeModal();
});
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape" && !$("modal-backdrop").hidden) closeModal();
});

$("copy-snippet").addEventListener("click", async () => {
  try {
    await navigator.clipboard.writeText(state.snippet);
    $("copy-label").textContent = "Copied";
  } catch {
    $("copy-label").textContent = "Copy failed";
  }
  setTimeout(() => ($("copy-label").textContent = "Copy"), 1600);
});

init();
