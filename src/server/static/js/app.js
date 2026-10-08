/**
 * QuantumVault Frontend Application
 * Minimalist, tactile Neumorphic UI matching reference design.
 * Enforces per-user isolated private keystores & post-quantum encryption.
 */

// -----------------------------------------------------------------------------
// Authentication & Session
// -----------------------------------------------------------------------------

const storedUser = sessionStorage.getItem("quantum_vault_user") || localStorage.getItem("quantum_vault_user");
if (!storedUser) {
  window.location.href = "/login";
}

let currentUser = (storedUser || "alice").toLowerCase();
let currentPeer = currentUser === "alice" ? "bob" : "alice";
let selectedFile = null;
let selectedFileContentB64 = null;

function logoutUser() {
  sessionStorage.removeItem("quantum_vault_user");
  sessionStorage.removeItem("quantum_vault_user_info");
  localStorage.removeItem("quantum_vault_user");
  window.location.href = "/login";
}

document.addEventListener("DOMContentLoaded", () => {
  initUserUI();
  loadState();
  refreshVaultFiles();
  setupDropzone();
  setInterval(loadState, 3500);
});

function initUserUI() {
  const userCap = currentUser.charAt(0).toUpperCase() + currentUser.slice(1);
  const headerName = document.getElementById("header-user-name");
  if (headerName) headerName.textContent = userCap;
  const headerAvatar = document.getElementById("header-user-avatar");
  if (headerAvatar) headerAvatar.textContent = userCap.charAt(0);
  const cryptoUser = document.getElementById("crypto-active-user-display");
  if (cryptoUser) cryptoUser.textContent = currentUser;

  const peerCap = currentPeer.charAt(0).toUpperCase() + currentPeer.slice(1);
  const peerDisplay = document.getElementById("peer-name-display");
  if (peerDisplay) peerDisplay.textContent = peerCap;
  const peerAvatar = document.getElementById("peer-avatar-letter");
  if (peerAvatar) peerAvatar.textContent = peerCap.charAt(0);
  const headerTitle = document.getElementById("chat-header-title");
  if (headerTitle) headerTitle.textContent = `Chat with ${peerCap}`;
  const recInput = document.getElementById("vault-recipient-input");
  if (recInput) recInput.value = currentPeer;
}

// -----------------------------------------------------------------------------
// Navigation & Peer Switcher
// -----------------------------------------------------------------------------

function switchTab(tabId) {
  document.querySelectorAll(".nav-tab-btn").forEach(btn => btn.classList.remove("active"));
  document.querySelectorAll(".tab-content-panel").forEach(panel => panel.classList.remove("active"));

  const target = document.getElementById(`tab-${tabId}`);
  if (target) target.classList.add("active");

  const tabs = ["chat", "vault", "hndl", "crypto"];
  const idx = tabs.indexOf(tabId);
  if (idx >= 0) {
    document.querySelectorAll(".nav-tab-btn")[idx].classList.add("active");
  }

  if (tabId === "vault") {
    refreshVaultFiles();
  }
}

function switchPeer(newPeer) {
  if (!newPeer || newPeer.toLowerCase() === currentUser) return;
  currentPeer = newPeer.toLowerCase();

  const peerCap = currentPeer.charAt(0).toUpperCase() + currentPeer.slice(1);
  const peerDisplay = document.getElementById("peer-name-display");
  if (peerDisplay) peerDisplay.textContent = peerCap;
  const peerAvatar = document.getElementById("peer-avatar-letter");
  if (peerAvatar) peerAvatar.textContent = peerCap.charAt(0);
  const headerTitle = document.getElementById("chat-header-title");
  if (headerTitle) headerTitle.textContent = `Chat with ${peerCap}`;
  const recInput = document.getElementById("vault-recipient-input");
  if (recInput) recInput.value = currentPeer;

  loadState();
}

function updatePeerDropdown(users) {
  const select = document.getElementById("peer-selector");
  if (!select) return;

  const peers = users.filter(u => u.toLowerCase() !== currentUser);
  const currentVal = select.value || currentPeer;

  // Re-populate if options changed
  const currentOptions = Array.from(select.options).map(o => o.value);
  const isDifferent = peers.length !== currentOptions.length || peers.some(p => !currentOptions.includes(p));

  if (isDifferent) {
    select.innerHTML = "";
    peers.forEach(p => {
      const opt = document.createElement("option");
      opt.value = p;
      opt.textContent = p.charAt(0).toUpperCase() + p.slice(1);
      select.appendChild(opt);
    });

    if (peers.includes(currentPeer)) {
      select.value = currentPeer;
    } else if (peers.length > 0) {
      currentPeer = peers[0];
      select.value = currentPeer;
    }
  }
}

// -----------------------------------------------------------------------------
// State Synchronization
// -----------------------------------------------------------------------------

async function loadState() {
  try {
    const res = await fetch(`/api/v1/demo/state?user=${currentUser}&peer=${currentPeer}`);
    if (!res.ok) return;
    const data = await res.json();

    document.getElementById("stat-ratchet-turns").textContent = data.metrics.ratchet_turn;
    document.getElementById("telemetry-turns").textContent = data.metrics.ratchet_turn;
    document.getElementById("chat-turn-badge").textContent = data.metrics.ratchet_turn;

    const totalMsgs = data.metrics.sent_messages + data.metrics.received_messages;
    document.getElementById("telemetry-chain-step").textContent = `Step ${totalMsgs}`;

    if (data.users) {
      updatePeerDropdown(data.users);
    }

    if (data.keys) {
      document.getElementById("crypto-mldsa-fp").textContent = data.keys.mldsa_pub_fingerprint || "N/A";
      document.getElementById("crypto-opk-active").textContent = data.keys.active_onetime_prekeys || "20";
      const opk2 = document.getElementById("crypto-opk-active-2");
      if (opk2) opk2.textContent = data.keys.active_onetime_prekeys || "20";
      document.getElementById("crypto-opk-consumed").textContent = data.keys.consumed_onetime_prekeys || "0";
      document.getElementById("crypto-x25519-pub").textContent = (data.keys.x25519_pub_hex || "N/A").slice(0, 32) + "...";
      const userDisplay = document.getElementById("crypto-active-user-display");
      if (userDisplay) userDisplay.textContent = currentUser;
    }

    renderMessages(data.conversation || []);

  } catch (err) {
    console.warn("State sync error:", err);
  }
}

// -----------------------------------------------------------------------------
// Messaging
// -----------------------------------------------------------------------------

function renderMessages(messages) {
  const stream = document.getElementById("chat-stream");
  stream.innerHTML = "";

  if (messages.length === 0) {
    stream.innerHTML = `
      <div style="text-align:center; padding: 48px; color: var(--text-muted); font-size: 0.85rem; font-weight:600;">
        No messages yet with ${currentPeer.charAt(0).toUpperCase() + currentPeer.slice(1)}. Send a message below.
      </div>
    `;
    return;
  }

  messages.forEach(msg => {
    const isSent = msg.sender_id === currentUser;
    const row = document.createElement("div");
    row.className = `msg-bubble-wrap ${isSent ? 'sent' : 'received'}`;

    const dateStr = new Date(msg.timestamp * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

    let healingHtml = msg.is_healing_turn ? `<span style="font-weight:700; color:var(--text-main);">⚡ Healed</span> • ` : '';

    let statusBadge = `<span style="color:#16a34a;">✔ ML-DSA</span>`;
    let bubbleExtraStyle = "";
    if (msg.is_tampered || msg.status === "tamper_rejected" || msg.status === "tamper_detected_and_dropped") {
      statusBadge = `<span style="color:#ef4444; font-weight:700;">❌ Tamper Rejected</span>`;
      bubbleExtraStyle = "border-left: 3px solid #ef4444; background: rgba(239, 68, 68, 0.05);";
    } else if (msg.is_dropped || msg.status === "dropped_by_attacker") {
      statusBadge = `<span style="color:#f59e0b; font-weight:700;">🗑 Packet Dropped</span>`;
      bubbleExtraStyle = "border-left: 3px solid #f59e0b; background: rgba(245, 158, 11, 0.05);";
    }

    row.innerHTML = `
      <div class="msg-bubble" style="${bubbleExtraStyle}">
        <div style="font-weight:800; font-size:0.75rem; color:${isSent ? 'var(--text-main)' : 'var(--text-secondary)'}; margin-bottom:2px;">
          ${msg.sender_id.toUpperCase()}
        </div>
        <div>${escapeHtml(msg.text)}</div>
      </div>
      <div class="msg-meta-row">
        ${healingHtml}
        <span>Turn #${msg.ratchet_turn}</span> •
        ${statusBadge} •
        <span>${dateStr}</span>
      </div>
    `;
    stream.appendChild(row);
  });

  stream.scrollTop = stream.scrollHeight;
}

async function sendMessage() {
  const input = document.getElementById("chat-input");
  const text = input.value.trim();
  if (!text) return;
  input.value = "";

  try {
    const res = await fetch("/api/v1/demo/message/send", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        sender_id: currentUser,
        recipient_id: currentPeer,
        text: text
      })
    });
    if (res.ok) loadState();
  } catch (err) {
    alert("Send error: " + err);
  }
}

async function quickSend(role, text) {
  const senderId = role === 'incoming' ? currentPeer : currentUser;
  const recipientId = role === 'incoming' ? currentUser : currentPeer;

  try {
    const res = await fetch("/api/v1/demo/message/send", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        sender_id: senderId,
        recipient_id: recipientId,
        text: text
      })
    });
    if (res.ok) loadState();
  } catch (err) {
    alert("Error: " + err);
  }
}

// -----------------------------------------------------------------------------
// Vault (Sculptural Upload Slot)
// -----------------------------------------------------------------------------

function setupDropzone() {
  const slot = document.querySelector(".sculpted-upload-slot");
  if (!slot) return;

  ["dragenter", "dragover"].forEach(name => {
    slot.addEventListener(name, (e) => {
      e.preventDefault();
      slot.style.background = "#cfd2d9";
    });
  });

  ["dragleave", "drop"].forEach(name => {
    slot.addEventListener(name, (e) => {
      e.preventDefault();
      slot.style.background = "";
    });
  });

  slot.addEventListener("drop", (e) => {
    if (e.dataTransfer.files.length > 0) {
      handleFileSelected({ files: e.dataTransfer.files });
    }
  });
}

function handleFileSelected(input) {
  if (!input.files || input.files.length === 0) return;
  selectedFile = input.files[0];

  const label = document.getElementById("upload-status-label");
  label.textContent = `${selectedFile.name} (${(selectedFile.size / 1024).toFixed(1)} KB)`;

  const reader = new FileReader();
  reader.onload = (e) => {
    const arrayBuffer = e.target.result;
    const bytes = new Uint8Array(arrayBuffer);
    let binary = "";
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    selectedFileContentB64 = btoa(binary);
  };
  reader.readAsArrayBuffer(selectedFile);
}

function loadSampleFile(preset) {
  let content = "";
  if (preset === "defense_spec.pdf") {
    content = "QUANTUM-RESISTANT DEFENSE PROTOCOL SPECIFICATION\nClassification: RESTRICTED\nAlgorithms: FIPS 203 ML-KEM-768 & FIPS 204 ML-DSA-65\nIntegrity: Merkle Tree SHA-256";
  } else {
    content = "CRYPTOGRAPHIC INDEPENDENT KEY AUDIT REPORT 2026\nStatus: PASSED\nZero-Access Storage Guaranteed\nEach user holds private keys exclusively.";
  }

  selectedFile = {
    name: preset,
    size: content.length,
  };
  selectedFileContentB64 = btoa(content);

  document.getElementById("upload-status-label").textContent = `${preset} (${selectedFile.size} B)`;
}

async function uploadSelectedFile() {
  if (!selectedFileContentB64 || !selectedFile) {
    alert("Please select a file or click a sample file first.");
    return;
  }

  const uploadBtn = document.getElementById("btn-vault-upload");
  const statusBox = document.getElementById("upload-status-box");
  statusBox.style.display = "flex";
  statusBox.innerHTML = `
    <div>1. Streaming 64 KB Chunks & SHA-256...</div>
    <div>2. Generating AES-256-GCM DEK & Encapsulating with ML-KEM-768...</div>
    <div>3. Signing Manifest with ML-DSA-65 Private Key...</div>
  `;
  uploadBtn.disabled = true;

  try {
    const recipient = document.getElementById("vault-recipient-input").value.trim().toLowerCase() || currentPeer;
    const res = await fetch("/api/v1/demo/vault/upload", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        sender_id: currentUser,
        recipient_id: recipient,
        filename: selectedFile.name,
        content_b64: selectedFileContentB64
      })
    });

    const data = await res.json();
    statusBox.innerHTML += `<div style="color:var(--text-main); font-weight:700;">✔ Uploaded ${data.chunk_count} chunks (Encrypted for ${recipient})</div>`;
    refreshVaultFiles();
  } catch (err) {
    statusBox.innerHTML += `<div style="color:red;">Error: ${err}</div>`;
  } finally {
    uploadBtn.disabled = false;
  }
}

async function refreshVaultFiles() {
  try {
    const res = await fetch("/api/v1/vault/files");
    const data = await res.json();
    const tbody = document.getElementById("vault-files-tbody");
    tbody.innerHTML = "";

    if (!data.files || data.files.length === 0) {
      tbody.innerHTML = `<tr><td colspan="6" style="text-align:center; padding:24px; color:var(--text-muted);">Vault empty. Deposit a file above.</td></tr>`;
      return;
    }

    data.files.forEach(f => {
      const isRecipient = f.recipient_id === currentUser;
      const isSender = f.sender_id === currentUser;
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td><strong>${escapeHtml(f.filename)}</strong></td>
        <td>${(f.total_size / 1024).toFixed(1)} KB</td>
        <td>${f.chunk_count}</td>
        <td>${escapeHtml(f.sender_id)}</td>
        <td>
          <span class="nm-pill-badge ${isRecipient ? 'nm-badge-dark' : 'nm-badge-neutral'}" style="font-size:0.7rem;">
            ${escapeHtml(f.recipient_id || 'Anyone')}
          </span>
        </td>
        <td>
          <div style="display:flex; gap:6px;">
            <button class="nm-btn" style="padding:4px 10px; font-size:0.75rem;" onclick="inspectManifest('${f.file_id}')">Manifest</button>
            <button class="nm-btn-dark" style="padding:4px 12px; font-size:0.75rem;" onclick="downloadFile('${f.file_id}')">Decrypt</button>
          </div>
        </td>
      `;
      tbody.appendChild(tr);
    });
  } catch (err) {
    console.error("Vault refresh error:", err);
  }
}

async function inspectManifest(fileId) {
  try {
    const res = await fetch(`/api/v1/vault/manifest/${fileId}`);
    const data = await res.json();
    openModal(`Manifest: ${data.filename}`, `
      <pre class="compact-code" style="max-height:360px; overflow-y:auto;">${escapeHtml(JSON.stringify(data, null, 2))}</pre>
    `);
  } catch (err) {
    alert("Error: " + err);
  }
}

async function downloadFile(fileId) {
  try {
    const res = await fetch("/api/v1/demo/vault/download", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        user_id: currentUser,
        file_id: fileId
      })
    });
    const data = await res.json();

    if (data.status === "decryption_failed") {
      openModal(`Access Denied: ${data.filename}`, `
        <div style="padding:10px 0; color:#dc2626; font-weight:700; font-size:0.95rem;">
          ❌ Decryption Rejected
        </div>
        <div style="font-size:0.84rem; color:var(--text-secondary); line-height:1.5;">
          ${escapeHtml(data.error)}
        </div>
        <div style="margin-top:14px; padding:12px 14px; border-radius:var(--radius-sm); background:var(--bg-inset); font-size:0.76rem; color:var(--text-main); line-height:1.4;">
          <strong>Cryptographic Key Isolation:</strong> Each user holds a distinct ML-KEM-768 private key. Because this file was encrypted for a different recipient, your private key cannot unwrap the AES-256-GCM Data Encryption Key (DEK).
        </div>
      `);
      return;
    }

    if (data.is_text) {
      openModal(`Decrypted: ${data.filename}`, `
        <div style="display:flex; gap:6px; margin-bottom:10px;">
          <span class="nm-pill-badge nm-badge-dark">ML-DSA Verified</span>
          <span class="nm-pill-badge nm-badge-dark">ML-KEM Unwrapped</span>
          <span class="nm-pill-badge nm-badge-neutral">Decrypted by ${currentUser.toUpperCase()}</span>
        </div>
        <textarea class="compact-code" style="width:100%; height:200px; resize:none;" readonly>${escapeHtml(data.text_content)}</textarea>
      `);
    } else {
      const a = document.createElement("a");
      a.href = `data:application/octet-stream;base64,${data.content_b64}`;
      a.download = data.filename;
      a.click();
    }
  } catch (err) {
    alert("Decrypt error: " + err);
  }
}

// -----------------------------------------------------------------------------
// HNDL Simulation
// -----------------------------------------------------------------------------

async function runQuantumSimulation() {
  const container = document.getElementById("simulation-timeline");
  container.innerHTML = `
    <div class="nm-card step-card" style="grid-column: span 4; text-align:center; padding:32px;">
      <div style="color:var(--text-main); font-weight:800; font-size:1.05rem;">Simulating Shor's Algorithm Attack...</div>
    </div>
  `;

  try {
    const res = await fetch("/api/v1/demo/simulate-harvest", { method: "POST" });
    const data = await res.json();
    container.innerHTML = "";

    data.steps.forEach(s => {
      const card = document.createElement("div");
      card.className = "nm-card step-card";
      card.innerHTML = `
        <div class="step-circle" style="color:${s.color === 'green' ? '#16a34a' : 'var(--text-main)'}">${s.step}</div>
        <h4>${escapeHtml(s.tag)}</h4>
        <p>${escapeHtml(s.title)}</p>
        ${s.result ? `<div style="font-size:0.75rem; font-weight:800; color:var(--text-main); margin-top:4px;">✔ 0 Bits Leaked</div>` : ''}
        ${s.plaintext_revealed ? `<div style="font-size:0.72rem; color:#16a34a; font-weight:700; margin-top:4px;">✔ Decrypted by Bob</div>` : ''}
      `;
      container.appendChild(card);
    });
  } catch (err) {
    container.innerHTML = `<div style="color:red; padding:20px;">Error: ${err}</div>`;
  }
}

// -----------------------------------------------------------------------------
// Modal
// -----------------------------------------------------------------------------

function openModal(title, bodyHtml) {
  document.getElementById("modal-title").textContent = title;
  document.getElementById("modal-body").innerHTML = bodyHtml;
  document.getElementById("inspect-modal").classList.add("open");
}

function closeModal() {
  document.getElementById("inspect-modal").classList.remove("open");
}

function escapeHtml(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}
