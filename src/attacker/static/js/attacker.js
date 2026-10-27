/**
 * Intruder Interception Console Client Logic
 * Coordinates wiretapping, quantum cryptanalysis, tampering, and packet dropping.
 */

let packetsList = [];
let selectedPacketId = null;
let currentMode = "tamper";
let isServerOn = true;

document.addEventListener("DOMContentLoaded", () => {
  fetchPackets();
  setInterval(fetchPackets, 2000);
});

function updatePowerUI(isOn) {
  isServerOn = !!isOn;
  const btnOn = document.getElementById("power-btn-on");
  const btnOff = document.getElementById("power-btn-off");
  const banner = document.getElementById("master-status-banner");
  const headline = document.getElementById("status-headline");
  const subtext = document.getElementById("status-subtext");
  const badge = document.getElementById("status-badge-live");

  if (isServerOn) {
    if (btnOn) btnOn.classList.add("active");
    if (btnOff) btnOff.classList.remove("active");
    if (banner) {
      banner.classList.remove("off");
      banner.classList.add("on");
    }
    if (headline) headline.textContent = "INTRUDER SERVER IS ON — AUTOMATIC WIRE TAMPERING ACTIVE";
    if (subtext) subtext.textContent = "All chat messages and shared vault documents between Alice and Bob are automatically intercepted and tampered on the wire, triggering cryptographic verification errors on their end.";
    if (badge) {
      badge.textContent = "TAMPERING ACTIVE";
    }
  } else {
    if (btnOff) btnOff.classList.add("active");
    if (btnOn) btnOn.classList.remove("active");
    if (banner) {
      banner.classList.remove("on");
      banner.classList.add("off");
    }
    if (headline) headline.textContent = "INTRUDER SERVER IS OFF — STANDBY / PASS-THROUGH MODE";
    if (subtext) subtext.textContent = "Wiretap is in standby. Messages and vault documents pass between Alice and Bob cleanly without tampering or errors.";
    if (badge) {
      badge.textContent = "STANDBY (CLEAN)";
    }
  }
}

async function togglePower(state) {
  const isOn = (state === 'on');
  updatePowerUI(isOn);
  try {
    const res = await fetch("/api/v1/attacker/power", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ state: state })
    });
    if (res.ok) {
      const data = await res.json();
      updatePowerUI(data.is_on);
      fetchPackets();
    }
  } catch (e) {
    console.error("Error toggling power:", e);
  }
}

async function fetchPackets() {
  try {
    const res = await fetch("/api/v1/attacker/packets");
    if (!res.ok) return;
    const data = await res.json();
    packetsList = data.packets || [];

    // Update telemetry and power state
    if (data.status) {
      currentMode = data.status.interceptor_mode || "tamper";
      const onState = (data.status.is_on !== undefined) ? data.status.is_on : (currentMode === "tamper" || currentMode === "on");
      updatePowerUI(onState);

      if (data.status.stats) {
        document.getElementById("stat-intercepted").textContent = data.status.stats.total_intercepted || 0;
        document.getElementById("stat-reads").textContent = data.status.stats.read_attempts || 0;
        document.getElementById("stat-tampered").textContent = data.status.stats.tampered_count || 0;
        document.getElementById("stat-dropped").textContent = data.status.stats.dropped_count || 0;
      }
    }

    renderPacketsStream();

    // Auto-select first packet if none selected
    if (!selectedPacketId && packetsList.length > 0) {
      selectPacket(packetsList[0].packet_id);
    } else if (selectedPacketId) {
      const current = packetsList.find(p => p.packet_id === selectedPacketId);
      if (current) renderInspector(current);
    }
  } catch (err) {
    console.warn("Fetch packets error:", err);
  }
}

function renderPacketsStream() {
  const container = document.getElementById("packets-container");
  if (packetsList.length === 0) {
    container.innerHTML = `
      <div style="text-align:center; padding:48px 16px; color:var(--text-dim); font-size:0.82rem; font-family:var(--font-mono);">
        No intercepted packets yet.<br>Send a message or deposit a document between Alice & Bob in the Vault app to capture live wire traffic.
      </div>
    `;
    return;
  }

  container.innerHTML = "";
  packetsList.forEach(pkt => {
    const isSelected = pkt.packet_id === selectedPacketId;
    const item = document.createElement("div");
    item.className = `packet-item ${isSelected ? 'selected' : ''}`;
    item.onclick = () => selectPacket(pkt.packet_id);

    const timeStr = new Date(pkt.timestamp * 1000).toLocaleTimeString();
    const isVault = pkt.payload_type === "vault_file";
    const typeBadge = isVault
      ? `<span style="font-size:0.68rem; padding:2px 6px; border-radius:4px; background:rgba(168,85,247,0.15); color:var(--cyber-purple); font-weight:800;">VAULT FILE</span>`
      : `<span style="font-size:0.68rem; padding:2px 6px; border-radius:4px; background:rgba(56,189,248,0.15); color:var(--cyber-blue); font-weight:800;">HPQ-DR MSG</span>`;

    const subInfo = isVault
      ? `<span>File: ${escapeHtml(pkt.filename || 'vault_deposit')} • ${pkt.seq_num} chunks</span>`
      : `<span>Turn #${pkt.ratchet_turn} • Seq #${pkt.seq_num}</span>`;

    item.innerHTML = `
      <div class="packet-item-header">
        <div style="display:flex; align-items:center; gap:8px;">
          ${typeBadge}
          <span style="font-weight:700; color:var(--text-main);">${pkt.sender_id.toUpperCase()} ➔ ${pkt.recipient_id.toUpperCase()}</span>
        </div>
        <span class="status-badge ${pkt.status}">${pkt.status.replace('_', ' ')}</span>
      </div>
      <div style="display:flex; justify-content:space-between; font-size:0.74rem; font-family:var(--font-mono); color:var(--text-muted); margin-top:4px;">
        ${subInfo}
        <span>${pkt.ciphertext_len} B Payload</span>
      </div>
      <div style="font-size:0.7rem; font-family:var(--font-mono); color:var(--text-dim); margin-top:2px;">
        Captured: ${timeStr} • ID: ${pkt.packet_id.slice(-8)}
      </div>
    `;
    container.appendChild(item);
  });
}

function selectPacket(packetId) {
  selectedPacketId = packetId;
  renderPacketsStream();
  const pkt = packetsList.find(p => p.packet_id === packetId);
  if (pkt) renderInspector(pkt);
}

function renderInspector(pkt) {
  document.getElementById("inspector-pkt-id").textContent = pkt.packet_id;
  const content = document.getElementById("inspector-content");

  const ctPreview = pkt.ciphertext_b64;
  const sigPreview = pkt.signature_b64 ? (pkt.signature_b64.slice(0, 36) + "...") : "None";
  const dhPreview = pkt.dh_pub_b64 ? (pkt.dh_pub_b64.slice(0, 36) + "...") : "None";
  const kemPreview = pkt.kem_ct_b64 ? (`${pkt.kem_ct_len} B (${pkt.kem_ct_b64.slice(0, 24)}...)`) : "None (Symmetric Turn)";

  let attackLogHtml = "";

  if (pkt.cryptanalysis_result) {
    const res = pkt.cryptanalysis_result;
    attackLogHtml = `
      <div class="terminal-card">
        <div class="term-highlight">=== QUANTUM CRYPTANALYSIS LOG • ${pkt.packet_id} ===</div>
        <div>[Phase 1] ${res.phase_1_trial_decryption.method}: <span class="term-alert">${res.phase_1_trial_decryption.status}</span></div>
        <div style="color:var(--text-muted); font-size:0.72rem;">${res.phase_1_trial_decryption.details}</div>
        <br>
        <div>[Phase 2] ${res.phase_2_classical_crqc_attack.method}: <span class="term-warn">${res.phase_2_classical_crqc_attack.status}</span></div>
        <div style="color:var(--text-muted); font-size:0.72rem;">${res.phase_2_classical_crqc_attack.details}</div>
        <div class="term-warn">Extracted Classical ECDH Secret: ${res.phase_2_classical_crqc_attack.compromised_ecdh_secret}</div>
        <br>
        <div>[Phase 3] ${res.phase_3_lattice_shield_defense.method}: <span class="term-success">${res.phase_3_lattice_shield_defense.status}</span></div>
        <div style="color:var(--text-muted); font-size:0.72rem;">${res.phase_3_lattice_shield_defense.details}</div>
        <br>
        <div class="term-success">==================================================</div>
        <div class="term-success">RESULT: Plaintext Revealed = FALSE | Bytes Leaked = 0</div>
        <div style="font-weight:700;">Attacker View: ${res.final_outcome.attacker_view}</div>
        <div class="term-highlight">${res.final_outcome.defense_summary}</div>
      </div>
    `;
  } else if (pkt.status === "tampered") {
    attackLogHtml = `
      <div class="terminal-card">
        <div class="term-warn">⚠ ACTIVE MITM TAMPER INJECTED</div>
        <div>Mod Type: <span class="term-highlight">${pkt.tamper_details?.type || "ciphertext_bitflip"}</span></div>
        <div style="font-size:0.72rem; color:var(--text-muted);">${pkt.tamper_details?.description || ""}</div>
        <br>
        <div class="term-alert">DEFENSE OUTCOME AT RECIPIENT (BOB):</div>
        <div>1. Bob verifies NIST FIPS 204 ML-DSA-65 digital signature on envelope.</div>
        <div>2. Verification FAILS due to altered ciphertext/signature bits.</div>
        <div>3. Tampered packet is REJECTED and DROPPED with Security Alert!</div>
      </div>
    `;
  } else if (pkt.status === "dropped") {
    attackLogHtml = `
      <div class="terminal-card">
        <div class="term-alert">🗑 PACKET DROPPED (DENIAL OF SERVICE)</div>
        <div>The intercepted envelope was obliterated from the delivery pipeline.</div>
        <div style="font-size:0.72rem; color:var(--text-muted);">Bob will never receive this message. Ratchet sequence will observe a dropped packet gap.</div>
      </div>
    `;
  } else if (pkt.status === "forwarded" || pkt.status === "forwarded_clean") {
    attackLogHtml = `
      <div class="terminal-card">
        <div class="term-success">✔ PACKET FORWARDED CLEAN</div>
        <div>Envelope released to Bob unaltered. ML-DSA-65 signature is valid. Bob successfully decodes message.</div>
      </div>
    `;
  }

  content.innerHTML = `
    <!-- Metadata Well -->
    <div class="info-well">
      <div class="info-row">
        <span>Packet Target:</span>
        <span style="color:var(--cyber-blue); font-weight:700;">${pkt.sender_id.toUpperCase()} ➔ ${pkt.recipient_id.toUpperCase()}</span>
      </div>
      <div class="info-row">
        <span>Ratchet Turn / Seq:</span>
        <span>Turn #${pkt.ratchet_turn} • Step #${pkt.seq_num}</span>
      </div>
      <div class="info-row">
        <span>Payload Size:</span>
        <span>${pkt.ciphertext_len} Bytes</span>
      </div>
      <div class="info-row">
        <span>ML-DSA-65 Signature:</span>
        <span style="font-size:0.72rem; color:var(--text-main);">${sigPreview}</span>
      </div>
      <div class="info-row">
        <span>X25519 DH Public Key:</span>
        <span style="font-size:0.72rem; color:var(--text-main);">${dhPreview}</span>
      </div>
      <div class="info-row">
        <span>ML-KEM-768 Ciphertext:</span>
        <span style="font-size:0.72rem; color:var(--text-main);">${kemPreview}</span>
      </div>
    </div>

    <!-- Raw Ciphertext View -->
    <div>
      <div style="font-size:0.72rem; font-weight:700; color:var(--text-muted); margin-bottom:4px; font-family:var(--font-mono);">
        INTERCEPTED CIPHERTEXT (BASE64)
      </div>
      <div class="code-box">${escapeHtml(ctPreview)}</div>
    </div>

    <!-- Adversary Action Suite -->
    <div>
      <div style="font-size:0.72rem; font-weight:700; color:var(--text-muted); margin-bottom:8px; font-family:var(--font-mono);">
        EXECUTE ADVERSARIAL ATTACK
      </div>
      <div class="action-grid">
        <button class="action-btn read" onclick="executeRead('${pkt.packet_id}')">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
          Read Attempt
        </button>

        <button class="action-btn modify" onclick="executeModify('${pkt.packet_id}', 'ciphertext_bitflip')">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><path d="M12 20h9"/><path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4L16.5 3.5z"/></svg>
          Modify (Bit-Flip)
        </button>

        <button class="action-btn modify" onclick="executeModify('${pkt.packet_id}', 'signature_corrupt')">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
          Corrupt Signature
        </button>

        <button class="action-btn delete" onclick="executeDelete('${pkt.packet_id}')">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>
          Delete (Drop)
        </button>
      </div>

      <div style="margin-top:8px;">
        <button class="action-btn forward" style="width:100%; flex-direction:row; justify-content:center;" onclick="executeForward('${pkt.packet_id}')">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><polygon points="5 4 15 12 5 20 5 4"/><line x1="19" y1="5" x2="19" y2="19"/></svg>
          Forward Intact to Bob
        </button>
      </div>
    </div>

    <!-- Cryptanalysis Terminal Log -->
    ${attackLogHtml}
  `;
}

async function executeRead(packetId) {
  try {
    const res = await fetch("/api/v1/attacker/action/read", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ packet_id: packetId })
    });
    if (res.ok) {
      await fetchPackets();
    }
  } catch (err) {
    alert("Read attempt error: " + err);
  }
}

async function executeModify(packetId, tamperType) {
  try {
    const res = await fetch("/api/v1/attacker/action/modify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        packet_id: packetId,
        tamper_type: tamperType,
        auto_forward: true
      })
    });
    if (res.ok) {
      await fetchPackets();
    }
  } catch (err) {
    alert("Modify error: " + err);
  }
}

async function executeDelete(packetId) {
  try {
    const res = await fetch("/api/v1/attacker/action/delete", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ packet_id: packetId })
    });
    if (res.ok) {
      await fetchPackets();
    }
  } catch (err) {
    alert("Delete error: " + err);
  }
}

async function executeForward(packetId) {
  try {
    const res = await fetch("/api/v1/attacker/action/forward", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ packet_id: packetId })
    });
    if (res.ok) {
      await fetchPackets();
    }
  } catch (err) {
    alert("Forward error: " + err);
  }
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
