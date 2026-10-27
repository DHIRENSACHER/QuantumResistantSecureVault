"""Independent Attacker Backend Server running on Port 8080."""

from __future__ import annotations

import os
import sys
from typing import Any, Dict, List, Optional
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import requests

# Ensure project root is in sys.path when running as a direct script
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from src.attacker.interceptor import AttackerInterceptor

app = FastAPI(
    title="Intruder Interception & MITM Server",
    description="Independent attack proxy and eavesdropping console for HPQ-DR wire surveillance",
    version="1.0.0",
)

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
if os.path.exists(STATIC_DIR):
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

interceptor = AttackerInterceptor.get_instance()
MAIN_RELAY_URL = os.environ.get("MAIN_RELAY_URL", "http://127.0.0.1:8000")


# -----------------------------------------------------------------------------
# Request Models
# -----------------------------------------------------------------------------

class InterceptPayloadRequest(BaseModel):
    sender_id: str
    recipient_id: str
    envelope: dict


class PacketActionRequest(BaseModel):
    packet_id: str


class ModifyPayloadRequest(BaseModel):
    packet_id: str
    tamper_type: str = "ciphertext_bitflip"  # ciphertext_bitflip, signature_corrupt, header_seq_alter
    custom_payload: Optional[str] = None
    auto_forward: bool = True


class ModeChangeRequest(BaseModel):
    mode: str  # on, off, hold, pass, tamper, drop


class PowerToggleRequest(BaseModel):
    state: str = "on"  # on or off


# -----------------------------------------------------------------------------
# Routes
# -----------------------------------------------------------------------------

@app.get("/")
def serve_attacker_ui():
    index_path = os.path.join(STATIC_DIR, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return {"message": "Intruder Interception Server running on port 8080"}


@app.get("/api/v1/attacker/status")
def get_status():
    return interceptor.get_status()


@app.get("/api/v1/attacker/power")
def get_power():
    return {
        "status": "ok",
        "is_on": interceptor.is_on(),
        "mode": interceptor.get_status()["interceptor_mode"],
    }


@app.post("/api/v1/attacker/power")
def set_power(req: PowerToggleRequest):
    is_on = str(req.state).lower() in ("on", "true", "1")
    interceptor.set_power(is_on)
    return {
        "status": "updated",
        "is_on": interceptor.is_on(),
        "mode": interceptor.get_status()["interceptor_mode"],
    }


@app.post("/api/v1/attacker/mode")
def set_mode(req: ModeChangeRequest):
    new_mode = interceptor.set_mode(req.mode)
    return {"status": "updated", "mode": new_mode, "is_on": interceptor.is_on()}


@app.get("/api/v1/attacker/packets")
def list_packets():
    return {"packets": interceptor.list_packets(), "status": interceptor.get_status()}


@app.get("/api/v1/attacker/packet/{packet_id}")
def get_packet(packet_id: str):
    packet = interceptor.packets.get(packet_id)
    if not packet:
        raise HTTPException(status_code=404, detail="Packet not found")
    return packet


@app.post("/api/v1/attacker/intercept")
def intercept_packet(req: InterceptPayloadRequest):
    """Called by relay wire hook or MITM proxy to capture wire packets."""
    pkt = interceptor.intercept(req.sender_id, req.recipient_id, req.envelope)
    return {"status": "captured", "packet": pkt}


@app.post("/api/v1/attacker/action/read")
def action_read(req: PacketActionRequest):
    """Executes simulated quantum cryptanalysis & lattice attack."""
    try:
        result = interceptor.attempt_read(req.packet_id)
        return {"status": "success", "result": result}
    except KeyError:
        raise HTTPException(status_code=404, detail="Packet not found")


@app.post("/api/v1/attacker/action/modify")
def action_modify(req: ModifyPayloadRequest):
    """Tampers with ciphertext or signature and optionally forwards to Bob."""
    try:
        tamper_res = interceptor.tamper_packet(
            packet_id=req.packet_id,
            tamper_type=req.tamper_type,
            custom_payload=req.custom_payload,
        )

        forward_res = None
        if req.auto_forward:
            forward_res = interceptor.forward_packet(req.packet_id, use_tampered=True)
            # Try to push to main relay mailbox if reachable
            try:
                env_to_send = tamper_res["tampered_envelope"]
                pkt = interceptor.packets[req.packet_id]
                requests.post(
                    f"{MAIN_RELAY_URL}/api/v1/messages/send",
                    json={"recipient_id": pkt["recipient_id"], "envelope": env_to_send},
                    timeout=1.0,
                )
            except Exception:
                pass

        return {
            "status": "tampered",
            "tamper_details": tamper_res["tamper_details"],
            "tampered_envelope": tamper_res["tampered_envelope"],
            "forward_result": forward_res,
        }
    except KeyError:
        raise HTTPException(status_code=404, detail="Packet not found")


@app.post("/api/v1/attacker/action/delete")
def action_delete(req: PacketActionRequest):
    """Drops / deletes an intercepted packet."""
    try:
        res = interceptor.drop_packet(req.packet_id)
        return res
    except KeyError:
        raise HTTPException(status_code=404, detail="Packet not found")


@app.post("/api/v1/attacker/action/forward")
def action_forward(req: PacketActionRequest):
    """Releases clean packet to recipient."""
    try:
        res = interceptor.forward_packet(req.packet_id, use_tampered=False)
        pkt = interceptor.packets[req.packet_id]
        try:
            requests.post(
                f"{MAIN_RELAY_URL}/api/v1/messages/send",
                json={"recipient_id": pkt["recipient_id"], "envelope": pkt["raw_envelope"]},
                timeout=1.0,
            )
        except Exception:
            pass
        return res
    except KeyError:
        raise HTTPException(status_code=404, detail="Packet not found")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8080)
