"""Untrusted Zero-Access Relay and Storage Server with Neumorphic Web Frontend."""

from __future__ import annotations

import base64
import os
from typing import Dict, List, Optional
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from src.server.storage import ZeroAccessStorage
from src.server.demo_service import DemoManager

storage = ZeroAccessStorage()
demo_manager = DemoManager(storage)

app = FastAPI(
    title="Zero-Access HPQ-DR Relay & Vault Server",
    description="Untrusted relay server for hybrid post-quantum messaging and encrypted file vault",
    version="1.0.0",
)

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
if os.path.exists(STATIC_DIR):
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


# -----------------------------------------------------------------------------
# Core Zero-Access Protocol Endpoints
# -----------------------------------------------------------------------------

class RegisterBundleRequest(BaseModel):
    user_id: str
    bundle: dict


class SendMessageRequest(BaseModel):
    recipient_id: str
    envelope: dict


class StoreManifestRequest(BaseModel):
    file_id: str
    manifest: dict


@app.get("/")
def serve_index():
    index_path = os.path.join(STATIC_DIR, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return {"message": "Quantum-Resistant Secure Vault API running"}


@app.get("/login")
def serve_login():
    login_path = os.path.join(STATIC_DIR, "login.html")
    if os.path.exists(login_path):
        return FileResponse(login_path)
    return {"message": "Login page not found"}


@app.get("/api/v1/health")
def health():
    return {
        "status": "healthy",
        "registered_users": list(storage.prekey_bundles.keys()),
        "stored_manifests": len(storage.manifests),
        "stored_chunks": len(storage.chunks),
    }


@app.post("/api/v1/prekeys/register")
def register_prekey_bundle(req: RegisterBundleRequest):
    storage.register_bundle(req.user_id, req.bundle)
    return {"status": "registered", "user_id": req.user_id}


@app.get("/api/v1/prekeys/{user_id}")
def get_prekey_bundle(user_id: str):
    bundle = storage.fetch_bundle(user_id)
    if not bundle:
        raise HTTPException(status_code=404, detail=f"No prekey bundle found for user {user_id}")
    return bundle


@app.post("/api/v1/messages/send")
def send_message(req: SendMessageRequest):
    storage.store_message(req.recipient_id, req.envelope)
    return {"status": "queued", "recipient_id": req.recipient_id}


@app.get("/api/v1/messages/inbox/{user_id}")
def get_inbox(user_id: str):
    messages = storage.fetch_and_drain_messages(user_id)
    return {"user_id": user_id, "messages": messages}


@app.post("/api/v1/vault/manifest")
def upload_manifest(req: StoreManifestRequest):
    storage.store_manifest(req.file_id, req.manifest)
    return {"status": "stored", "file_id": req.file_id}


@app.get("/api/v1/vault/manifest/{file_id}")
def get_manifest(file_id: str):
    manifest = storage.fetch_manifest(file_id)
    if not manifest:
        raise HTTPException(status_code=404, detail=f"Manifest not found for file {file_id}")
    return manifest


@app.get("/api/v1/vault/files")
def list_vault_files():
    files = []
    for file_id, m in storage.manifests.items():
        files.append({
            "file_id": file_id,
            "filename": m.get("filename"),
            "total_size": m.get("total_size"),
            "chunk_count": m.get("chunk_count"),
            "sender_id": m.get("sender_id"),
            "recipient_id": m.get("recipient_id"),
            "timestamp": m.get("timestamp"),
            "recipient_prekey_id": m.get("recipient_prekey_id"),
        })
    return {"files": files}


@app.post("/api/v1/vault/chunk/{chunk_hash}")
async def upload_chunk(chunk_hash: str, request: Request):
    chunk_data = await request.body()
    if not chunk_data:
        raise HTTPException(status_code=400, detail="Empty chunk data")
    storage.store_chunk(chunk_hash, chunk_data)
    return {"status": "chunk_stored", "chunk_hash": chunk_hash, "bytes": len(chunk_data)}


@app.get("/api/v1/vault/chunk/{chunk_hash}")
def download_chunk(chunk_hash: str):
    chunk_data = storage.fetch_chunk(chunk_hash)
    if chunk_data is None:
        raise HTTPException(status_code=404, detail=f"Chunk not found: {chunk_hash}")
    return Response(content=chunk_data, media_type="application/octet-stream")


# -----------------------------------------------------------------------------
# Demo UI Helper Endpoints
# -----------------------------------------------------------------------------

class DemoSendMessageRequest(BaseModel):
    sender_id: str
    recipient_id: str
    text: str


class DemoUploadFileRequest(BaseModel):
    sender_id: str
    recipient_id: str
    filename: str
    content_b64: str


class DemoDownloadFileRequest(BaseModel):
    user_id: str
    file_id: str


class AuthLoginRequest(BaseModel):
    user_id: str


@app.post("/api/v1/auth/login")
def auth_login(req: AuthLoginRequest):
    if not req.user_id or not req.user_id.strip():
        raise HTTPException(status_code=400, detail="User ID cannot be empty")
    return demo_manager.login(req.user_id)


@app.get("/api/v1/auth/users")
def auth_list_users():
    return {"users": demo_manager.list_users()}


@app.get("/api/v1/demo/state")
def get_demo_state(user: str = "alice", peer: Optional[str] = None):
    return demo_manager.get_state(active_user=user, peer_id=peer)


@app.post("/api/v1/demo/message/send")
def demo_send_message(req: DemoSendMessageRequest):
    return demo_manager.send_message(req.sender_id, req.recipient_id, req.text)


@app.post("/api/v1/demo/vault/upload")
def demo_upload_file(req: DemoUploadFileRequest):
    content_bytes = base64.b64decode(req.content_b64.encode("ascii"))
    return demo_manager.upload_file(req.sender_id, req.recipient_id, req.filename, content_bytes)


@app.post("/api/v1/demo/vault/download")
def demo_download_file(req: DemoDownloadFileRequest):
    return demo_manager.download_file(req.user_id, req.file_id)


@app.post("/api/v1/demo/simulate-harvest")
def demo_simulate_harvest():
    return demo_manager.simulate_harvest_attack()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
