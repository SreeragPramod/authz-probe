"""Secure API fixture with proper Object-Level Authorization checks."""

from fastapi import FastAPI, Header, HTTPException

app = FastAPI(title="Fixture API - Fixed")

DOCUMENTS = {
    "alice_doc": {"id": "alice_doc", "owner": "alice", "content": "Alice's Secret Financial Records"},
    "bob_doc": {"id": "bob_doc", "owner": "bob", "content": "Bob's Personal Medical Notes"},
}

def get_current_user(auth_header: str) -> str:
    """Simulate token decoding."""
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid token")
    token = auth_header.split(" ")[1]
    if token == "token_alice":
        return "alice"
    if token == "token_bob":
        return "bob"
    raise HTTPException(status_code=401, detail="Unauthorized")

@app.get("/api/documents/{doc_id}")
def get_document(doc_id: str, authorization: str = Header(None)):
    current_user = get_current_user(authorization)

    if doc_id not in DOCUMENTS:
        raise HTTPException(status_code=404, detail="Document not found")

    doc = DOCUMENTS[doc_id]

    # SECURITY FIX: Server-side object ownership verification!
    if doc["owner"] != current_user:
        raise HTTPException(status_code=403, detail="Forbidden: You do not own this document")

    return doc
