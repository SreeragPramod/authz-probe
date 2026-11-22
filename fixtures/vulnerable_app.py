"""Deliberately vulnerable API fixture with BOLA."""

from fastapi import FastAPI, Header, HTTPException

app = FastAPI(title="Fixture API - Vulnerable")

# Simulated Database
DOCUMENTS = {
    "alice_doc": {"id": "alice_doc", "owner": "alice", "content": "Alice's Secret Financial Records"},
    "bob_doc": {"id": "bob_doc", "owner": "bob", "content": "Bob's Personal Medical Notes"},
}

@app.get("/api/documents/{doc_id}")
def get_document(doc_id: str, authorization: str = Header(None)):
    # Vulnerability: No ownership check! Anyone can read any document.
    if doc_id not in DOCUMENTS:
        raise HTTPException(status_code=404, detail="Document not found")
    return DOCUMENTS[doc_id]
