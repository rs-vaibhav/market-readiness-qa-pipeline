"""
Shared pytest fixtures for the backend / RAG test suite.
"""

import time
from dataclasses import dataclass, field
from typing import Any
from unittest.mock import MagicMock

import pytest


# ---------------------------------------------------------------------------
# Fake / in-memory services used by multiple test modules
# ---------------------------------------------------------------------------

@dataclass
class FakeVectorStore:
    """In-memory vector store mock."""
    _store: dict[str, list[float]] = field(default_factory=dict)

    def upsert(self, doc_id: str, embedding: list[float]) -> None:
        if not isinstance(embedding, list) or not all(isinstance(v, (int, float)) for v in embedding):
            raise ValueError("embedding must be a list of floats")
        self._store[doc_id] = embedding

    def query(self, embedding: list[float], top_k: int = 5) -> list[dict]:
        results = []
        for doc_id, vec in self._store.items():
            score = sum(a * b for a, b in zip(embedding, vec)) / (
                max(sum(x ** 2 for x in embedding) ** 0.5 * sum(x ** 2 for x in vec) ** 0.5, 1e-9)
            )
            results.append({"id": doc_id, "score": round(score, 4)})
        return sorted(results, key=lambda x: x["score"], reverse=True)[:top_k]

    def delete(self, doc_id: str) -> bool:
        return self._store.pop(doc_id, None) is not None

    def count(self) -> int:
        return len(self._store)


@dataclass
class FakeRAGService:
    """Simulated RAG pipeline: chunk → embed → retrieve → generate."""
    vector_store: FakeVectorStore = field(default_factory=FakeVectorStore)

    def chunk_text(self, text: str, chunk_size: int = 200, overlap: int = 50) -> list[str]:
        if not isinstance(text, str):
            raise TypeError(f"Expected str, got {type(text).__name__}")
        if not text:
            return []
        chunks = []
        start = 0
        while start < len(text):
            end = min(start + chunk_size, len(text))
            chunks.append(text[start:end])
            start += chunk_size - overlap
        return chunks

    def embed(self, text: str, dim: int = 128) -> list[float]:
        import hashlib
        h = hashlib.sha256(text.encode()).digest()
        raw = [b / 255.0 for b in h]
        while len(raw) < dim:
            raw += raw
        return raw[:dim]

    def ingest(self, doc_id: str, text: str) -> int:
        chunks = self.chunk_text(text)
        for i, chunk in enumerate(chunks):
            emb = self.embed(chunk)
            self.vector_store.upsert(f"{doc_id}_chunk_{i}", emb)
        return len(chunks)

    def query(self, question: str, top_k: int = 3) -> dict[str, Any]:
        emb = self.embed(question)
        hits = self.vector_store.query(emb, top_k=top_k)
        if not hits or hits[0]["score"] < 0.3:
            return {"answer": "I don't know.", "confidence": 0.0, "sources": [], "abstained": True}
        return {
            "answer": f"Based on {len(hits)} sources, here is the answer to '{question}'.",
            "confidence": round(hits[0]["score"], 4),
            "sources": [h["id"] for h in hits],
            "abstained": False,
        }


@dataclass
class FakeBackendAPI:
    """Simulated REST-style backend with health, CRUD, and search endpoints."""
    _db: dict[str, dict] = field(default_factory=dict)
    _rag: FakeRAGService = field(default_factory=FakeRAGService)
    _healthy: bool = True

    def health(self) -> dict:
        if not self._healthy:
            raise ConnectionError("Service unavailable")
        return {"status": "ok", "version": "1.2.0", "uptime_s": 86400}

    def create_document(self, doc_id: str, title: str, body: str) -> dict:
        if not title or not body:
            raise ValueError("title and body are required")
        doc = {"id": doc_id, "title": title, "body": body, "created_at": "2026-10-20T00:00:00Z"}
        self._db[doc_id] = doc
        self._rag.ingest(doc_id, body)
        return doc

    def get_document(self, doc_id: str) -> dict | None:
        return self._db.get(doc_id)

    def delete_document(self, doc_id: str) -> bool:
        if doc_id in self._db:
            del self._db[doc_id]
            return True
        return False

    def search(self, query: str) -> dict:
        return self._rag.query(query)

    def simulate_timeout(self, seconds: float = 5.0) -> None:
        time.sleep(seconds)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def vector_store() -> FakeVectorStore:
    return FakeVectorStore()


@pytest.fixture
def rag_service() -> FakeRAGService:
    return FakeRAGService()


@pytest.fixture
def backend_api() -> FakeBackendAPI:
    return FakeBackendAPI()


@pytest.fixture
def populated_api() -> FakeBackendAPI:
    api = FakeBackendAPI()
    api.create_document("doc1", "Python Guide", "Python is a versatile programming language used for web development, data science, and automation. " * 10)
    api.create_document("doc2", "RAG Overview", "Retrieval Augmented Generation combines retrieval with generation to produce grounded answers. " * 10)
    api.create_document("doc3", "Testing Best Practices", "Automated testing improves code quality by catching regressions early. Unit, integration, and e2e tests form a testing pyramid. " * 10)
    return api
