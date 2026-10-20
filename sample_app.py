"""
Sample application module — a toy document processing API.
Used to demonstrate the source analyzer & test generator.
"""

import hashlib
import json
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Document:
    """Represents a stored document."""
    doc_id: str
    title: str
    content: str
    tags: list[str] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)

    def word_count(self) -> int:
        """Return the number of words in the content."""
        return len(self.content.split())

    def char_count(self) -> int:
        """Return the number of characters in the content."""
        return len(self.content)

    def summary(self, max_words: int = 50) -> str:
        """Return a truncated summary of the content."""
        words = self.content.split()
        if len(words) <= max_words:
            return self.content
        return " ".join(words[:max_words]) + "..."

    def add_tag(self, tag: str) -> None:
        """Add a tag if not already present."""
        if not tag:
            raise ValueError("Tag cannot be empty")
        if tag not in self.tags:
            self.tags.append(tag)

    def has_tag(self, tag: str) -> bool:
        return tag in self.tags

    def content_hash(self) -> str:
        """SHA-256 hash of the content."""
        return hashlib.sha256(self.content.encode()).hexdigest()


class DocumentStore:
    """In-memory document storage with search capabilities."""

    def __init__(self):
        self._docs: dict[str, Document] = {}

    def add(self, doc: Document) -> Document:
        """Add a document to the store."""
        if not doc.doc_id:
            raise ValueError("doc_id is required")
        if doc.doc_id in self._docs:
            raise KeyError(f"Document '{doc.doc_id}' already exists")
        self._docs[doc.doc_id] = doc
        return doc

    def get(self, doc_id: str) -> Optional[Document]:
        """Retrieve a document by ID."""
        return self._docs.get(doc_id)

    def delete(self, doc_id: str) -> bool:
        """Delete a document. Returns True if it existed."""
        return self._docs.pop(doc_id, None) is not None

    def count(self) -> int:
        return len(self._docs)

    def search(self, query: str) -> list[Document]:
        """Search documents by keyword in title or content."""
        if not query:
            return []
        query_lower = query.lower()
        return [
            doc for doc in self._docs.values()
            if query_lower in doc.title.lower() or query_lower in doc.content.lower()
        ]

    def list_all(self) -> list[Document]:
        return list(self._docs.values())

    def bulk_add(self, docs: list[Document]) -> int:
        """Add multiple documents. Returns count of successfully added."""
        added = 0
        for doc in docs:
            try:
                self.add(doc)
                added += 1
            except (ValueError, KeyError):
                continue
        return added


def normalize_text(text: str) -> str:
    """Normalize whitespace and strip a text string."""
    if not isinstance(text, str):
        raise TypeError(f"Expected str, got {type(text).__name__}")
    return " ".join(text.split())


def compute_similarity(text_a: str, text_b: str) -> float:
    """Compute a simple Jaccard similarity between two texts."""
    if not text_a or not text_b:
        return 0.0
    words_a = set(text_a.lower().split())
    words_b = set(text_b.lower().split())
    intersection = words_a & words_b
    union = words_a | words_b
    return len(intersection) / len(union) if union else 0.0


def chunk_document(content: str, chunk_size: int = 500, overlap: int = 100) -> list[str]:
    """Split document content into overlapping chunks."""
    if chunk_size <= 0:
        raise ValueError("chunk_size must be positive")
    if overlap >= chunk_size:
        raise ValueError("overlap must be less than chunk_size")
    if not content:
        return []
    chunks = []
    start = 0
    while start < len(content):
        end = min(start + chunk_size, len(content))
        chunks.append(content[start:end])
        if end >= len(content):
            break
        start += chunk_size - overlap
    return chunks


def extract_keywords(text: str, top_n: int = 10) -> list[str]:
    """Extract top-N most frequent words (naive keyword extraction)."""
    if not text:
        return []
    stopwords = {"the", "a", "an", "is", "are", "was", "were", "in", "on", "at", "to", "for", "of", "and", "or", "but"}
    words = text.lower().split()
    words = [w.strip(".,!?;:\"'()[]{}") for w in words if w.strip(".,!?;:\"'()[]{}")]
    words = [w for w in words if w and w not in stopwords]
    freq: dict[str, int] = {}
    for w in words:
        freq[w] = freq.get(w, 0) + 1
    sorted_words = sorted(freq.items(), key=lambda x: x[1], reverse=True)
    return [w for w, _ in sorted_words[:top_n]]
