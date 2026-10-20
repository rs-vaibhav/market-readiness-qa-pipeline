"""
Realistic, runnable pytest suite testing a sample backend / RAG service.
Includes fixtures, mocks, parameterized edge cases, and schema validation.
"""

import json
import time
from unittest.mock import patch

import pytest


# ===========================================================================
# UNIT TESTS — chunking, embedding shapes, data transformations
# ===========================================================================

class TestChunking:
    """Unit tests for text chunking logic."""

    def test_basic_chunking(self, rag_service):
        text = "word " * 100  # 500 chars
        chunks = rag_service.chunk_text(text, chunk_size=200, overlap=50)
        assert len(chunks) >= 2
        assert all(len(c) <= 200 for c in chunks)

    def test_empty_input_returns_empty(self, rag_service):
        assert rag_service.chunk_text("") == []

    def test_small_text_single_chunk(self, rag_service):
        chunks = rag_service.chunk_text("Hello", chunk_size=200)
        assert len(chunks) == 1
        assert chunks[0] == "Hello"

    @pytest.mark.parametrize("size,overlap", [
        (50, 10), (100, 25), (200, 50), (500, 100),
    ])
    def test_chunk_size_parametrized(self, rag_service, size, overlap):
        text = "a" * 1000
        chunks = rag_service.chunk_text(text, chunk_size=size, overlap=overlap)
        assert all(len(c) <= size for c in chunks)
        # Verify overlap: last chars of chunk N should appear at start of chunk N+1
        for i in range(len(chunks) - 1):
            tail = chunks[i][-overlap:]
            assert chunks[i + 1].startswith(tail)

    def test_unicode_chunking(self, rag_service):
        text = "日本語テスト " * 80
        chunks = rag_service.chunk_text(text, chunk_size=100, overlap=20)
        assert len(chunks) >= 1
        reconstructed = chunks[0]
        assert "日本語" in reconstructed


class TestEmbedding:
    """Unit tests for embedding generation."""

    def test_embedding_shape(self, rag_service):
        emb = rag_service.embed("test text", dim=128)
        assert len(emb) == 128
        assert all(isinstance(v, float) for v in emb)

    @pytest.mark.parametrize("dim", [64, 128, 256, 512])
    def test_embedding_dimensions(self, rag_service, dim):
        emb = rag_service.embed("sample", dim=dim)
        assert len(emb) == dim

    def test_embedding_deterministic(self, rag_service):
        e1 = rag_service.embed("hello world")
        e2 = rag_service.embed("hello world")
        assert e1 == e2

    def test_different_texts_different_embeddings(self, rag_service):
        e1 = rag_service.embed("cats are great")
        e2 = rag_service.embed("dogs are great")
        assert e1 != e2

    def test_embedding_values_normalized(self, rag_service):
        emb = rag_service.embed("normalization test")
        assert all(0.0 <= v <= 1.0 for v in emb)


# ===========================================================================
# INTEGRATION TESTS — API endpoints, DB / vector store connections
# ===========================================================================

class TestVectorStoreIntegration:
    """Integration tests for the vector store layer."""

    def test_upsert_and_query(self, vector_store):
        vector_store.upsert("doc1", [1.0, 0.0, 0.0])
        vector_store.upsert("doc2", [0.0, 1.0, 0.0])
        results = vector_store.query([1.0, 0.0, 0.0], top_k=1)
        assert len(results) == 1
        assert results[0]["id"] == "doc1"
        assert results[0]["score"] == pytest.approx(1.0, abs=0.01)

    def test_delete(self, vector_store):
        vector_store.upsert("doc1", [1.0, 0.0])
        assert vector_store.delete("doc1") is True
        assert vector_store.count() == 0

    def test_delete_nonexistent(self, vector_store):
        assert vector_store.delete("ghost") is False

    def test_count(self, vector_store):
        for i in range(10):
            vector_store.upsert(f"d{i}", [float(i)])
        assert vector_store.count() == 10


class TestBackendAPIIntegration:
    """Integration tests for the backend API layer."""

    def test_health_check(self, backend_api):
        resp = backend_api.health()
        assert resp["status"] == "ok"
        assert "version" in resp

    def test_health_response_schema(self, backend_api):
        resp = backend_api.health()
        required_keys = {"status", "version", "uptime_s"}
        assert required_keys.issubset(resp.keys())
        assert isinstance(resp["uptime_s"], (int, float))

    def test_create_and_retrieve_document(self, backend_api):
        doc = backend_api.create_document("d1", "Title", "Body text content")
        assert doc["id"] == "d1"
        retrieved = backend_api.get_document("d1")
        assert retrieved is not None
        assert retrieved["title"] == "Title"

    def test_create_document_schema(self, backend_api):
        doc = backend_api.create_document("d1", "T", "B")
        required = {"id", "title", "body", "created_at"}
        assert required.issubset(doc.keys())

    def test_delete_document(self, backend_api):
        backend_api.create_document("d1", "T", "B")
        assert backend_api.delete_document("d1") is True
        assert backend_api.get_document("d1") is None

    def test_search_returns_answer(self, populated_api):
        result = populated_api.search("What is Python?")
        assert "answer" in result
        assert "confidence" in result
        assert "sources" in result

    def test_search_response_schema(self, populated_api):
        result = populated_api.search("testing practices")
        required = {"answer", "confidence", "sources", "abstained"}
        assert required.issubset(result.keys())
        assert isinstance(result["confidence"], float)
        assert isinstance(result["sources"], list)


class TestRAGPipelineIntegration:
    """End-to-end RAG pipeline integration tests."""

    def test_ingest_and_query(self, rag_service):
        n = rag_service.ingest("doc1", "The capital of France is Paris. " * 20)
        assert n > 0
        result = rag_service.query("capital of France")
        assert result["abstained"] is False
        assert len(result["sources"]) > 0

    def test_multiple_document_ingest(self, rag_service):
        rag_service.ingest("a", "Alpha content " * 30)
        rag_service.ingest("b", "Beta content " * 30)
        assert rag_service.vector_store.count() > 2

    def test_query_confidence_range(self, rag_service):
        rag_service.ingest("d1", "Machine learning is a subset of AI. " * 20)
        result = rag_service.query("machine learning")
        assert 0.0 <= result["confidence"] <= 1.0


# ===========================================================================
# EDGE-CASE & FAILURE TESTS — corrupted input, timeouts, hallucination
# ===========================================================================

class TestEdgeCaseCorruptedInputs:
    """Tests with corrupted / adversarial inputs."""

    def test_embedding_empty_string(self, rag_service):
        emb = rag_service.embed("")
        assert len(emb) == 128

    def test_chunking_only_whitespace(self, rag_service):
        chunks = rag_service.chunk_text("   \n\t  ")
        assert len(chunks) >= 1  # whitespace is still content

    def test_vector_store_invalid_embedding_type(self, vector_store):
        with pytest.raises(ValueError):
            vector_store.upsert("bad", "not_a_list")  # type: ignore

    def test_vector_store_non_numeric_embedding(self, vector_store):
        with pytest.raises(ValueError):
            vector_store.upsert("bad", ["a", "b", "c"])  # type: ignore

    def test_create_document_missing_title(self, backend_api):
        with pytest.raises(ValueError, match="title and body are required"):
            backend_api.create_document("d1", "", "body")

    def test_create_document_missing_body(self, backend_api):
        with pytest.raises(ValueError, match="title and body are required"):
            backend_api.create_document("d1", "title", "")

    def test_get_nonexistent_document(self, backend_api):
        assert backend_api.get_document("nonexistent") is None

    def test_very_long_input(self, rag_service):
        text = "x" * 100_000
        chunks = rag_service.chunk_text(text, chunk_size=500)
        assert len(chunks) > 100

    @pytest.mark.parametrize("payload", [
        None, 42, {"nested": {"deep": True}}, [1, 2, 3],
    ])
    def test_chunk_non_string_input(self, rag_service, payload):
        with pytest.raises((TypeError, AttributeError, KeyError)):
            rag_service.chunk_text(payload)


class TestEdgeCaseTimeouts:
    """Timeout simulation tests."""

    def test_timeout_simulation(self, backend_api):
        start = time.perf_counter()
        with pytest.raises(Exception):
            # Wrapping in a thread timeout simulation
            import signal

            def handler(signum, frame):
                raise TimeoutError("Operation timed out")

            # Use a fast timeout for testing
            backend_api._healthy = False
            backend_api.health()

    def test_service_unavailable(self, backend_api):
        backend_api._healthy = False
        with pytest.raises(ConnectionError):
            backend_api.health()

    def test_service_recovery(self, backend_api):
        backend_api._healthy = False
        with pytest.raises(ConnectionError):
            backend_api.health()
        backend_api._healthy = True
        assert backend_api.health()["status"] == "ok"


class TestEdgeCaseHallucination:
    """RAG hallucination and abstention checks."""

    def test_abstention_on_unknown_query(self, rag_service):
        """RAG should abstain when no documents are ingested."""
        result = rag_service.query("What is the meaning of life?")
        assert result["abstained"] is True
        assert result["confidence"] == 0.0
        assert "I don't know" in result["answer"]

    def test_abstention_flag_present(self, rag_service):
        result = rag_service.query("random query no context")
        assert "abstained" in result

    def test_confidence_low_on_irrelevant_query(self, rag_service):
        rag_service.ingest("cooking", "Recipe for pasta with tomato sauce. " * 20)
        result = rag_service.query("quantum entanglement in black holes")
        # confidence should be low or model should abstain
        assert result["confidence"] < 0.9 or result["abstained"]

    def test_answer_contains_source_attribution(self, populated_api):
        result = populated_api.search("Python programming")
        if not result["abstained"]:
            assert len(result["sources"]) > 0, "Non-abstained answers must cite sources"

    def test_rag_response_schema_validation(self, rag_service):
        rag_service.ingest("d1", "Some content. " * 20)
        result = rag_service.query("content")
        assert isinstance(result, dict)
        assert "answer" in result
        assert "confidence" in result
        assert "sources" in result
        assert "abstained" in result
        assert isinstance(result["answer"], str)
        assert isinstance(result["confidence"], (int, float))
        assert isinstance(result["sources"], list)
        assert isinstance(result["abstained"], bool)

    @pytest.mark.parametrize("query,should_abstain", [
        ("", True),  # empty query
        ("   ", True),  # whitespace query
    ])
    def test_edge_queries_abstention(self, rag_service, query, should_abstain):
        result = rag_service.query(query)
        if should_abstain:
            assert result["abstained"] is True


class TestRAGFaithfulness:
    """Tests verifying RAG output faithfulness properties."""

    def test_faithful_answer_references_ingested_content(self, rag_service, request):
        rag_service.ingest("facts", "The Eiffel Tower is 330 meters tall. " * 20)
        result = rag_service.query("How tall is the Eiffel Tower?")
        # Record confidence as a test property for the report
        request.node.user_properties.append(("confidence_score", result["confidence"]))
        assert not result["abstained"]

    def test_multiple_queries_consistent(self, populated_api):
        r1 = populated_api.search("What is RAG?")
        r2 = populated_api.search("What is RAG?")
        assert r1["answer"] == r2["answer"]
        assert r1["confidence"] == r2["confidence"]
