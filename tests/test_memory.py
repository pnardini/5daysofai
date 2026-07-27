"""
Unit tests for Async Vector Store Memory module.
"""

import pytest
from src.memory import AsyncVectorStore, MemoryDocument


@pytest.mark.asyncio
async def test_async_vector_store_add_and_search(tmp_path):
    store = AsyncVectorStore(
        collection_name="test_collection",
        persist_directory=str(tmp_path / "vector_db")
    )

    doc = MemoryDocument(
        content="Acme Corp passed SOC2 Type II audit with high compliance score.",
        vendor_id="acme_corp",
        category="audit_history"
    )

    doc_id = await store.add_document(doc)
    assert doc_id is not None

    results = await store.search(query="Acme Corp SOC2 audit", limit=3)
    assert len(results) >= 1
    assert "Acme Corp" in results[0].document.content
    assert results[0].score >= 0.0
