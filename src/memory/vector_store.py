"""
Asynchronous Vector Store Memory Engine for VendorGuard ADK.
Provides async vector storage, similarity search, and PII-sanitized state persistence.
Uses a lightweight deterministic embedding function to avoid heavy model downloads and disk space errors.
"""

import asyncio
import os
import uuid
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
import chromadb
from chromadb.api.types import EmbeddingFunction, Documents, Embeddings
from src.pii_sanitizer import pii_sanitizer
from src.logger import logger
from src.telemetry import trace_span


class LightweightEmbeddingFunction(EmbeddingFunction):
    """Deterministic, lightweight embedding function without external disk model downloads."""

    def __init__(self):
        """Initializes LightweightEmbeddingFunction."""
        super().__init__()

    def name(self) -> str:
        """Returns the unique name identifier of the embedding function.

        Returns:
            str: Function name identifier string.
        """
        return "lightweight_embedding_function"

    def __call__(self, input: Documents) -> Embeddings:
        """Generates 64-dimensional normalized float vectors for input text documents.

        Args:
            input (Documents): List of document text strings to convert into embeddings.

        Returns:
            Embeddings: List of 64-dimensional float vector embeddings.
        """
        embeddings: List[List[float]] = []
        for text in input:
            vec = [0.0] * 64
            for i, char in enumerate(text[:256]):
                vec[i % 64] += ord(char) / 255.0
            norm = (sum(x * x for x in vec) ** 0.5) or 1.0
            embeddings.append([x / norm for x in vec])
        return embeddings


class MemoryDocument(BaseModel):
    """Schema for documents stored in vector memory."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    content: str
    metadata: Dict[str, Any] = Field(default_factory=dict)
    vendor_id: Optional[str] = None
    category: str = "general"


class SearchResult(BaseModel):
    """Schema for vector similarity search results."""
    document: MemoryDocument
    score: float
    distance: float


class AsyncVectorStore:
    """Asynchronous vector store wrapper around ChromaDB."""

    def __init__(self, collection_name: str = "vendorguard_memory", persist_directory: str = "./data/vector_db"):
        """Initializes the ChromaDB async vector store client and collection.

        Args:
            collection_name (str, optional): ChromaDB collection name. Defaults to "vendorguard_memory".
            persist_directory (str, optional): Disk directory path for persistent storage. Defaults to "./data/vector_db".
        """
        self.collection_name = collection_name
        self.persist_directory = persist_directory
        os.makedirs(self.persist_directory, exist_ok=True)
        
        self.embedding_fn = LightweightEmbeddingFunction()
        try:
            self.client = chromadb.PersistentClient(path=self.persist_directory)
        except Exception:
            logger.warning("PersistentClient failed, using EphemeralClient for in-memory vector store")
            self.client = chromadb.EphemeralClient()

        try:
            self.collection = self.client.get_or_create_collection(
                name=self.collection_name,
                embedding_function=self.embedding_fn,
                metadata={"description": "VendorGuard ADK Long-Term Vector Memory"}
            )
        except Exception:
            try:
                self.client.delete_collection(name=self.collection_name)
            except Exception:
                pass
            self.collection = self.client.get_or_create_collection(
                name=self.collection_name,
                embedding_function=self.embedding_fn,
                metadata={"description": "VendorGuard ADK Long-Term Vector Memory"}
            )
        logger.info(f"Initialized AsyncVectorStore at {self.persist_directory} with collection '{self.collection_name}'")

    @trace_span(name="vector_store.add_document", kind="memory")
    async def add_document(self, doc: MemoryDocument) -> str:
        """Asynchronously add a document to the vector store with PII sanitization.

        Args:
            doc (MemoryDocument): Memory document instance containing content, vendor_id, category, and metadata.

        Returns:
            str: Document unique ID string.
        """
        return await asyncio.to_thread(self._add_document_sync, doc)

    def _add_document_sync(self, doc: MemoryDocument) -> str:
        """Synchronous implementation to sanitize and persist a document in ChromaDB.

        Args:
            doc (MemoryDocument): Document to persist into collection.

        Returns:
            str: Document ID string.
        """
        clean_content = pii_sanitizer.sanitize_text(doc.content)
        clean_metadata = pii_sanitizer.sanitize_data(doc.metadata)
        clean_metadata["vendor_id"] = doc.vendor_id or "global"
        clean_metadata["category"] = doc.category

        self.collection.add(
            ids=[doc.id],
            documents=[clean_content],
            metadatas=[clean_metadata]
        )
        logger.info(f"Stored document in vector memory [id={doc.id}, category={doc.category}]")
        return doc.id

    @trace_span(name="vector_store.search", kind="memory")
    async def search(self, query: str, limit: int = 5, vendor_id: Optional[str] = None) -> List[SearchResult]:
        """Asynchronously perform vector similarity search over memory store entries.

        Args:
            query (str): Natural language search query string.
            limit (int, optional): Maximum number of top matching results to return. Defaults to 5.
            vendor_id (Optional[str], optional): Optional vendor ID string filter. Defaults to None.

        Returns:
            List[SearchResult]: List of SearchResult objects matching similarity criteria.
        """
        return await asyncio.to_thread(self._search_sync, query, limit, vendor_id)

    def _search_sync(self, query: str, limit: int, vendor_id: Optional[str]) -> List[SearchResult]:
        """Synchronous implementation for querying ChromaDB collection.

        Args:
            query (str): Search query string.
            limit (int): Max result count integer.
            vendor_id (Optional[str]): Vendor ID filter string.

        Returns:
            List[SearchResult]: List of matching SearchResult objects.
        """
        clean_query = pii_sanitizer.sanitize_text(query)
        where_clause = {"vendor_id": vendor_id} if vendor_id else None

        results = self.collection.query(
            query_texts=[clean_query],
            n_results=limit,
            where=where_clause
        )

        search_results: List[SearchResult] = []
        if results and results.get("ids") and results["ids"][0]:
            ids = results["ids"][0]
            docs = results["documents"][0]
            metadatas = results["metadatas"][0]
            distances = results["distances"][0] if results.get("distances") else [0.0] * len(ids)

            for doc_id, text, meta, dist in zip(ids, docs, metadatas, distances):
                similarity_score = max(0.0, round(1.0 - (dist / 2.0 if dist else 0.0), 4))
                
                doc = MemoryDocument(
                    id=doc_id,
                    content=text,
                    metadata=meta,
                    vendor_id=meta.get("vendor_id"),
                    category=meta.get("category", "general")
                )
                search_results.append(SearchResult(document=doc, score=similarity_score, distance=round(dist, 4)))

        return search_results

    @trace_span(name="vector_store.clear", kind="memory")
    async def clear(self):
        """Asynchronously clear all memory entries in the vector collection."""
        await asyncio.to_thread(self._clear_sync)

    def _clear_sync(self):
        """Synchronous implementation for clearing ChromaDB collection."""
        self.client.delete_collection(self.collection_name)
        self.collection = self.client.get_or_create_collection(
            name=self.collection_name,
            embedding_function=self.embedding_fn
        )
        logger.info("Cleared all vector store memories.")
