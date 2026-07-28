"""
OpenTelemetry Tracing Setup for VendorGuard ADK.
Provides structured span instrumentation and in-memory trace collection for real-time observability.
"""

import functools
import json
import time
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor, ConsoleSpanExporter
from opentelemetry.sdk.resources import Resource
from src.pii_sanitizer import pii_sanitizer
from src.logger import logger

# Initialize OpenTelemetry Tracer
resource = Resource.create(attributes={"service.name": "vendorguard-adk"})
provider = TracerProvider(resource=resource)
provider.add_span_processor(SimpleSpanProcessor(ConsoleSpanExporter()))
trace.set_tracer_provider(provider)
tracer = trace.get_tracer("vendorguard.tracer")


class TraceCollector:
    """In-memory trace collector to power the UI Telemetry Dashboard."""

    def __init__(self):
        """Initializes TraceCollector with an empty internal trace buffer."""
        self._traces: List[Dict[str, Any]] = []

    def record_span(
        self,
        name: str,
        kind: str,
        duration_ms: float,
        attributes: Dict[str, Any],
        status: str = "OK",
        error: Optional[str] = None,
    ):
        """Records an OpenTelemetry span execution entry in the trace log.

        Args:
            name (str): Span or operation name (e.g. 'vector_store.search').
            kind (str): Span categorization kind (e.g. 'memory', 'tool', 'routing').
            duration_ms (float): Execution duration in milliseconds.
            attributes (Dict[str, Any]): Dictionary of attributes associated with the span.
            status (str, optional): Span execution status ('OK' or 'ERROR'). Defaults to "OK".
            error (Optional[str], optional): Error message string if execution failed. Defaults to None.
        """
        span_data = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "name": name,
            "kind": kind,
            "duration_ms": round(duration_ms, 2),
            "attributes": pii_sanitizer.sanitize_data(attributes),
            "status": status,
            "error": error,
        }
        self._traces.append(span_data)
        # Keep last 100 traces
        if len(self._traces) > 100:
            self._traces.pop(0)

        logger.info(
            f"OTel Span Completed: {name}",
            extra={"payload": span_data}
        )

    def get_traces(self) -> List[Dict[str, Any]]:
        """Returns recorded trace spans in reverse chronological order.

        Returns:
            List[Dict[str, Any]]: List of recorded span dictionaries.
        """
        return list(reversed(self._traces))

    def clear(self):
        """Clears all stored traces in memory."""
        self._traces.clear()


trace_collector = TraceCollector()


def trace_span(name: str, kind: str = "internal"):
    """Decorator to instrument async or sync functions with OpenTelemetry spans.

    Args:
        name (str): OpenTelemetry span name.
        kind (str, optional): Span kind categorization. Defaults to "internal".

    Returns:
        Callable: Wrapped function with telemetry tracing logic.
    """
    def decorator(func: Callable):
        if asyncio_iscoroutinefunction(func):
            @functools.wraps(func)
            async def async_wrapper(*args, **kwargs):
                start_time = time.perf_counter()
                status = "OK"
                error_msg = None
                with tracer.start_as_current_span(name) as span:
                    try:
                        result = await func(*args, **kwargs)
                        span.set_status(trace.StatusCode.OK)
                        return result
                    except Exception as e:
                        status = "ERROR"
                        error_msg = str(e)
                        span.set_status(trace.StatusCode.ERROR, description=error_msg)
                        span.record_exception(e)
                        raise e
                    finally:
                        duration_ms = (time.perf_counter() - start_time) * 1000
                        trace_collector.record_span(
                            name=name,
                            kind=kind,
                            duration_ms=duration_ms,
                            attributes={"function": func.__name__},
                            status=status,
                            error=error_msg,
                        )
            return async_wrapper
        else:
            @functools.wraps(func)
            def sync_wrapper(*args, **kwargs):
                start_time = time.perf_counter()
                status = "OK"
                error_msg = None
                with tracer.start_as_current_span(name) as span:
                    try:
                        result = func(*args, **kwargs)
                        span.set_status(trace.StatusCode.OK)
                        return result
                    except Exception as e:
                        status = "ERROR"
                        error_msg = str(e)
                        span.set_status(trace.StatusCode.ERROR, description=error_msg)
                        span.record_exception(e)
                        raise e
                    finally:
                        duration_ms = (time.perf_counter() - start_time) * 1000
                        trace_collector.record_span(
                            name=name,
                            kind=kind,
                            duration_ms=duration_ms,
                            attributes={"function": func.__name__},
                            status=status,
                            error=error_msg,
                        )
            return sync_wrapper
    return decorator


def asyncio_iscoroutinefunction(func: Callable) -> bool:
    import asyncio
    return asyncio.iscoroutinefunction(func)
