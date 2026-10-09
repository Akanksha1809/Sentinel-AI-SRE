"""Bounded, self-expiring fault injection.

Safety properties, which are covered by tests:
- Memory growth stops at `target_rss_mb`. That value is capped by the configured
  maximum, and the maximum sits below the container memory limit, so the cgroup
  is the hard backstop and the host is never at risk.
- Every fault has a duration that is capped by `max_duration_s` and expires on
  its own.
- CPU burn uses a single thread. The container's CPU quota bounds it further.
"""

from __future__ import annotations

import asyncio
import gc
import os
import resource
import sys
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from pydantic import BaseModel, Field

MB = 1024 * 1024
_TICK_S = 0.25


def read_rss_bytes() -> int:
    """Resident set size: /proc on Linux, getrusage fallback for macOS dev/tests."""
    try:
        with open("/proc/self/statm", encoding="ascii") as fh:
            return int(fh.read().split()[1]) * os.sysconf("SC_PAGE_SIZE")
    except OSError:
        peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        return peak if sys.platform == "darwin" else peak * 1024


class MemoryFault(BaseModel):
    rate_mb_s: float = Field(default=2.0, gt=0, le=16)
    target_rss_mb: int = Field(default=220, ge=16)
    duration_s: int = Field(default=600, ge=1)


class LatencyFault(BaseModel):
    delay_ms: int = Field(default=500, ge=0, le=2000)
    duration_s: int = Field(default=300, ge=1)


class CpuFault(BaseModel):
    duration_s: int = Field(default=60, ge=1, le=120)


class ChaosLimitError(ValueError):
    """Requested fault exceeds configured safety limits."""


@dataclass
class _MemoryState:
    target_bytes: int
    rate_bytes_s: float
    expires_at: float
    chunks: list[bytearray] = field(default_factory=list)

    @property
    def allocated(self) -> int:
        return sum(len(c) for c in self.chunks)


class ChaosEngine:
    def __init__(
        self,
        max_memory_mb: int,
        max_duration_s: int,
        clock: Callable[[], float] = time.monotonic,
        rss_reader: Callable[[], int] = read_rss_bytes,
    ) -> None:
        self._max_memory_bytes = max_memory_mb * MB
        self._max_duration_s = max_duration_s
        self._clock = clock
        self._rss = rss_reader
        self._memory: _MemoryState | None = None
        self._memory_task: asyncio.Task[None] | None = None
        self._latency_s = 0.0
        self._latency_expires_at = 0.0
        self._cpu_stop = threading.Event()
        self._cpu_thread: threading.Thread | None = None
        self._cpu_expires_at = 0.0

    # ---- validation -------------------------------------------------------
    def _bounded_duration(self, duration_s: int) -> int:
        if duration_s > self._max_duration_s:
            raise ChaosLimitError(f"duration_s {duration_s} exceeds max {self._max_duration_s}")
        return duration_s

    # ---- memory -----------------------------------------------------------
    async def start_memory(self, fault: MemoryFault) -> None:
        target = fault.target_rss_mb * MB
        if target > self._max_memory_bytes:
            raise ChaosLimitError(
                f"target_rss_mb {fault.target_rss_mb} exceeds max {self._max_memory_bytes // MB}"
            )
        duration = self._bounded_duration(fault.duration_s)
        self.stop_memory()
        self._memory = _MemoryState(
            target_bytes=target,
            rate_bytes_s=fault.rate_mb_s * MB,
            expires_at=self._clock() + duration,
        )
        self._memory_task = asyncio.create_task(self._memory_loop(), name="chaos-memory")

    def memory_step(self) -> bool:
        """One allocation tick. Returns False once expired (memory is then released)."""
        state = self._memory
        if state is None:
            return False
        if self._clock() >= state.expires_at:
            self.stop_memory()
            return False
        headroom = state.target_bytes - self._rss()
        chunk = int(min(state.rate_bytes_s * _TICK_S, headroom))
        if chunk > 0:
            # Fill with a non-zero byte so the pages are actually resident.
            state.chunks.append(bytearray(b"\x5a") * chunk)
        return True

    async def _memory_loop(self) -> None:
        while self.memory_step():  # noqa: ASYNC110 (fixed-rate ticker, not a condition wait)
            await asyncio.sleep(_TICK_S)

    def stop_memory(self) -> None:
        if self._memory_task is not None and not self._memory_task.done():
            self._memory_task.cancel()
        self._memory_task = None
        if self._memory is not None:
            self._memory.chunks.clear()
            self._memory = None
            gc.collect()

    # ---- latency ----------------------------------------------------------
    def start_latency(self, fault: LatencyFault) -> None:
        duration = self._bounded_duration(fault.duration_s)
        self._latency_s = fault.delay_ms / 1000
        self._latency_expires_at = self._clock() + duration

    def injected_latency_s(self) -> float:
        if self._latency_s and self._clock() < self._latency_expires_at:
            return self._latency_s
        self._latency_s = 0.0
        return 0.0

    # ---- cpu --------------------------------------------------------------
    def start_cpu(self, fault: CpuFault) -> None:
        duration = self._bounded_duration(fault.duration_s)
        self.stop_cpu()
        self._cpu_stop = threading.Event()
        deadline = time.monotonic() + duration
        self._cpu_expires_at = self._clock() + duration

        def burn(stop: threading.Event) -> None:
            x = 0
            while not stop.is_set() and time.monotonic() < deadline:
                x = (x * 31 + 7) % 1_000_003

        self._cpu_thread = threading.Thread(
            target=burn, args=(self._cpu_stop,), name="chaos-cpu", daemon=True
        )
        self._cpu_thread.start()

    def stop_cpu(self) -> None:
        self._cpu_stop.set()
        if self._cpu_thread is not None:
            self._cpu_thread.join(timeout=2)
        self._cpu_thread = None

    # ---- aggregate --------------------------------------------------------
    def clear(self) -> None:
        self.stop_memory()
        self.stop_cpu()
        self._latency_s = 0.0

    def memory_allocated_bytes(self) -> int:
        return self._memory.allocated if self._memory else 0

    def state(self) -> dict[str, Any]:
        cpu_active = self._cpu_thread is not None and self._cpu_thread.is_alive()
        return {
            "memory": {
                "active": self._memory is not None,
                "allocated_bytes": self.memory_allocated_bytes(),
                "target_bytes": self._memory.target_bytes if self._memory else 0,
            },
            "latency": {"active": self.injected_latency_s() > 0, "delay_s": self._latency_s},
            "cpu": {"active": cpu_active},
            "limits": {
                "max_memory_mb": self._max_memory_bytes // MB,
                "max_duration_s": self._max_duration_s,
            },
        }
