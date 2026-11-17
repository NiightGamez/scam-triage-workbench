"""In-memory thread-safe rate limiter for API requests."""

from __future__ import annotations

from collections import deque
import os
import threading
import time
from typing import Dict, Tuple

DEFAULT_LIMIT = int(os.getenv("RATE_LIMIT_PER_MINUTE", "10"))
WINDOW_SECONDS = 60.0


class InMemoryRateLimiter:
    """Sliding-window rate limiter per client identifier."""

    def __init__(self, limit: int = DEFAULT_LIMIT, window_seconds: float = WINDOW_SECONDS):
        self.limit = limit
        self.window_seconds = window_seconds
        self._clients: Dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def is_rate_limited(self, client_id: str) -> Tuple[bool, int]:
        """Check if client has exceeded limit.
        
        Returns:
            (is_limited, retry_after_seconds)
        """
        now = time.time()
        cutoff = now - self.window_seconds

        with self._lock:
            if client_id not in self._clients:
                self._clients[client_id] = deque()

            timestamps = self._clients[client_id]

            # Prune timestamps outside the rolling window
            while timestamps and timestamps[0] <= cutoff:
                timestamps.popleft()

            if len(timestamps) >= self.limit:
                # Calculate remaining seconds until oldest request expires
                oldest = timestamps[0]
                retry_after = max(1, int(oldest + self.window_seconds - now))
                return True, retry_after

            # Record this request timestamp
            timestamps.append(now)
            return False, 0

    def reset(self) -> None:
        """Clear all rate limit records."""
        with self._lock:
            self._clients.clear()


# Global singleton instance
rate_limiter = InMemoryRateLimiter()
