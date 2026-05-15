"""Rate limiter for API requests."""

import time
from collections import deque


class RateLimiter:
    """
    Simple rate limiter using a sliding window.

    Tracks the timestamps of recent requests. If we're about to exceed
    the limit, wait until the oldest request falls out of the window.
    """

    def __init__(self, max_requests: int, window_seconds: int):
        """
        Args:
            max_requests: Maximum requests allowed in the window
            window_seconds: Duration of the window in seconds
        """
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests = deque()

    def wait_if_needed(self):
        """
        Block until it's safe to make another request.
        Records the new request timestamp.
        """
        now = time.time()

        while self.requests and now - self.requests[0] > self.window_seconds:
            self.requests.popleft()

        if len(self.requests) >= self.max_requests:
            oldest = self.requests[0]
            wait_time = self.window_seconds - (now - oldest) + 1

            if wait_time > 0:
                print(f"  ⏳ Rate limit approaching, waiting {wait_time:.0f}s...")
                time.sleep(wait_time)

        self.requests.append(time.time())
