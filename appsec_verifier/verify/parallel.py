"""What only the main thread can do for a run that tests findings at the same time (VER-065).

The proof browser belongs to the thread that started it, and only the main thread can interrupt work at a
deadline (limits.execution_deadline). A worker thread therefore hands each browser call to `MainThread`, which
the runner serves on the main thread while the workers test: the call runs there under the deadline the worker
is bound by, and its result or exception goes back to the worker. The browser's page requests still go through
the guarded HTTP client, as in a run that tests one finding at a time.
"""

from __future__ import annotations

import queue
import threading
from concurrent.futures import Future

from ..limits import deadline_left, execution_deadline


class MainThread:
    def __init__(self):
        self._jobs: queue.SimpleQueue = queue.SimpleQueue()

    def call(self, operation):
        """Run `operation` on the main thread and return its result; its exception is raised here."""
        if threading.current_thread() is threading.main_thread():
            return operation()
        future: Future = Future()
        self._jobs.put((operation, deadline_left(), future))
        return future.result()

    def serve(self, done) -> None:
        """Run the workers' calls until `done()`. Ctrl-C during a call ends that call for its worker and is
        raised here as well, for the runner to cancel the run; the runner then serves on."""
        while not done():
            try:
                operation, seconds, future = self._jobs.get(timeout=0.1)
            except queue.Empty:
                continue
            try:
                if seconds is None:
                    result = operation()
                else:
                    with execution_deadline(seconds):
                        result = operation()
            except BaseException as exc:  # noqa: BLE001 - the worker that asked gets whatever ended its call
                future.set_exception(exc)
                if isinstance(exc, KeyboardInterrupt):
                    raise
            else:
                future.set_result(result)


class MainThreadBrowser:
    """The proof browser for worker threads: its calls run on the main thread, everything else is its own."""

    def __init__(self, browser, main: MainThread):
        self._browser, self._main = browser, main

    def __getattr__(self, name):
        return getattr(self._browser, name)

    def check(self, *args, **kwargs):
        return self._main.call(lambda: self._browser.check(*args, **kwargs))

    def render(self, *args, **kwargs):
        return self._main.call(lambda: self._browser.render(*args, **kwargs))

    def render_exchanges(self, *args, **kwargs):
        return self._main.call(lambda: self._browser.render_exchanges(*args, **kwargs))
