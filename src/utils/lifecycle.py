"""Lifecycle helpers to support graceful shutdown."""

from __future__ import annotations

import atexit
import logging
import signal
import threading
from types import FrameType
from typing import Callable, Iterable, List, Tuple

from flask import Flask

ShutdownCallback = Callable[[], None]


class _ShutdownRegistry:
    """Registry of shutdown callbacks executed once."""

    def __init__(self) -> None:
        self._callbacks: List[Tuple[str, ShutdownCallback]] = []
        self._lock = threading.Lock()
        self._engaged = False

    def add(self, name: str, callback: ShutdownCallback) -> None:
        with self._lock:
            self._callbacks.append((name, callback))

    def fire(self, *, reason: str | None = None, logger: logging.Logger | None = None) -> None:
        with self._lock:
            if self._engaged:
                return
            self._engaged = True
            callbacks = list(self._callbacks)
        for name, callback in callbacks:
            try:
                callback()
            except Exception:  # pragma: no cover - defensive logging
                if logger is not None:
                    logger.exception("Shutdown callback %s failed", name)


_registry = _ShutdownRegistry()


def register_shutdown_task(name: str, callback: ShutdownCallback) -> None:
    """Register a callback executed when the process shuts down."""

    _registry.add(name, callback)


def _signal_name(signum: int) -> str:
    try:
        return signal.Signals(signum).name
    except Exception:  # pragma: no cover - fallback for unsupported values
        return str(signum)


def install_signal_handlers(app: Flask) -> None:
    """Install SIGTERM/SIGINT handlers that trigger graceful shutdown."""

    def _handler(signum: int, frame: FrameType | None) -> None:  # pragma: no cover - signal path
        signame = _signal_name(signum)
        app.logger.info("Received shutdown signal", extra={"signal": signame})
        _registry.fire(reason=signame, logger=app.logger)
        previous = previous_handlers.get(signum)
        if callable(previous):
            previous(signum, frame)

    previous_handlers: dict[int, signal.Handlers] = {}
    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            previous_handlers[sig] = signal.getsignal(sig)
            signal.signal(sig, _handler)
        except ValueError:  # pragma: no cover - not in main thread
            app.logger.debug(
                "Unable to install handler for %s; not running in main thread", _signal_name(sig)
            )

    atexit.register(lambda: _registry.fire(reason="atexit", logger=app.logger))


def iter_shutdown_callbacks() -> Iterable[Tuple[str, ShutdownCallback]]:
    """Return the registered shutdown callbacks (primarily for introspection/tests)."""

    return tuple(_registry._callbacks)
