"""Optional startup diagnostics and best-effort bootloader splash control."""
import os
import time

_started = time.perf_counter()
_splash = None


def mark(stage, **details):
    """Write timing only when explicitly requested by the diagnostic runner."""
    path = os.environ.get("ORASENTRY_STARTUP_TRACE")
    if path:
        try:
            import json
            with open(path, "a", encoding="utf-8") as stream:
                stream.write(json.dumps({"stage": stage, "pid": os.getpid(),
                                         "timestamp_ms": time.time_ns() // 1000000,
                                         "elapsed_ms": round((time.perf_counter() - _started) * 1000, 2),
                                         **details}, ensure_ascii=False) + "\n")
        except OSError:
            pass  # Diagnostics must never prevent startup.


def connect_splash():
    global _splash
    if os.environ.get("_PYI_SPLASH_IPC", "0") != "0":
        try:
            import pyi_splash
            if pyi_splash.is_alive():
                _splash = pyi_splash
        except (ImportError, OSError, RuntimeError):
            pass


def update_splash(text):
    if _splash is not None:
        try:
            _splash.update_text(text)
        except (OSError, RuntimeError):
            pass


def close_splash():
    global _splash
    if _splash is not None:
        try:
            _splash.close()
        except (OSError, RuntimeError):
            pass
        finally:
            _splash = None
