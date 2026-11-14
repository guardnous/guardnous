"""Integrity gate for external scanner binaries.

Every external scanner (trivy, checkov, semgrep, gitleaks, tfsec) is a program
GuardNous executes with access to customer source code. Before each execution
the executable that is about to run is checked against a pinned SHA-256:

* hash matches the pin         -> run
* hash differs from the pin    -> the plugin is blocked until an administrator
                                  approves the new binary
* no pin yet                   -> its hash is pinned (trust on first use)

Pins come from two places. The container image records a read-only baseline at
build time (``python -m app.services.plugins.integrity baseline <file>``, see
the Dockerfile), so every container of that image trusts exactly the scanners
it was built with. Installations without a baseline pin on first use, and
administrator approvals are stored in the plugin cache directory. An approval
overrides the baseline. In a multi-container deployment an approval only
reaches containers that share that directory; the intended fix for a changed
binary there is to rebuild the image.

The executable is the file ``shutil.which`` resolves, the same lookup the
adapters use. Hashing is cached on the file's (inode, size, mtime), so a scan
costs one ``stat`` per plugin unless the file changed.

Limit: for scanners installed with pip (semgrep, checkov) the executable is a
small launcher script; this pins the launcher, not the Python packages behind
it.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import shutil
import threading
import time
from dataclasses import asdict, dataclass
from pathlib import Path

logger = logging.getLogger(__name__)

KNOWN_BINARIES = ("trivy", "checkov", "semgrep", "gitleaks", "tfsec")
BASELINE_FILE = Path(os.environ.get("GUARDNOUS_INTEGRITY_BASELINE", "/app/integrity-baseline.json"))

VERIFIED = "verified"
PINNED = "pinned"          # first sighting, pin recorded now
MISMATCH = "mismatch"
NOT_INSTALLED = "not_installed"


class PluginIntegrityError(RuntimeError):
    """A scanner binary does not match its pinned hash and must not be run."""


@dataclass
class IntegrityStatus:
    binary: str
    status: str
    path: str | None = None
    sha256: str | None = None
    expected_sha256: str | None = None
    pinned_at: float | None = None
    approved_by: str | None = None

    @property
    def ok(self) -> bool:
        return self.status in (VERIFIED, PINNED)

    def to_dict(self) -> dict:
        return asdict(self)


class BinaryIntegrity:
    def __init__(self, state_dir: Path | None = None, baseline_file: Path | None = None) -> None:
        if state_dir is None:
            from app.services.plugins.version_manager import CACHE_DIR
            state_dir = CACHE_DIR
        self._state_file = Path(state_dir) / "integrity_pins.json"
        self._baseline_file = Path(baseline_file) if baseline_file else BASELINE_FILE
        self._lock = threading.Lock()
        self._pins: dict[str, dict] = {}
        self._local: dict[str, dict] = {}
        self._pins_mtime: tuple | None = None
        self._hash_cache: dict[str, tuple[tuple, str]] = {}  # path -> (stat signature, sha256)

    # ── pin storage (shared between API and worker processes via the file) ──

    @staticmethod
    def _read(path: Path) -> dict:
        try:
            return json.loads(path.read_text())
        except FileNotFoundError:
            return {}
        except (OSError, json.JSONDecodeError) as exc:
            # An unreadable pin file must not silently re-pin everything.
            raise PluginIntegrityError(f"Integrity pin file {path} is unreadable: {exc}") from exc

    def _load(self) -> None:
        try:
            mtime = self._state_file.stat().st_mtime
        except FileNotFoundError:
            mtime = None
        if self._pins_mtime is not None and mtime == self._pins_mtime[0]:
            return
        self._local = self._read(self._state_file)  # first-use pins and approvals
        self._pins = {**self._read(self._baseline_file), **self._local}
        self._pins_mtime = (mtime,)

    def _save(self, binary: str, pin: dict) -> None:
        self._local[binary] = pin
        self._pins[binary] = pin
        self._state_file.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._state_file.with_suffix(".tmp")
        tmp.write_text(json.dumps(self._local, indent=2))
        os.replace(tmp, self._state_file)
        self._pins_mtime = (self._state_file.stat().st_mtime,)

    # ── hashing ──

    def _sha256(self, path: str) -> str:
        st = os.stat(path)
        signature = (st.st_ino, st.st_size, st.st_mtime_ns)
        cached = self._hash_cache.get(path)
        if cached and cached[0] == signature:
            return cached[1]
        digest = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                digest.update(chunk)
        value = digest.hexdigest()
        self._hash_cache[path] = (signature, value)
        return value

    # ── public API ──

    def check(self, binary: str, pin_if_new: bool = True) -> IntegrityStatus:
        """Compare the executable for *binary* with its pin."""
        located = shutil.which(binary)
        if not located:
            return IntegrityStatus(binary=binary, status=NOT_INSTALLED)
        path = os.path.realpath(located)
        with self._lock:
            self._load()
            actual = self._sha256(path)
            pin = self._pins.get(binary)
            if pin is None:
                if not pin_if_new:
                    return IntegrityStatus(binary=binary, status=PINNED, path=path, sha256=actual)
                pin = {"path": path, "sha256": actual, "pinned_at": time.time(), "approved_by": "first-use"}
                try:
                    self._save(binary, pin)
                except OSError as exc:
                    # Still pinned for the life of this process
                    self._pins[binary] = pin
                    logger.warning("Could not persist integrity pin for %s: %s", binary, exc)
                logger.info("Pinned scanner binary %s (%s) sha256=%s", binary, path, actual)
                return IntegrityStatus(binary=binary, status=PINNED, path=path, sha256=actual,
                                       expected_sha256=actual, pinned_at=pin["pinned_at"],
                                       approved_by=pin["approved_by"])
            status = VERIFIED if pin["sha256"] == actual else MISMATCH
            return IntegrityStatus(binary=binary, status=status, path=path, sha256=actual,
                                   expected_sha256=pin["sha256"], pinned_at=pin.get("pinned_at"),
                                   approved_by=pin.get("approved_by"))

    def approve(self, binary: str, approved_by: str) -> IntegrityStatus:
        """Pin the binary as it is now. Use after a deliberate scanner upgrade."""
        located = shutil.which(binary)
        if not located:
            raise FileNotFoundError(f"{binary} is not installed")
        path = os.path.realpath(located)
        with self._lock:
            self._load()
            actual = self._sha256(path)
            self._save(binary, {"path": path, "sha256": actual, "pinned_at": time.time(),
                                "approved_by": approved_by})
        logger.warning("Scanner binary %s re-pinned by %s sha256=%s", binary, approved_by, actual)
        return self.check(binary)

    def ensure(self, binary: str) -> IntegrityStatus:
        """Gate called immediately before a scanner is executed."""
        from app.core.config import settings

        mode = (settings.PLUGIN_INTEGRITY_MODE or "enforce").lower()
        if mode == "off":
            return IntegrityStatus(binary=binary, status=VERIFIED)
        status = self.check(binary)
        if status.status == MISMATCH:
            message = (
                f"Integrity check failed for scanner '{binary}': {status.path} has SHA-256 "
                f"{status.sha256}, expected {status.expected_sha256}. The scanner was not run. "
                "If it was upgraded deliberately, approve the new binary under Plugins."
            )
            if mode == "warn":
                logger.error("%s (PLUGIN_INTEGRITY_MODE=warn: running anyway)", message)
            else:
                raise PluginIntegrityError(message)
        return status


_instance: BinaryIntegrity | None = None


def get_integrity() -> BinaryIntegrity:
    global _instance
    if _instance is None:
        _instance = BinaryIntegrity()
    return _instance


def ensure_adapter_integrity(adapter) -> IntegrityStatus | None:
    """Verify the binary behind a plugin adapter. No-op for native (in-process) plugins."""
    binary = getattr(adapter, "_binary", None)
    if not binary or not adapter.metadata().requires_binary:
        return None
    return get_integrity().ensure(binary)


def write_baseline(path: Path) -> dict:
    """Record the hash of every installed scanner. Run once when the image is built."""
    pins = {}
    for binary in KNOWN_BINARIES:
        located = shutil.which(binary)
        if not located:
            continue
        real = os.path.realpath(located)
        digest = hashlib.sha256()
        with open(real, "rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                digest.update(chunk)
        pins[binary] = {"path": real, "sha256": digest.hexdigest(), "pinned_at": time.time(),
                        "approved_by": "image-build"}
    Path(path).write_text(json.dumps(pins, indent=2))
    return pins


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 3 or sys.argv[1] != "baseline":
        sys.exit("usage: python -m app.services.plugins.integrity baseline <output-file>")
    for name, pin in write_baseline(Path(sys.argv[2])).items():
        print(f"pinned {name} {pin['sha256']} {pin['path']}")
