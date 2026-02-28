import os
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional


RESTART_DELAY_SECONDS = int(os.getenv("SUPERVISOR_RESTART_DELAY", "5"))
CHECK_INTERVAL_SECONDS = int(os.getenv("SUPERVISOR_CHECK_INTERVAL", "2"))
PATTERN_UPDATER_INTERVAL = int(os.getenv("PATTERN_UPDATER_INTERVAL", "600"))
LOG_DIR = Path(os.getenv("SUPERVISOR_LOG_DIR", "logs"))


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _print(msg: str) -> None:
    print(f"[{_now()}] {msg}", flush=True)


class ManagedProcess:
    def __init__(self, name: str, command: List[str], log_path: Path):
        self.name = name
        self.command = command
        self.log_path = log_path
        self.proc: Optional[subprocess.Popen] = None
        self.log_file = None
        self.last_start_ts = 0.0

    def start(self) -> None:
        self.log_file = open(self.log_path, "a", encoding="utf-8")
        self.log_file.write(f"\n[{_now()}] Starting {self.name}: {' '.join(self.command)}\n")
        self.log_file.flush()
        self.proc = subprocess.Popen(
            self.command,
            stdout=self.log_file,
            stderr=subprocess.STDOUT,
            text=True,
        )
        self.last_start_ts = time.time()
        _print(f"Started {self.name} (pid={self.proc.pid})")

    def stop(self) -> None:
        if self.proc is not None and self.proc.poll() is None:
            _print(f"Stopping {self.name} (pid={self.proc.pid})")
            self.proc.terminate()
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                _print(f"Force killing {self.name} (pid={self.proc.pid})")
                self.proc.kill()
        self.proc = None
        if self.log_file is not None:
            self.log_file.write(f"[{_now()}] Stopped {self.name}\n")
            self.log_file.flush()
            self.log_file.close()
            self.log_file = None

    def check_and_restart(self) -> None:
        if self.proc is None:
            self.start()
            return
        code = self.proc.poll()
        if code is None:
            return
        _print(f"{self.name} exited with code {code}")
        if self.log_file is not None:
            self.log_file.write(f"[{_now()}] Exit code: {code}\n")
            self.log_file.flush()
            self.log_file.close()
            self.log_file = None
        self.proc = None
        time.sleep(RESTART_DELAY_SECONDS)
        self.start()


def _build_processes() -> Dict[str, ManagedProcess]:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    py = sys.executable
    return {
        "monitor": ManagedProcess(
            "monitor",
            [py, "monitor.py"],
            LOG_DIR / "monitor.log",
        ),
        "pattern_updater": ManagedProcess(
            "pattern_updater",
            [py, "pattern_updater.py", "--interval", str(PATTERN_UPDATER_INTERVAL)],
            LOG_DIR / "pattern_updater.log",
        ),
    }


def main() -> None:
    processes = _build_processes()
    running = True

    def _handle_signal(signum, _frame):
        nonlocal running
        _print(f"Received signal {signum}. Shutting down.")
        running = False

    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    _print("Supervisor started.")
    for proc in processes.values():
        proc.start()

    try:
        while running:
            for proc in processes.values():
                proc.check_and_restart()
            time.sleep(CHECK_INTERVAL_SECONDS)
    finally:
        for proc in processes.values():
            proc.stop()
        _print("Supervisor stopped.")


if __name__ == "__main__":
    main()

