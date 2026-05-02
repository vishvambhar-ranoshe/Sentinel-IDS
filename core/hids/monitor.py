# core/hids/monitor.py

import psutil
import os
import time
import threading
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from datetime import datetime

# ─── Known safe processes (whitelist) ────────────────────────────────────────

WHITELIST = {
    "kernel_task", "launchd", "python", "python3", "zsh", "bash",
    "Terminal", "Finder", "Safari", "Chrome", "Code", "nano",
    "sudo", "ssh", "git", "node", "npm", "conda", "anaconda",
    "mdworker_shared", "osanalyticshelper", "mdworker", "mds",
    "mds_stores", "cfprefsd", "distnoted", "trustd", "loginwindow",
    "WindowServer", "Dock", "SystemUIServer", "coreaudiod", "secd",
    "securityd", "coreduetd", "nsurlsessiond", "bird", "cloudd",
    "Google Chrome Helper (Renderer)", "Google Chrome Helper",
    "Google Chrome", "Google Chrome Helper (GPU)",
    "Brave Browser Helper (Renderer)", "Brave Browser Helper",
    "Brave Browser", "Brave Browser Helper (GPU)",
    "replayd", "aned", "online-auth-agent",
    "PerfPowerTelemetryClientRegistrationService",
    "APFSUserAgent", "AirPlayUIAgent", "UserEventAgent",
    "universalaccessd", "powerd", "thermalmonitord",
    "symptomsd", "syslogd", "logd", "notifyd"
}
# ─── Sensitive paths to watch ─────────────────────────────────────────────────
WATCH_PATHS = [
    "/etc",
    "/usr/local/bin",
    os.path.expanduser("~/.ssh"),
]
# ─── Alert callback ───────────────────────────────────────────────────────────
alert_callback = None

def set_alert_callback(fn):
    global alert_callback
    alert_callback = fn

def emit_alert(alert):
    if alert_callback:
        alert_callback(alert)
    else:
        print(f"[HIDS] [{alert['severity']}] [{alert['layer']}] {alert['reason']}")


# ─── Process Monitor ──────────────────────────────────────────────────────────
known_pids = set()

def monitor_processes():
    global known_pids
    known_pids = {p.pid for p in psutil.process_iter()}

    while True:
        try:
            current_pids = {p.pid for p in psutil.process_iter()}
            new_pids = current_pids - known_pids

            for pid in new_pids:
                try:
                    proc = psutil.Process(pid)
                    name = proc.name()
                    cmdline = " ".join(proc.cmdline())

                    if name not in WHITELIST:
                        emit_alert({
                            "layer":    "HIDS-PROCESS",
                            "severity": "MEDIUM",
                            "reason":   f"New unknown process: {name} | CMD: {cmdline[:80]}",
                            "timestamp": datetime.now().isoformat()
                        })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

            known_pids = current_pids
            time.sleep(2)

        except Exception as e:
            time.sleep(2)


# ─── File Monitor ─────────────────────────────────────────────────────────────
class SentinelFileHandler(FileSystemEventHandler):
    def on_created(self, event):
        if not event.is_directory:
            emit_alert({
                "layer":    "HIDS-FILE",
                "severity": "LOW",
                "reason":   f"New file created: {event.src_path}",
                "timestamp": datetime.now().isoformat()
            })

    def on_modified(self, event):
        if not event.is_directory:
            emit_alert({
                "layer":    "HIDS-FILE",
                "severity": "LOW",
                "reason":   f"File modified: {event.src_path}",
                "timestamp": datetime.now().isoformat()
            })

    def on_deleted(self, event):
        emit_alert({
            "layer":    "HIDS-FILE",
            "severity": "MEDIUM",
            "reason":   f"File deleted: {event.src_path}",
            "timestamp": datetime.now().isoformat()
        })

def monitor_files():
    observer = Observer()
    handler  = SentinelFileHandler()
    for path in WATCH_PATHS:
        if os.path.exists(path):
            observer.schedule(handler, path, recursive=True)
    observer.start()
    try:
        while True:
            time.sleep(1)
    except:
        observer.stop()
    observer.join()


# ─── Log Monitor ──────────────────────────────────────────────────────────────
LOG_FILE = "/var/log/system.log"

def monitor_logs():
    if not os.path.exists(LOG_FILE):
        return

    with open(LOG_FILE, "r") as f:
        f.seek(0, 2)  # go to end of file
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue

            line_lower = line.lower()

            if "authentication failure" in line_lower or \
               "failed password" in line_lower:
                emit_alert({
                    "layer":    "HIDS-LOG",
                    "severity": "HIGH",
                    "reason":   f"Auth failure detected: {line.strip()[:120]}",
                    "timestamp": datetime.now().isoformat()
                })

            elif "sudo" in line_lower and "incorrect" in line_lower:
                emit_alert({
                    "layer":    "HIDS-LOG",
                    "severity": "HIGH",
                    "reason":   f"Sudo failure: {line.strip()[:120]}",
                    "timestamp": datetime.now().isoformat()
                })

            elif "invalid user" in line_lower:
                emit_alert({
                    "layer":    "HIDS-LOG",
                    "severity": "HIGH",
                    "reason":   f"Invalid user attempt: {line.strip()[:120]}",
                    "timestamp": datetime.now().isoformat()
                })


# ─── Start All HIDS Threads ───────────────────────────────────────────────────
def start_hids():
    print("[HIDS] Starting process monitor...")
    threading.Thread(target=monitor_processes, daemon=True).start()

    print("[HIDS] Starting file monitor...")
    threading.Thread(target=monitor_files, daemon=True).start()

    print("[HIDS] Starting log monitor...")
    threading.Thread(target=monitor_logs, daemon=True).start()

    print("[HIDS] All monitors active\n")
