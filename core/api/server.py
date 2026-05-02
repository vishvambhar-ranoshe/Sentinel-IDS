# core/api/server.py

import os
import json
import asyncio
import threading
import numpy as np
from datetime import datetime
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from collections import deque

app = FastAPI(title="Sentinel-IDS API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

alerts       = deque(maxlen=500)
traffic_log  = deque(maxlen=200)
connected_ws = set()
stats = {
    "total_packets": 0,
    "total_alerts":  0,
    "rule_alerts":   0,
    "ml_alerts":     0,
    "hids_alerts":   0,
    "correlated":    0,
    "start_time":    datetime.now().isoformat()
}

class NumpyEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, (np.float32, np.float64)): return float(obj)
        if isinstance(obj, (np.int32, np.int64)):     return int(obj)
        if isinstance(obj, np.ndarray):               return obj.tolist()
        if isinstance(obj, bytes):                    return obj.hex()
        return super().default(obj)

def safe_json(data):
    return json.dumps(data, cls=NumpyEncoder)

async def broadcast(message: dict):
    dead = set()
    text = safe_json(message)
    for ws in connected_ws:
        try:
            await ws.send_text(text)
        except:
            dead.add(ws)
    connected_ws.difference_update(dead)

def broadcast_sync(message: dict):
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            asyncio.run_coroutine_threadsafe(broadcast(message), loop)
    except:
        pass

def push_alert(alert_type: str, alert: dict):
    entry = {
        "id":        len(alerts) + 1,
        "type":      alert_type,
        "timestamp": datetime.now().isoformat(),
        "alert":     alert
    }
    alerts.appendleft(entry)
    stats["total_alerts"] += 1
    if alert_type == "RULE":       stats["rule_alerts"]  += 1
    elif alert_type == "ML":       stats["ml_alerts"]    += 1
    elif alert_type == "HIDS":     stats["hids_alerts"]  += 1
    elif alert_type == "CORRELATED": stats["correlated"] += 1
    broadcast_sync({"event": "alert", "data": entry})

def push_packet(packet_info: dict):
    stats["total_packets"] += 1
    traffic_log.appendleft(packet_info)
    if stats["total_packets"] % 50 == 0:
        broadcast_sync({"event": "traffic", "data": packet_info})

def push_stats():
    broadcast_sync({"event": "stats", "data": stats})

@app.get("/")
def root():
    return {"status": "Sentinel-IDS running"}

@app.get("/stats")
def get_stats():
    return stats

@app.get("/alerts")
def get_alerts(limit: int = 50):
    return json.loads(safe_json(list(alerts)[:limit]))

@app.get("/traffic")
def get_traffic(limit: int = 50):
    return list(traffic_log)[:limit]

@app.get("/health")
def get_health():
    import psutil
    return {
        "cpu_percent":    psutil.cpu_percent(interval=1),
        "memory_percent": psutil.virtual_memory().percent,
        "disk_percent":   psutil.disk_usage("/").percent,
        "status":         "running"
    }

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    connected_ws.add(websocket)
    try:
        await websocket.send_text(safe_json({
            "event": "init",
            "data": {
                "stats":   stats,
                "alerts":  list(alerts)[:50],
                "traffic": list(traffic_log)[:50]
            }
        }))
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        connected_ws.discard(websocket)

def start_api():
    import uvicorn
    print("[API] Starting FastAPI server on http://localhost:8000")
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="error")
