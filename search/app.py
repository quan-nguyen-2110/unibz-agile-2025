from fastapi import FastAPI
import threading
from typing import Dict, Any, List
from mq_client import publish_json, consume

app = FastAPI()


# later you wecan replace with a real DB)
apartments: Dict[str, Dict[str, Any]] = {}


@app.get("/health")
def health():
    return {"status": "ok", "service": "search"}


@app.post("/test-publish")
def test_publish():
    """
    Test endpoint that publishes a dummy 'apartment_added' event to RabbitMQ.
    """
    event = {
        "type": "apartment_added",
        "data": {
            "id": "apt-test-1",
            "name": "Test Apartment",
            "address": "Bolzano",
            "noiselevel": 2,
            "floor": 1,
        },
    }
    publish_json("apartment_events", event)
    return {"status": "sent", "event": event}


@app.get("/search/apartments", response_model=List[Dict[str, Any]])
def list_apartments():
    """
    Return all apartments known to the Search service (from events).
    """
    return list(apartments.values())


def handle_apartment_event(message: Dict[str, Any]):
    """
    Handler for messages coming from the 'apartment_events' queue.
    """
    event_type = message.get("type")
    data = message.get("data", {})

    if event_type == "apartment_added":
        apt_id = data["id"]
        apartments[apt_id] = data
        print(f"[SEARCH] Stored apartment: {apt_id}")

    elif event_type == "apartment_removed":
        apt_id = data["id"]
        if apt_id in apartments:
            del apartments[apt_id]
            print(f"[SEARCH] Removed apartment: {apt_id}")

    else:
        print(f"[SEARCH] Ignored event type: {event_type}")


def start_consumers():
    # Listen to apartment-related events
    consume("apartment_events", handle_apartment_event)


@app.on_event("startup")
def on_startup():
    """
    Start background consumer thread when FastAPI boots.
    """
    t = threading.Thread(target=start_consumers, daemon=True)
    t.start()
    print("[SEARCH] Background consumer thread started")
