from flask import Flask, request
import requests
import time
import json
import base64
import hashlib
import urllib3
from threading import Lock, Thread

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


app = Flask(__name__)

DELIVERY_TTL_SECONDS = 600
PROCESSED_DELIVERIES = {}
PROCESSED_DELIVERIES_LOCK = Lock()

server_url = SERVER_URL
client_id = CLIENT_ID
client_secret = CLIENT_SECRET
username = USERNAME
password = PASSWORD

job_id = JOB_ID

STATUS_TO_RERUN = ["Error"]

POLL_TIMEOUT_SECONDS = 60 * 60        
POLL_INTERVAL_SECONDS = 30

REQUEST_TIMEOUT = (10, 30)

def cleanup_processed_deliveries():
    now = time.time()
    expired_keys = [
        delivery_key
        for delivery_key, expires_at in PROCESSED_DELIVERIES.items()
        if expires_at <= now
    ]
    for delivery_key in expired_keys:
        PROCESSED_DELIVERIES.pop(delivery_key, None)


def extract_event_key():
    return (
        request.headers.get("X-Event-Key")
        or request.headers.get("X-Event")
        or "unknown"
    )


def build_delivery_key(event_key, payload):
    request_uuid = (
        request.headers.get("X-Request-UUID")
        or request.headers.get("X-Hook-UUID")
        or request.headers.get("X-B3-TraceId")
    )

    if request_uuid:
        return f"header:{event_key}:{request_uuid}"

    fingerprint_source = json.dumps(
        payload, sort_keys=True, separators=(",", ":")
    )
    fingerprint = hashlib.sha256(
        f"{event_key}:{fingerprint_source}".encode()
    ).hexdigest()

    return f"payload:{fingerprint}"


def is_duplicate_delivery(delivery_key):
    with PROCESSED_DELIVERIES_LOCK:
        cleanup_processed_deliveries()
        if delivery_key in PROCESSED_DELIVERIES:
            return True
        PROCESSED_DELIVERIES[delivery_key] = (
            time.time() + DELIVERY_TTL_SECONDS
        )
    return False


def should_trigger_pipeline(event_key, payload):
    if event_key not in ["repo:push", "repo:refs_changed"]:
        return False, f"Ignoring unsupported event: {event_key}"

    if event_key == "repo:push":
        changes = payload.get("push", {}).get("changes", [])
        branch_changes = [
            change for change in changes
            if change.get("new", {}).get("type") == "branch"
        ]
        if not branch_changes:
            return False, "Ignoring repo:push event without branch changes"

    if event_key == "repo:refs_changed":
        changes = payload.get("changes", [])
        branch_changes = [
            change for change in changes
            if change.get("ref", {}).get("type") == "BRANCH"
        ]
        if not branch_changes:
            return False, "Ignoring repo:refs_changed event without branch changes"

    return True, "Accepted webhook event"

def authenticate():
    auth_url = f"{server_url}/dataopssecurity/oauth2/token"

    basic_auth_str = f"{client_id}:{client_secret}"
    base64_auth_str = base64.b64encode(basic_auth_str.encode()).decode()

    auth_headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Authorization": f"Basic {base64_auth_str}"
    }
    auth_payload = {
        "username": username,
        "password": password,
        "grant_type": "password"
    }

    response = requests.post(
        auth_url,
        headers=auth_headers,
        data=auth_payload,
        verify=False,
        timeout=REQUEST_TIMEOUT
    )

    print(f"AUTH STATUS: {response.status_code}")
    print(f"AUTH RESPONSE: {response.text}")
    response.raise_for_status()

    token = response.json().get("access_token")
    if not token:
        raise Exception("No access token received")

    return f"Bearer {token}"


def restart_failed_dataflows(bearer_token, target_job_id):
    """
    PUT /piper/jobs/{job_id}/restart?isRerun=y
    Body: {"statusToRerun": ["Failed", "Error"]}

    The API itself only reruns the failed/error dataflows inside the job.
    No pre-check needed -- this mirrors what works in Postman.
    """
    url = f"{server_url}/piper/jobs/{target_job_id}/restart?isRerun=y"

    headers = {
        "Content-Type": "application/json",
        "Authorization": bearer_token
    }
    payload = {"statusToRerun": STATUS_TO_RERUN}

    print(f"RESTART URL: {url}")
    print(f"RESTART BODY: {json.dumps(payload)}")

    response = requests.put(
        url,
        headers=headers,
        json=payload,
        verify=False,
        timeout=REQUEST_TIMEOUT
    )

    print(f"RESTART STATUS: {response.status_code}")
    print(f"RESTART RESPONSE: {response.text}")
    response.raise_for_status()

    try:
        data = response.json()
        new_run_id = (
            data.get("id")
            or data.get("jobId")
            or data.get("runId")
            or target_job_id
        )
    except ValueError:
        new_run_id = target_job_id

    print(f"Restart accepted. Tracking job id: {new_run_id}")
    return new_run_id


def poll_until_complete(bearer_token, target_job_id):
    """Poll job status until it reaches a terminal state or times out."""
    url = f"{server_url}/piper/jobs/{target_job_id}/status"
    headers = {"Authorization": bearer_token}
    terminal_states = {
        "COMPLETED", "SUCCESS", "SUCCEEDED", "FAILED", "ERROR"
    }
    deadline = time.time() + POLL_TIMEOUT_SECONDS

    while time.time() < deadline:
        try:
            response = requests.get(
                url,
                headers=headers,
                verify=False,
                timeout=REQUEST_TIMEOUT
            )
            response.raise_for_status()
            status = (response.json().get("status") or "").upper()
            print(f"Pipeline Status: {status}")

            if status in terminal_states:
                return status

        except requests.RequestException as e:
            print(f"Status check failed (will retry): {e}")

        time.sleep(POLL_INTERVAL_SECONDS)

    raise TimeoutError(
        f"Polling job {target_job_id} exceeded "
        f"{POLL_TIMEOUT_SECONDS} seconds"
    )


def run_pipeline_for_event(delivery_key, event_key):
    print(
        f"Starting restart-failed for delivery {delivery_key}, "
        f"event {event_key}, job {job_id}"
    )

    try:
        bearer_token = authenticate()
        new_run_id = restart_failed_dataflows(bearer_token, job_id)
        final_status = poll_until_complete(bearer_token, new_run_id)

        print(
            f"Delivery {delivery_key}: job {new_run_id} finished "
            f"with status {final_status}"
        )

    except Exception as e:
        print(f"Delivery {delivery_key} failed: {e}")


@app.route('/bitbucket-webhook', methods=['POST'])
def webhook():
    print("BITBUCKET WEBHOOK RECEIVED")

    event_key = extract_event_key()
    payload = request.get_json(silent=True) or {}
    delivery_key = build_delivery_key(event_key, payload)

    print(f"EVENT KEY: {event_key}")
    print(f"DELIVERY KEY: {delivery_key}")
    print("REQUEST HEADERS:")
    print(json.dumps(
        {
            key: value
            for key, value in request.headers.items()
            if key.lower().startswith("x-")
        },
        indent=2
    ))
    print(json.dumps(payload, indent=2))

    try:
        should_trigger, reason = should_trigger_pipeline(event_key, payload)
        if not should_trigger:
            print(reason)
            return {
                "message": reason,
                "event_key": event_key,
                "delivery_key": delivery_key
            }, 202

        if is_duplicate_delivery(delivery_key):
            print(f"Duplicate delivery ignored: {delivery_key}")
            return {
                "message": "Duplicate webhook delivery ignored",
                "event_key": event_key,
                "delivery_key": delivery_key
            }, 202

        worker = Thread(
            target=run_pipeline_for_event,
            args=(delivery_key, event_key),
            daemon=True
        )
        worker.start()

        return {
            "message": "Webhook accepted, restarting failed/error dataflows",
            "event_key": event_key,
            "delivery_key": delivery_key,
            "job_id": job_id
        }, 202

    except Exception as e:
        print(f"ERROR: {e}")
        return {"error": str(e)}, 500


if __name__ == '__main__':
    app.run(port=5000)
