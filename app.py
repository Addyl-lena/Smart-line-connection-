# app.py
import os
import time
import json
import base64
import requests
from datetime import datetime
from flask import Flask, request, jsonify, render_template
from dotenv import load_dotenv
import redis
import routeros_api
from flask_cors import CORS



# load .env if present
load_dotenv()

# ------------------ Config (from env) ------------------
# M-PESA (Daraja)
CONSUMER_KEY = os.getenv("qefnp4VWYkkrEtuZRqa5RnWOSSGNJD6dQ5yQ80EnQeVMfBkT")
CONSUMER_SECRET = os.getenv("rWL0xVkxqHu2AmBN1H1UrXR027JtDTq3rS0uYRwxf73peAkz7khXgZtJjIsAg6aI")
BUSINESS_SHORTCODE = os.getenv("BUSINESS_SHORTCODE", "8427910")
PASSKEY = os.getenv("PASSKEY")
# Use sandbox by default:
OAUTH_URL = os.getenv("OAUTH_URL", "https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials")
STK_URL = os.getenv("STK_URL", "https://sandbox.safaricom.co.ke/mpesa/stkpush/v1/processrequest")

# callback url must be public HTTPS for Safaricom
CALLBACK_BASE = os.getenv("CALLBACK_BASE", "")  # set to your ngrok or domain
CALLBACK_PATH = os.getenv("CALLBACK_PATH", "/mpesa_callback")
CALLBACK_URL = os.getenv("CALLBACK_URL", CALLBACK_BASE + CALLBACK_PATH)

# MikroTik
MIKROTIK_IP = os.getenv("MIKROTIK_IP", "192.168.1.1")
MIKROTIK_USER = os.getenv("MIKROTIK_USER", "api_user")
MIKROTIK_PASS = os.getenv("MIKROTIK_PASS", "your_password")
MIKROTIK_PORT = int(os.getenv("MIKROTIK_PORT", "8728"))

# Redis (pending payment store)
REDIS_URL = os.getenv("REDIS_URL", "redis://127.0.0.1:6379/0")
REDIS_TTL = int(os.getenv("REDIS_TTL", "900"))  # 15 minutes default

# service
APP_HOST = "0.0.0.0"
APP_PORT = int(os.getenv("APP_PORT", "5000"))

# security / debug
DEBUG = os.getenv("DEBUG", "true").lower() in ("1", "true", "yes")

# ------------------ init ------------------
app = Flask(__name__, static_folder='static', template_folder='templates')
CORS(app)

r = redis.from_url(REDIS_URL, decode_responses=True)

# -------------- helpers --------------
def get_access_token():
    """Get Daraja access token."""
    try:
        res = requests.get(OAUTH_URL, auth=(CONSUMER_KEY, CONSUMER_KEY, timeout=10)
        res.raise_for_status()
        return res.json().get("access_token")
    except Exception as e:
        app.logger.error("Access token error: %s", e)
        return None

def initiate_stk_push(phone: str, amount: int, account_ref: str, callback_url: str):
    token = get_access_token()
    if not token:
        return None, "Could not get access token"

    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    password_str = BUSINESS_SHORTCODE + PASSKEY + timestamp
    password = base64.b64encode(password_str.encode()).decode()

    payload = {
        "BusinessShortCode": BUSINESS_SHORTCODE,
        "Password": password,
        "Timestamp": timestamp,
        "TransactionType": "CustomerPayBillOnline",
        "Amount": amount,
        "PartyA": phone,
        "PartyB": BUSINESS_SHORTCODE,
        "PhoneNumber": phone,
        "CallBackURL": callback_url,
        "AccountReference": account_ref,
        "TransactionDesc": "WiFi Purchase"
    }

    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    try:
        resp = requests.post(STK_URL, json=payload, headers=headers, timeout=15)
        resp.raise_for_status()
        return resp.json(), None
    except Exception as e:
        app.logger.error("STK push error: %s", e)
        return None, str(e)

def authorize_mikrotik(mac_address: str, package_minutes: int, comment: str = ""):
    """Adds MAC to hotspot ip-binding as 'bypassed' so it skips captive portal."""
    try:
        pool = routeros_api.RouterOsApiPool(
            MIKROTIK_IP,
            username=MIKROTIK_USER,
            password=MIKROTIK_PASS,
            plaintext_login=True,
            port=MIKROTIK_PORT,
            timeout=5
        )
        api = pool.get_api()
        # Add IP binding entry (mac-address field is mac-address)
        api.get_resource('/ip/hotspot/ip-binding').add(
            mac_address=mac_address,
            comment=comment,
            type='bypassed'
        )
        pool.disconnect()
        return True, None
    except Exception as e:
        app.logger.error("MikroTik error: %s", e)
        return False, str(e)

# ------------ helpers: redis mapping ------------
# We'll store pending payments keyed by "checkout:<CheckoutRequestID>" and short index by phone as fallback.
def store_pending(checkout_id: str, payload: dict):
    key = f"checkout:{checkout_id}"
    r.set(key, json.dumps(payload), ex=REDIS_TTL)

def get_pending(checkout_id: str):
    key = f"checkout:{checkout_id}"
    val = r.get(key)
    return json.loads(val) if val else None

def mark_processed(checkout_id: str, info: dict):
    key = f"checkout:{checkout_id}"
    r.set(key, json.dumps(info), ex=3600)  # keep processed record 1 hour

# -------------- Routes ----------------

@app.route("/")
def index():
    # This is a simple page not used by the MikroTik captive portal.
    return "WiFi payment service is running."

# Route the MikroTik login page will fetch: it contains $(mac) variable replaced by router.
@app.route("/hotspot-login")
def hotspot_login():
    # This file should be uploaded to MikroTik hotspot as the login page
    return render_template("hotspot_login.html")

# Frontend POST from login page: { phone, amount, mac, ip }
@app.route("/pay", methods=["POST"])
def pay():
    data = request.get_json() or request.form
    phone = data.get("phone")
    amount = data.get("amount")
    mac = data.get("mac")
    ip_addr = data.get("ip")  # optional

    # sanitize and normalize phone -> Safaricom expects 2547XXXXXXXX
    if not phone:
        return jsonify({"error": "phone required"}), 400
    phone = phone.strip()
    phone = normalize_phone(phone)

    try:
        amount = int(amount)
    except Exception:
        return jsonify({"error": "invalid amount"}), 400

    if not mac:
        return jsonify({"error": "mac required"}), 400

    # create a local transaction id (fallback) and call STK
    tx_local = f"tx-{int(time.time()*1000)}"
    account_ref = f"WiFi_{amount}KES"

    # prepare pending payload and store keyed by a local id until checkout response comes back
    pending_payload = {
        "local_tx": tx_local,
        "phone": phone,
        "amount": amount,
        "mac": mac,
        "ip": ip_addr,
        "created_at": datetime.utcnow().isoformat()
    }

    # We'll initiate STK push and store mapping by CheckoutRequestID once Daraja returns it.
    # For now store a temporary mapping by phone so callback can use fallback (not ideal: use CheckoutRequestID).
    r.set(f"pending:phone:{phone}", json.dumps(pending_payload), ex=REDIS_TTL)

    stk_resp, err = initiate_stk_push(phone, amount, account_ref, CALLBACK_URL)
    if err or not stk_resp:
        return jsonify({"error": "could not initiate stk", "details": err or stk_resp}), 500

    # Daraja returns 'CheckoutRequestID' - store mapping
    checkout_id = stk_resp.get("CheckoutRequestID") or stk_resp.get("CheckoutRequestID")
    if checkout_id:
        pending_payload["daraja"] = stk_resp
        store_pending(checkout_id, pending_payload)

    return jsonify({"status": "STK_SENT", "daraja_response": stk_resp})

# Utility phone normalization
def normalize_phone(p: str) -> str:
    p = p.replace("+", "").replace(" ", "")
    if p.startswith("0"):
        p = "254" + p[1:]
    if p.startswith("7") and len(p) == 9:
        p = "254" + p
    return p

# MPESA Callback endpoint (Daraja will POST here)
@app.route("/mpesa_callback", methods=["POST"])
def mpesa_callback():
    data = request.get_json(force=True, silent=True)
    app.logger.info("Callback received: %s", data)

    # Daraja callback payload format: Body -> stkCallback
    try:
        body = data.get("Body", {})
        stk = body.get("stkCallback", {})
    except Exception:
        app.logger.error("Malformed callback")
        return jsonify({"ResultCode": 1, "ResultDesc": "Malformed"}), 400

    # get result and metadata
    result_code = stk.get("ResultCode")
    checkout_request_id = stk.get("CheckoutRequestID")
    callback_meta = stk.get("CallbackMetadata", {})
    # Extract phone & amount from metadata if present
    meta_items = callback_meta.get("Item", []) if callback_meta else []
    meta = {}
    for it in meta_items:
        # Names vary slightly; check both 'Value' and 'value'
        key = it.get("Name")
        val = it.get("Value") or it.get("value")
        meta[key] = val

    phone = meta.get("PhoneNumber") or meta.get("MSISDN")
    amount = meta.get("Amount")

    # Try to find pending by checkout_id, otherwise fallback by phone
    pending = get_pending(checkout_request_id) if checkout_request_id else None
    if not pending and phone:
        pending_json = r.get(f"pending:phone:{phone}")
        if pending_json:
            pending = json.loads(pending_json)

    # Handle success
    if result_code == 0:
        # ensure pending exists and amount matches
        if not pending:
            app.logger.warning("Payment success but no pending found for checkout=%s phone=%s", checkout_request_id, phone)
            # still return success to Daraja
            return jsonify({"ResultCode": 0, "ResultDesc": "Accepted"}), 200

        # authorize on MikroTik using stored MAC
        mac = pending.get("mac")
        pkg_minutes = int(pending.get("amount", amount))
        comment = f"paid {amount} by {phone}"
        ok, err = authorize_mikrotik(mac, pkg_minutes, comment)
        # mark processed
        pending["status"] = "PAID" if ok else "AUTH_FAILED"
        pending["processed_at"] = datetime.utcnow().isoformat()
        pending["daraja_meta"] = {"checkout": checkout_request_id, "raw_meta": meta}
        mark_processed(checkout_request_id or f"local-{time.time()}", pending)

        if ok:
            app.logger.info("Authorized %s", mac)
        else:
            app.logger.error("Mikrotik auth failed: %s", err)
    else:
        # failed or cancelled
        app.logger.warning("Transaction failed: %s", stk.get("ResultDesc"))
        if checkout_request_id:
            mark_processed(checkout_request_id, {"status": "FAILED", "reason": stk.get("ResultDesc")})

    # IMPORTANT: reply with the required JSON structure
    return jsonify({"ResultCode": 0, "ResultDesc": "Accepted"}), 200


if __name__ == "__main__":
    app.run(host=APP_HOST, port=APP_PORT, debug=DEBUG)

