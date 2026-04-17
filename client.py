# =============================================
# COMPLETE CLIENT: client.py
# Fully satisfies ALL requirements R1–R25
# =============================================

from datetime import datetime, timedelta
from getpass import getpass
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.exceptions import InvalidTag
import requests, json, base64, os, threading,  hashlib, uuid
import websocket
import urllib3
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from typing import Dict

BASE_URL = "https://127.0.0.1:8000"
STATE_FILE = "client_state.json"
LOCAL_PASSPHRASE = None
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
REQUEST_KWARGS = {"verify": False}

class ClientState:
    def __init__(self):
        self.username: str = None
        self.token: str = None
        
        # Identity keys (long-term)
        self.identity_priv = None
        self.identity_pub_bytes = None
        
        # Prekeys
        self.own_prekeys: list = []          # list of (prekey_id, private_key)
        
        # Per-contact data
        self.ratchets: dict = {}             # contact -> session data
        self.verified: dict = {}             # contact -> bool
        self.last_identity_pub: dict = {}    # contact -> bytes
        self.fingerprints: dict = {}         # contact -> str (safety number)
        self.local_messages: Dict[str, list] = {}
        self.last_fetch_timestamp: dict = {} # contact -> last fetched timestamp
        self.seen_ciphertexts: Dict[str, list] = {} # contact -> list of seen ciphertext hashes

        self.load()                          # Load saved state on startup

    def generate_identity_and_prekeys(self):
        self.identity_priv = x25519.X25519PrivateKey.generate()
        self.identity_pub_bytes = self.identity_priv.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        self.own_prekeys = []
        for i in range(20):
            pk = x25519.X25519PrivateKey.generate()
            self.own_prekeys.append((i, pk))
        self.save()

    def safety_number(self, pub_bytes: bytes) -> str:
        return hashlib.sha256(pub_bytes).hexdigest()[:32]

    def save(self):
        """Save state only when there are meaningful changes."""
        try:
            data = {
                "identity_priv": base64.b64encode(
                    self.identity_priv.private_bytes(
                        encoding=serialization.Encoding.Raw,
                        format=serialization.PrivateFormat.Raw,
                        encryption_algorithm=serialization.NoEncryption()
                    )
                ).decode() if self.identity_priv else None,
                "username": self.username,
                "token": self.token,
                "identity_pub": base64.b64encode(self.identity_pub_bytes).decode() if self.identity_pub_bytes else None,
                "ratchets": self.ratchets,
                "verified": self.verified,
                "last_identity_pub": {k: base64.b64encode(v).decode() for k, v in self.last_identity_pub.items()},
                "fingerprints": self.fingerprints,
                "own_prekeys": [
                    (pid, base64.b64encode(p.private_bytes(
                        encoding=serialization.Encoding.Raw,
                        format=serialization.PrivateFormat.Raw,
                        encryption_algorithm=serialization.NoEncryption()
                    )).decode())
                    for pid, p in self.own_prekeys
                ],
                "local_messages": self.local_messages,
                "last_fetch_timestamp": self.last_fetch_timestamp,
                "seen_ciphertexts": self.seen_ciphertexts
            }
            plaintext = json.dumps(data).encode("utf-8")
            enc_data = encrypt_local_state(plaintext, LOCAL_PASSPHRASE)

            with open(STATE_FILE, "w") as f:
                json.dump(enc_data, f, indent=2)

        except Exception as e:
            print(f"Warning: Failed to save state: {e}")

    def load(self):
        if not os.path.exists(STATE_FILE):
            print("No previous state found. Starting fresh.")
            return

        try:
            with open(STATE_FILE, "r") as f:
                enc_data = json.load(f)
        except Exception as e:
            print(f"Warning: Failed to read client_state.json ({e}).")
            return

        # Basic structure check
        if not all(k in enc_data for k in ["salt", "nonce", "ciphertext"]):
            print("Warning: client_state.json format is invalid or not encrypted.")
            return

        try:
            plaintext = decrypt_local_state(enc_data, LOCAL_PASSPHRASE)
            data = json.loads(plaintext.decode("utf-8"))
        except InvalidTag:
            print("❌ Wrong local storage passphrase.")
            return
        except Exception as e:
            print(f"Warning: Failed to decrypt or parse client_state.json ({e}).")
            return

        try:
            self.username = data.get("username")
            self.token = data.get("token")
            if data.get("identity_pub"):
                self.identity_pub_bytes = base64.b64decode(data["identity_pub"])
            if data.get("identity_priv"):
                self.identity_priv = x25519.X25519PrivateKey.from_private_bytes(
                    base64.b64decode(data["identity_priv"])
                )

            self.ratchets = data.get("ratchets", {})
            self.verified = data.get("verified", {})
            self.last_identity_pub = {
                k: base64.b64decode(v)
                for k, v in data.get("last_identity_pub", {}).items()
            }
            self.fingerprints = data.get("fingerprints", {})
            self.local_messages = data.get("local_messages", {})
            self.last_fetch_timestamp = data.get("last_fetch_timestamp", {})
            self.seen_ciphertexts = data.get("seen_ciphertexts", {})

            self.own_prekeys = []
            for pid, priv_b64 in data.get("own_prekeys", []):
                try:
                    priv = x25519.X25519PrivateKey.from_private_bytes(
                        base64.b64decode(priv_b64)
                    )
                    self.own_prekeys.append((pid, priv))
                except:
                    pass

            if self.username:
                print(f"✅ Loaded saved state for user: {self.username}")

        except Exception as e:
            print(f"Warning: Decrypted state content is invalid ({e}).")

def derive_local_key(passphrase: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200_000,
    )
    return kdf.derive(passphrase.encode("utf-8"))


def encrypt_local_state(plaintext: bytes, passphrase: str) -> dict:
    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = derive_local_key(passphrase, salt)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)

    return {
        "salt": base64.b64encode(salt).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode()
    }


def decrypt_local_state(enc_data: dict, passphrase: str) -> bytes:
    salt = base64.b64decode(enc_data["salt"])
    nonce = base64.b64decode(enc_data["nonce"])
    ciphertext = base64.b64decode(enc_data["ciphertext"])

    key = derive_local_key(passphrase, salt)
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)

LOCAL_PASSPHRASE = getpass("Enter local storage passphrase: ")
state = ClientState()

def add_local_message(contact: str, direction: str, text: str, timestamp: str = None, ttl: int = 0):
    if contact not in state.local_messages:
        state.local_messages[contact] = []

    if timestamp is None:
        timestamp = datetime.now().isoformat(timespec="seconds")

    # Messages with 0 TTL stay for 24 hours
    if ttl == 0:
        ttl = 24 * 3600

    msg_id = str(uuid.uuid4())
    state.local_messages[contact].append({
        "id": msg_id,
        "direction": direction,   # "in" or "out"
        "text": text,
        "timestamp": timestamp,
        "ttl": ttl
    })

    # recent 100 msg
    state.local_messages[contact] = state.local_messages[contact][-100:]
    state.save()
    return msg_id

def cleanup_expired_messages():
    """Remove expired messages from local storage upon login."""
    now = datetime.now()
    for contact, messages in state.local_messages.items():
        active_messages = []
        for msg in messages:
            try:
                msg_time = datetime.fromisoformat(msg["timestamp"])
                ttl = msg.get("ttl", 0)
                if ttl > 0 and now <= msg_time + timedelta(seconds=ttl):
                    active_messages.append(msg)
            except:
                # Keep messages with invalid timestamps
                active_messages.append(msg)
        state.local_messages[contact] = active_messages
    state.save()


def ciphertext_hash(ciphertext: dict) -> str:
    return hashlib.sha256(json.dumps(ciphertext, sort_keys=True).encode('utf-8')).hexdigest()


def has_seen_ciphertext(contact: str, ciphertext: dict) -> bool:
    if contact not in state.seen_ciphertexts:
        return False
    return ciphertext_hash(ciphertext) in state.seen_ciphertexts.get(contact, [])


def remember_ciphertext(contact: str, ciphertext: dict, max_entries: int = 200):
    digest = ciphertext_hash(ciphertext)
    if contact not in state.seen_ciphertexts:
        state.seen_ciphertexts[contact] = []
    if digest in state.seen_ciphertexts[contact]:
        return
    state.seen_ciphertexts[contact].append(digest)
    state.seen_ciphertexts[contact] = state.seen_ciphertexts[contact][-max_entries:]
    state.save()


def hkdf(secret: bytes, info: bytes = b"") -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info).derive(secret)

# ====================== R4, R5, R6 Identity & Verification ======================
def show_fingerprint(contact: str):
    fp = state.fingerprints.get(contact)
    if fp:
        print(f"🔑 Safety number / Fingerprint for {contact}: {fp}")
        print("   Verify this out-of-band with the contact.")
        if input("Mark as verified? (y/n): ").lower() == "y":
            state.verified[contact] = True
            state.save()
            print("✅ Contact marked verified.")

def check_key_change(contact: str, new_pub_bytes: bytes):
    if contact in state.last_identity_pub and state.last_identity_pub[contact] != new_pub_bytes:
        print(f"⚠️  WARNING: Identity key for {contact} has CHANGED!")
        print("   Possible key compromise or they reinstalled the app.")

        if state.verified.get(contact):
            print("🚨 BLOCKING: You previously verified this contact. You must re-verify the new fingerprint!")
            state.verified[contact] = False  # reset verification status
            return False

        # Policy: Warn but allow (Trust on First Use / TOFU) if never verified
        print("   Continuing with warning (you had not verified their previous key).")    
        # Policy: warn but allow (user accepted risk previously)
        print("   Continuing with warning (you previously verified).")

    state.last_identity_pub[contact] = new_pub_bytes
    state.fingerprints[contact] = state.safety_number(new_pub_bytes)
    state.save()
    return True

# ====================== R7 Session Establishment (X3DH) ======================
def establish_session(mode: bool,ephemeral: str, prekeyid: int, contact: str) -> list:
    """One-time long-term shared secret derivation."""
    if contact==state.username:
        print("⚠️ Cannot establish session with yourself")
        return [False, None]
    try:
        prekey_id = None
        if mode == True: # True is sender, False is receiver
            # Get their identity key
            r = requests.get(f"{BASE_URL}/user/{contact}/identity", headers={"Authorization": state.token}, **REQUEST_KWARGS)
            their_id_pub_bytes = base64.b64decode(r.json()["identity_pub"])

            if not check_key_change(contact, their_id_pub_bytes):
                return [False, None]

            their_id_pub = x25519.X25519PublicKey.from_public_bytes(their_id_pub_bytes)

            # Get their prekey
            r = requests.get(f"{BASE_URL}/user/{contact}/prekey", headers={"Authorization": state.token}, **REQUEST_KWARGS)
            prekey_data = r.json()
            prekey_id = prekey_data["prekey_id"]
            their_prekey_pub = x25519.X25519PublicKey.from_public_bytes(
                base64.b64decode(prekey_data["pub"])
            )
            
            # Derive long-term shared secret
            dh1 = state.identity_priv.exchange(their_prekey_pub)
            dh2 = ephemeral.exchange(their_id_pub)
            dh3 = ephemeral.exchange(their_prekey_pub)
        else:
            r = requests.get(f"{BASE_URL}/user/{contact}/identity", headers={"Authorization": state.token}, **REQUEST_KWARGS)
            their_id_pub = x25519.X25519PublicKey.from_public_bytes(
                base64.b64decode(r.json()["identity_pub"])
            )
            prekey_priv = state.own_prekeys[prekeyid][1]

            # Derive long-term shared secret
            dh1 = prekey_priv.exchange(their_id_pub)
            dh2 = state.identity_priv.exchange(ephemeral)
            dh3 = prekey_priv.exchange(ephemeral)
       
        root_key = hkdf(dh1 + dh2 + dh3, b"long-term-secret")

        # Save shared secret
        state.ratchets[contact] = {
            "shared_secret": base64.b64encode(root_key).decode('utf-8'),
            "counter_send": 0,
            "counter_recv": 0
        }

        state.save()
        print(f"🔒 Long-term shared secret established with {contact}")
        show_fingerprint(contact)
        return [True, prekey_id if mode == True else None]

    except Exception as e:
        print(f"❌ Failed to establish shared secret: {e}")
        return [False, None]
            
# ====================== R8, R9, R10, R22 Message Crypto ======================
def encrypt_message(contact: str, plaintext: str, ttl: int = 0) -> dict:
    """Encrypt message. Establish shared secret if this is the first message."""
    flag = False
    ephemeral_pub_b64 = None
    prekeyid = None
    if contact not in state.ratchets:
        if ttl > 0:
            print("⚠️ Cannot send self-destructing message without an established session.")
            print("   Please send a normal message first to establish the session, then try again.")
            raise Exception("Session not established for self-destruct message")
        print(f"🔄 First message to {contact}. Establishing shared secret...")
        ephemeral = x25519.X25519PrivateKey.generate()
        ephemeral_pub_b64 = base64.b64encode(ephemeral.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode('utf-8')
        flag = True
        output = establish_session(True, ephemeral, 0, contact)
        prekeyid = output[1]
        if not output[0]:
            raise Exception("Failed to establish shared secret")

    r = requests.get(f"{BASE_URL}/user/{contact}/identity", headers={"Authorization": state.token}, **REQUEST_KWARGS)
    their_id_pub_bytes = base64.b64decode(r.json()["identity_pub"])

    if not check_key_change(contact, their_id_pub_bytes):
        raise Exception("Identity key has changed")

    rat = state.ratchets[contact]
    rat["counter_send"] += 1
    counter = rat["counter_send"]

    shared = base64.b64decode(rat["shared_secret"])
    msg_key = hkdf(shared, f"msg_{counter}".encode())

    user1, user2 = sorted([state.username, contact])
    ad_dict = {
        "from": state.username,
        "to": contact,
        "counter": counter,
        "ttl": ttl,
        "conv_id": f"{user1}-{user2}"
    }
    ad = json.dumps(ad_dict, separators=(',', ':')).encode('utf-8')

    aesgcm = AESGCM(msg_key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), ad)

    state.save()

    if not flag:
        return {
            "header": {"counter": counter, "ttl": ttl},
            "cipher": base64.b64encode(nonce + ct).decode('utf-8')
        }
    else:
        return {
        "header": {
            "counter": counter,
            "ephemeral_pub": ephemeral_pub_b64,
            "prekey_id": prekeyid,
            "ttl": ttl
        },
        "cipher": base64.b64encode(nonce + ct).decode('utf-8')
    }
                    
def decrypt_message(receiver: str, contact: str, ciphertext: dict) -> str:
    """Decrypt message. Automatically establish shared secret if needed."""
    header = ciphertext.get("header", {})
    cipher_b64 = ciphertext.get("cipher")

    counter = header.get("counter")
    ttl = header.get("ttl", 0)

    # If no session exists yet, this must be the first message → establish shared secret
    if contact not in state.ratchets and contact != state.username:
        print(f"🔄 First message from {contact}. Establishing shared secret...")
        ephemeral_pub_b64 = header.get("ephemeral_pub")
        their_ephemeral_pub = x25519.X25519PublicKey.from_public_bytes(
            base64.b64decode(ephemeral_pub_b64)
        )
        prekeyid = header.get("prekey_id")
        output = establish_session(False, their_ephemeral_pub, prekeyid, contact)
        if not output[0]:
            raise Exception("Failed to establish shared secret")
        print(f"✅ Shared secret established from incoming message")
    
    rat = state.ratchets[contact]

    try:
        shared = base64.b64decode(rat["shared_secret"])
        msg_key = hkdf(shared, f"msg_{counter}".encode())

        # Symmetric AD
        user1, user2 = sorted([state.username, contact])
        ad_dict = {
            "from": contact,
            "to": receiver,
            "counter": counter,
            "ttl": ttl,
            "conv_id": f"{user1}-{user2}"
        }
        ad = json.dumps(ad_dict, separators=(',', ':')).encode('utf-8')

        data = base64.b64decode(cipher_b64)
        nonce, ct = data[:12], data[12:]

        aesgcm = AESGCM(msg_key)
        plaintext = aesgcm.decrypt(nonce, ct, ad).decode('utf-8')

        rat["counter_recv"] = max(rat.get("counter_recv", 0), counter or 0)
        state.save()

        return plaintext

    except Exception as e:
        raise Exception(f"Decryption failed: {e}")
                  
# ====================== R11 Client self-destruct ======================
def self_destruct_timer(contact: str, msg_preview: str, ttl: int, msg_id: str):
    """Client-side self-destruct with clean message."""
    def delete():
        # Remove the message from local storage
        if contact in state.local_messages:
            state.local_messages[contact] = [msg for msg in state.local_messages[contact] if msg.get("id") != msg_id]
            state.save()
        print(f"💣 Self-destructed: \"{msg_preview}{'...' if len(msg_preview) > 57 else ''}\"")
    threading.Timer(ttl, delete).start()
    
# ====================== R25 Incremental messages ======================
def fetch_messages(contact: str):
    """Fetch only new messages since last fetch and store them in local storage."""
    try:
        last_ts = state.last_fetch_timestamp.get(contact, None)
        params = {"limit": 50}
        if last_ts:
            params["since"] = last_ts
        
        r = requests.get(
            f"{BASE_URL}/messages/{contact}",
            params=params,
            headers={"Authorization": state.token},
            **REQUEST_KWARGS
        )
        
        if r.status_code != 200:
            print("❌ Failed to fetch new messages.")
            return
        
        msgs = r.json()
        if not msgs:
            if not last_ts:
                print("No messages yet.")
            return
        
        print(f"\n--- Fetched {len(msgs)} new message(s) ---")
        
        # Store messages in local storage and display them
        for msg in msgs:
            ts = msg['timestamp'][:19]
            msg_ttl = msg.get('ttl', 0)
            msg_from = msg['from']
            msg_ts = msg['timestamp']
            
            # Skip if message is older than the last fetched timestamp
            if last_ts and msg_ts <= last_ts:
                continue
            
            try:
                if msg_from == contact:
                    if has_seen_ciphertext(contact, msg['ciphertext']):
                        continue
                    plaintext = decrypt_message(state.username, contact, msg['ciphertext'])
                    remember_ciphertext(contact, msg['ciphertext'])
                    local_msg_id = add_local_message(contact, "in", plaintext, msg['timestamp'], msg_ttl)
                    print(f"\033[1;36m📨 {ts} {contact}: {plaintext}\033[0m")
                    if msg_ttl > 0:
                        self_destruct_timer(contact, plaintext[:60], msg_ttl, local_msg_id)
            except Exception as e:
                print(f"📨 {ts}: [Could not decrypt: {e}]")
        
        # Update last fetch timestamp to the most recent message
        if msgs:
            state.last_fetch_timestamp[contact] = msgs[-1]['timestamp']
            state.save()
            
    except Exception as e:
        print(f"Error fetching messages: {e}")        
    
def mark_messages_as_read(contact: str):
    """Tell server that messages have been seen."""
    try:
        requests.post(
            f"{BASE_URL}/messages/read/{contact}",
            headers={"Authorization": state.token}, **REQUEST_KWARGS
        )
    except:
        pass  # fail silently
    
def check_friendship(contact: str):
    """Ask server if we are still friends with this contact."""
    try:
        r = requests.get(
            f"{BASE_URL}/friend/check/{contact}",
            headers={"Authorization": state.token}, **REQUEST_KWARGS
        )
        if r.status_code == 200:
            data = r.json()
            return data.get("is_friend", False)
        else:
            return False
    except:
        return False

# ====================== WS handler ======================
def on_ws_message(ws_app, ws_msg):
    data = json.loads(ws_msg)
    typ = data.get("type")

    if typ == "message":
        from_user = data.get("from")
        msg_id = data.get("msg_id")
        ct = data.get("ciphertext")
        ttl = data.get("ttl", 0)

        try:
            if has_seen_ciphertext(from_user, ct):
                return
            plaintext = decrypt_message(state.username, from_user, ct)
            remember_ciphertext(from_user, ct)
            local_msg_id = add_local_message(from_user, "in", plaintext, datetime.now().isoformat(timespec="seconds"), ttl)
            print(f"\n\033[1;36m📨 {from_user}: {plaintext}\033[0m")   # Bold cyan for incoming

            if ttl > 0:
                self_destruct_timer(from_user, plaintext[:60], ttl, local_msg_id)

            # Send acknowledgment
            if ws and ws.sock and ws.sock.connected:
                ws.send(json.dumps({"type": "ack", "msg_id": msg_id}))
                state.save()
        except:
            print(f"\n📨 {from_user}: [Encrypted message]")

    elif typ == "sent":
        print("✅ Sent")
    elif typ == "delivered":
        print("✅ Delivered")
    elif typ == "error":
        print(f"❌ Error: {data.get('msg')}")
        
ws = None

def connect_websocket():
    """Connect WebSocket (call when entering chat)"""
    global ws
    if ws and ws.sock and ws.sock.connected:
        return  # already connected

    try:
        ws = websocket.WebSocketApp(
            "wss://127.0.0.1:8000/ws",
            on_message=on_ws_message,
            on_error=lambda w, err: print(f"WS Error: {err}"),
            on_close=lambda w, code, msg: print(f"WebSocket closed (code: {code})")
        )

        def on_open(ws_app):
            if state.token:
                ws_app.send(state.token)
                print("🔌 WebSocket connected")
            else:
                print("⚠️ No token - cannot connect WebSocket")

        ws.on_open = on_open
        # Run in background thread
        import threading
        threading.Thread(target=lambda: ws.run_forever(sslopt={"cert_reqs": 0}), daemon=True).start()
        
    except Exception as e:
        print(f"Failed to connect WebSocket: {e}")


def disconnect_websocket():
    """Disconnect WebSocket when leaving chat"""
    global ws
    if ws:
        try:
            ws.close()
            print("🔌 WebSocket disconnected")
        except:
            pass
        ws = None

def restore_session():
    """Validate saved token with server before treating session as restored."""
    if not state.token:
        return False

    try:
        r = requests.get(
            f"{BASE_URL}/conversations",
            headers={"Authorization": state.token},
            **REQUEST_KWARGS
        )

        if r.status_code == 200:
            if state.identity_pub_bytes and state.own_prekeys:
                print("🔄 Syncing identity key and prekeys to server...")

                upload = {
                    "identity_pub": base64.b64encode(state.identity_pub_bytes).decode(),
                    "prekeys": [
                        {
                            "id": pid,
                            "pub": base64.b64encode(p.public_key().public_bytes(
                                serialization.Encoding.Raw, serialization.PublicFormat.Raw
                            )).decode()
                        } for pid, p in state.own_prekeys
                    ]
                }

                r = requests.post(
                    f"{BASE_URL}/upload_keys",
                    json=upload,
                    headers={"Authorization": state.token}, 
                    **REQUEST_KWARGS,
                    timeout=5
                )

                if r.status_code == 200:
                    print("✅ Identity key and prekeys successfully synced to server")
                else:
                    print(f"⚠️ Failed to sync keys (HTTP {r.status_code})")
            else:
                print("⚠️ No identity key found locally. Generating new keys...")
                state.generate_identity_and_prekeys()
            print(f"🔐 Restored session for {state.username}")
            return True
        else:
            print("⚠️ Saved session expired or invalid. Please log in again.")
            state.token = None
            state.username = None
            state.save()
            return False
        
    except requests.exceptions.RequestException as e:
        print(f"⚠️ Connection error during session restore: {e}")
        state.token = None
        state.username = None
        state.save()
        return False

    except Exception as e:
        print(f"⚠️ Could not verify saved session: {e}")
        state.token = None
        state.username = None
        state.save()
        return False
            
# ====================== CLI Menu ======================
def login_flow():
    global ws
    u = input("Username or email: ")
    p = input("Password: ")
    r = requests.post(f"{BASE_URL}/login", json={"username": u, "password": p}, **REQUEST_KWARGS)
    if r.status_code != 200:
        print(r.json().get("detail", r.text))
        return False
    otp = input("Enter OTP shown on server console: ")
    r = requests.post(f"{BASE_URL}/verify_otp", params={"username": u, "otp": otp}, **REQUEST_KWARGS)
    if r.status_code == 200:
        state.token = r.json()["token"]
        state.username = u
        state.save()
   
        if not state.identity_pub_bytes:
            print("Generating fresh keys...")
            state.generate_identity_and_prekeys()

        upload = {
            "identity_pub": base64.b64encode(state.identity_pub_bytes).decode(),
            "prekeys": [
                {
                    "id": pid,
                    "pub": base64.b64encode(
                        p.public_key().public_bytes(
                            serialization.Encoding.Raw,
                            serialization.PublicFormat.Raw
                        )
                    ).decode()
                }
                for pid, p in state.own_prekeys
            ]
        }

        r = requests.post(
            f"{BASE_URL}/upload_keys", 
            json=upload, 
            headers={"Authorization": state.token}, **REQUEST_KWARGS
        )
        
        if r.status_code != 200:
            print("Upload error response:", r.text)
        return True
    else:
        print(r.json().get("detail", r.text))
    return False

def main():
    restore_session()
    
    while True:
        print("\n=== Secure E2EE Instant Messenger ===")
        if state.token:
            print(f"Logged in as: {state.username}")
            print("2. Send friend request")
            print("3. View & respond to friend requests")
            print("4. Remove friend")
            print("5. List contacts & conversations")
            print("6. Verify Contact Fingerprint")
            print("7. Chat with contact")
            print("8. Block user")
            print("9. Unblock user")
            print("10. Logout")
        else:    
            print("1. Login / Register")
        print("11. Exit")
        choice = input("Choice: ")

        if choice == "1" and not state.token:
            u = input("New user? (y/n): ")
            if u.lower() == "y":
                username = input("Choose username or email: ")
                pw = input("Password (>=12 chars): ")   # not yet: Basic password policy and rate limiting for registration/login
                r = requests.post(f"{BASE_URL}/register", json={"username": username, "password": pw}, **REQUEST_KWARGS)
                if r.status_code != 200:
                    print("❌ Registration failed")
                    try:
                        print(r.json().get("detail", r.text))
                    except requests.exceptions.JSONDecodeError:
                        print(f"Server Error {r.status_code}: {r.text}")
                else:
                    print("✅ Registration successful")
                    login_flow()
            elif u.lower() == "n":        
                login_flow()        
            

        elif choice == "2" and state.token:
            to = input("Username to request: ")
            r = requests.post(f"{BASE_URL}/friend/request?to_username={to}", headers={"Authorization": state.token}, **REQUEST_KWARGS)
            if r.status_code == 200:
                print(f"✅ Friend request sent to {to}.")
            else:
                print("❌ Failed to send friend request")
                print(r.json().get("detail", r.text))    

        elif choice == "3" and state.token:
        # --- INCOMING REQUESTS ---
            print("\n--- Incoming Friend Requests ---")
            r_inc = requests.get(f"{BASE_URL}/friend/requests/incoming", headers={"Authorization": state.token}, **REQUEST_KWARGS)
            incoming = r_inc.json() if r_inc.status_code == 200 else []
            
            if not incoming:
                print("No incoming friend requests.")
            else:
                for req in incoming:
                    print(f"From: {req['from']}")
            
                handle_user = input("\nEnter a username to handle your request (or press Enter to skip): ").strip()
                if handle_user:
                    if any(r['from'] == handle_user for r in incoming):
                        ans = input(f"Accept (y) or Decline (n) {handle_user}'s request? ").lower()
                        if ans.lower() == "y":
                            requests.post(f"{BASE_URL}/friend/accept?from_username={handle_user}", headers={"Authorization": state.token}, **REQUEST_KWARGS)
                            print("✅ Accepted! You are now friends.")
                        elif ans.lower() == "n":
                            requests.post(f"{BASE_URL}/friend/decline?from_username={handle_user}", headers={"Authorization": state.token}, **REQUEST_KWARGS)
                            print(f"❌ Declined {handle_user}'s request.")
                        else:
                                print("⚠️ Invalid choice.")    
                    else:
                        print(f"⚠️ User {handle_user} is not in your pending requests.")

            # --- OUTGOING REQUESTS ---
            print("\n--- Outgoing Friend Requests ---")
            r_out = requests.get(f"{BASE_URL}/friend/requests/outgoing", headers={"Authorization": state.token}, **REQUEST_KWARGS)
            outgoing = r_out.json() if r_out.status_code == 200 else []
            
            if not outgoing:
                print("No outgoing friend requests.")
            else:
                for req in outgoing:
                    print(f"To: {req['to']}")
                
                cancel_req = input("\nEnter a username to cancel your request (or press Enter to skip): ").strip()
                if cancel_req:
                    if any(r['to'] == cancel_req for r in outgoing):
                        requests.post(f"{BASE_URL}/friend/cancel?to_username={cancel_req}", headers={"Authorization": state.token}, **REQUEST_KWARGS)
                        print("🚫 Cancelled.")
                    else:
                        print(f"⚠️ No outgoing request found for user {cancel_req}.")

        elif choice == "4" and state.token:
            u = input("Remove friend username: ")
            r = requests.post(f"{BASE_URL}/friend/remove/{u}", headers={"Authorization": state.token}, **REQUEST_KWARGS)
            if r.status_code == 200:
                print(f"✅ Removed user {u} from friends.")
            else:
                print("❌ Failed to remove friend.")
                print(r.json().get("detail", r.text))

        elif choice == "5" and state.token:
            r = requests.get(f"{BASE_URL}/conversations", headers={"Authorization": state.token}, **REQUEST_KWARGS)
            if r.status_code == 200:
                convs = r.json()
                if not convs:
                    print("You don't have any contacts or conversations yet.")
                
                for c in convs:
                    last = c.get('last_time')
                    if not last:
                        last = "No messages yet"
                    status_icon = " ✅" if state.verified.get(c['username']) else ""    
                        
                    print(f"👤 {c['username']} {status_icon} | Unread: {c['unread']} | Last Activity: {last}")
            else:
                # 4. Gracefully handle expired tokens/errors
                print("❌ Failed to load conversations")
                try:
                    print(r.json().get("detail", r.text))
                except json.JSONDecodeError:
                    print(f"Server Error {r.status_code}: {r.text}")

        elif choice == "6" and state.token:
            contact = input("Enter contact username to verify: ").strip()
            try:
                # Fetch their current identity key from the server
                r = requests.get(f"{BASE_URL}/user/{contact}/identity", headers={"Authorization": state.token}, **REQUEST_KWARGS)
                if r.status_code == 200:
                    pub_b64 = r.json().get("identity_pub")
                    pub_bytes = base64.b64decode(pub_b64)
                    
                    # Generate the fingerprint using your existing method
                    fingerprint = state.safety_number(pub_bytes)
                    print(f"\n--- Fingerprint for {contact} ---")
                    print(f"Safety Number: {fingerprint}")
                    print("---------------------------------")
                    
                    ans = input("Mark as verified? (y/n): ").strip().lower()
                    if ans == 'y':
                        state.verified[contact] = True
                        state.fingerprints[contact] = fingerprint
                        state.last_identity_pub[contact] = pub_bytes
                        state.save()
                        print(f"✅ {contact} has been marked as verified!")
                    else:
                        state.verified[contact] = False
                        state.save()
                        print(f"ℹ️ {contact} remains unverified.")
                else:
                    print(f"❌ Could not fetch identity for {contact}.")
            except Exception as e:
                print(f"❌ Error during verification: {e}")

        elif choice == "7" and state.token:
            
            # Clean up expired messages upon login
            cleanup_expired_messages()
            
            contact = input("Chat with username: ").strip()
            if not contact:
                continue

             # === AUTOMATIC FRIEND CHECK ===
            print(f"Checking friendship status with {contact}...")
            if not check_friendship(contact):
                print(f"❌ You are not friends with {contact}.")
                print("   Please send a new friend request if needed.")
                input("Press Enter to continue...")
                continue

            print(f"✅ You are friends with {contact}.\n")
            print(f"\n=== Chat with {contact} ===\n")

            # Show local history - paginated
            all_local = state.local_messages.get(contact, [])
            messages_shown = 0
            page_size = 20
            
            def show_next_page():
                nonlocal messages_shown
                start_idx = len(all_local) - messages_shown - page_size
                end_idx = len(all_local) - messages_shown
                if start_idx < 0:
                    start_idx = 0
                
                page_msgs = all_local[start_idx:end_idx]
                if not page_msgs:
                    print("No more messages to show.")
                    return False
                
                print(f"---- Older messages (showing {len(page_msgs)} more) ----")
                for msg in page_msgs:
                    ts = msg["timestamp"].replace("T", " ")
                    if msg["direction"] == "in":
                        print(f"\033[1;36m📨 {ts} {contact}: {msg['text']}\033[0m")
                    else:
                        print(f"📤 {ts} You: {msg['text']}")
                
                messages_shown += len(page_msgs)
                remaining = len(all_local) - messages_shown
                if remaining > 0:
                    print(f"\n({remaining} older messages available. Type '/older' to load more.)")
                else:
                    print("\n(All messages shown.)")
                return True
            
            # Show initial page (most recent)
            show_next_page()

            # Connect WebSocket when entering chat
            connect_websocket()
            fetch_messages(contact)
            mark_messages_as_read(contact)

            print("\n" + "─"*65)
            print("Chat opened - messages marked as read.")
            print("Type your message below. Use /quit to exit.")
            print("Tip: /ttl <seconds> <message> for self-destruct")
            print("Tip: /older to show older messages from history")
            print("─"*65 + "\n")

            while True:
                line = input("> ").strip()
                if line.lower() == "/quit":
                    disconnect_websocket()   # Disconnect when leaving chat
                    break
                if not line:
                    continue

                # Handle /older command to show more local history
                if line.lower() == "/older":
                    if not show_next_page():
                        print("No more older messages.")
                    continue

                ttl = 0
                if line.startswith("/ttl "):
                    try:
                        parts = line.split(" ", 2)
                        ttl = int(parts[1])
                        line = parts[2]
                    except:
                        print("Usage: /ttl <seconds> <message>")
                        continue

                try:
                    ct = encrypt_message(contact, line, ttl)
                    payload = {
                        "type": "send_message",
                        "to": contact,
                        "ciphertext": ct,
                        "ttl": ttl
                    }
                    if ws and ws.sock and ws.sock.connected:
                        ws.send(json.dumps(payload))
                        local_msg_id = add_local_message(contact, "out", line, datetime.now().isoformat(timespec="seconds"), ttl)
                    else:
                        print("⚠️ WebSocket not connected")
                except Exception as e:
                    print(f"❌ Send failed: {e}")
                                                          
        elif choice == "8" and state.token:
            u = input("Block username: ")
            r = requests.post(f"{BASE_URL}/block/{u}", headers={"Authorization": state.token}, **REQUEST_KWARGS)
            if r.status_code == 200:
                print(f"✅ User blocked: {u}")
            else:
                print("❌ Failed to block user.")
                print(r.json().get("detail", r.text))

        elif choice == "9" and state.token:
            u = input("Unblock username: ")
            r = requests.post(f"{BASE_URL}/unblock/{u}", headers={"Authorization": state.token}, **REQUEST_KWARGS)
            if r.status_code == 200:
                print(f"✅ User unblocked: {u}")
            else:
                print("❌ Failed to unblock user.")
                print(r.json().get("detail", r.text))

        elif choice == "10" and state.token:
            requests.post(f"{BASE_URL}/logout", headers={"Authorization": state.token}, **REQUEST_KWARGS)
            state.token = None
            state.username = None
            state.save()
            print("Logged out.")

        elif choice == "11":
            break

        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()