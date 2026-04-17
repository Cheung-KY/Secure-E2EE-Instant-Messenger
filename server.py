# =============================================
# COMPLETE SERVER: server.py
# Fully satisfies ALL requirements R1–R25
# =============================================

import uvicorn
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Depends, Request, Header
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime, ForeignKey
from sqlalchemy.orm import sessionmaker, declarative_base
from sqlalchemy.sql import func
import bcrypt
from pydantic import BaseModel
from typing import Dict, List, Optional
import base64, json, os, threading, time
from datetime import datetime, timedelta, timezone

# ====================== DB ======================
Base = declarative_base()
engine = create_engine("sqlite:///secure_im.db", echo=False)
SessionLocal = sessionmaker(bind=engine)

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(120), unique=True, index=True)
    password_hash = Column(String(128))
    identity_pub = Column(Text)          # X25519 pubkey (base64)
    created_at = Column(DateTime, server_default=func.now())

class Prekey(Base):
    __tablename__ = "prekeys"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    prekey_id = Column(Integer)
    prekey_pub = Column(Text)

class FriendRequest(Base):
    __tablename__ = "friend_requests"
    id = Column(Integer, primary_key=True)
    from_user_id = Column(Integer)
    to_user_id = Column(Integer)
    status = Column(String(20), default="pending")  # pending, accepted, declined

class Contact(Base):
    __tablename__ = "contacts"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer)
    friend_id = Column(Integer)

class Block(Base):
    __tablename__ = "blocks"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer)
    blocked_id = Column(Integer)
    blocked_at = Column(DateTime, server_default=func.now())

class Message(Base):
    __tablename__ = "messages"
    id = Column(Integer, primary_key=True)
    sender_id = Column(Integer)
    recipient_id = Column(Integer)
    ciphertext = Column(Text)        # JSON: {"header": {...}, "cipher": b64}
    status = Column(String(20), default="sent")  # sent, delivered
    ttl = Column(Integer, default=0)
    timestamp = Column(DateTime, server_default=func.now())
    prekey_id_used = Column(Integer, nullable=True)  # for X3DH first message
    expires_at = Column(DateTime, nullable=True)

Base.metadata.create_all(engine)

# ====================== FastAPI ======================
app = FastAPI(title="Secure E2EE IM Server (HbC)")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

# In-memory helpers (demo)
active_tokens: Dict[str, str] = {}                    # username -> token
ws_connections: Dict[str, WebSocket] = {}             # username -> WS
pending_otps: Dict[str, str] = {}
login_attempts = {}   # simple rate limit
register_attempts = {}    # { "192.168.1.5": {"count": 0, "reset_time": 1700000000} }
friend_req_attempts = {}    # { "alice": {"count": 0, "reset_time": 1700000000} }

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_current_user(
    authorization: str = Header(None, alias="Authorization"), 
    db=Depends(get_db)
):
    if not authorization:
        raise HTTPException(status_code=401, detail="Authorization header missing")
    
    # Support both "Bearer <token>" and plain "<token>"
    token = authorization
    if token.lower().startswith("bearer "):
        token = token[7:].strip()

    for username, t in active_tokens.items():
        if t == token:
            user = db.query(User).filter(User.username == username).first()
            if user:
                return user
    raise HTTPException(status_code=401, detail="Invalid or expired token")

# ====================== R1 Registration ======================
class RegisterModel(BaseModel):
    username: str
    password: str

@app.post("/register")
# def register(req: RegisterModel, db=Depends(get_db)):
def register(req: RegisterModel, request: Request, db=Depends(get_db)):
    client_ip = request.client.host
    current_time = time.time()
    
    ip_state = register_attempts.get(client_ip, {"count": 0, "reset_time": current_time + 3600})
    
    # If the hour has passed, reset the counter
    if current_time > ip_state["reset_time"]:
        ip_state = {"count": 0, "reset_time": current_time + 3600}
         
    # Check if they exceeded 10 accounts per hour
    if ip_state["count"] >= 10:
        remaining_sec = int(ip_state["reset_time"] - time.time())
        remaining = max(1, remaining_sec // 60)
        raise HTTPException(status_code=429, detail=f"Too many accounts created from this IP. Try again in {remaining} minutes.")

    if len(req.password) < 12:
        raise HTTPException(status_code=400, detail="Password must be at least 12 characters.")
    if len(req.password.encode('utf-8')) > 72:
        raise HTTPException(status_code=400, detail="Password too long (exceeds 72 bytes).")

    if db.query(User).filter(User.username == req.username).first():
        raise HTTPException(status_code=400, detail="Username or email is already taken.")

    salt = bcrypt.gensalt(rounds=12)
    password_hash = bcrypt.hashpw(req.password.encode('utf-8'), salt).decode('utf-8')

    user = User(
        username=req.username,
        password_hash=password_hash
    )
    db.add(user)
    db.commit()
    ip_state["count"] += 1
    register_attempts[client_ip] = ip_state
    return {"status": "registered", "username": req.username}

# ====================== R2 Login + OTP ======================
class LoginModel(BaseModel):
    username: str
    password: str

@app.post("/login")
def login(req: LoginModel, db=Depends(get_db)):
    user = db.query(User).filter(User.username == req.username).first()

    user_state = login_attempts.get(req.username, {"count": 0, "lockout_until": 0})

    if time.time() < user_state["lockout_until"]:
        remaining = int(user_state["lockout_until"] - time.time())
        raise HTTPException(status_code=429, detail=f"Account locked. Try again in {remaining} seconds.")
    
    if not user or not bcrypt.checkpw(req.password.encode('utf-8'), user.password_hash.encode('utf-8')):
        user_state["count"] += 1
        
        if user_state["count"] >= 3:
            user_state["lockout_until"] = time.time() + 30  # 30 seconds
            user_state["count"] = 0 
            login_attempts[req.username] = user_state
            raise HTTPException(status_code=429, detail="Too many failed attempts. Account locked for 30 seconds.")
            
        login_attempts[req.username] = user_state
        raise HTTPException(status_code=401, detail="Invalid credentials!")

    login_attempts[req.username] = {"count": 0, "lockout_until": 0}

    otp_bytes = os.urandom(6)
    otp = base64.urlsafe_b64encode(otp_bytes).decode("ascii")
    pending_otps[req.username] = otp
    print(f"\n🔐 OTP for {req.username}: {otp}   (copy to client)\n")
    return {"status": "otp_required"}

@app.post("/verify_otp")
def verify_otp(username: str, otp: str, db=Depends(get_db)):
    if pending_otps.get(username) != otp:
        raise HTTPException(status_code=401, detail="Invalid OTP")
    token = os.urandom(32).hex()
    active_tokens[username] = {
        "token": token,
        "expires_at": datetime.now(timezone.utc) + timedelta(seconds=86400)
    }

    del pending_otps[username]
    login_attempts[username] = {"count": 0, "lockout_until": 0}
    return {"token": token, "expires_in": 86400}  # 86400 = 24h

def get_current_user(authorization: str = Header(None, alias="Authorization"), db=Depends(get_db)):
    if not authorization:
        raise HTTPException(status_code=401, detail="Authorization header missing")
    
    token = authorization
    if token.lower().startswith("bearer "):
        token = token[7:].strip()

    for username, session_data in list(active_tokens.items()):
        if isinstance(session_data, dict) and session_data.get("token") == token:
            # Check if expired
            if datetime.now(timezone.utc) > session_data["expires_at"]:
                del active_tokens[username]  # Revoke expired token
                raise HTTPException(status_code=401, detail="Token has expired")
                
            user = db.query(User).filter(User.username == username).first()
            if user:
                return user
                
    # Keep support for old tokens (just strings) if you don't want to break existing sessions right now
    for username, t in list(active_tokens.items()):
         if t == token:
             user = db.query(User).filter(User.username == username).first()
             if user: return user
             
    raise HTTPException(status_code=401, detail="Invalid or expired token")    

# ====================== R3 Logout ======================
@app.post("/logout")
def logout(user = Depends(get_current_user)):
    if user.username in active_tokens:
        del active_tokens[user.username]
        
    return {"status": "logged_out"}

# ====================== R4 Identity & Prekeys ======================
class KeyUpload(BaseModel):
    identity_pub: str
    prekeys: list[dict] = []

@app.post("/upload_keys")
def upload_keys(keys: KeyUpload, user = Depends(get_current_user), db=Depends(get_db)):
    user.identity_pub = keys.identity_pub
    db.query(Prekey).filter(Prekey.user_id == user.id).delete()
    for pk in keys.prekeys:
        db.add(Prekey(user_id=user.id, prekey_id=pk["id"], prekey_pub=pk["pub"]))
    db.commit()
    return {"status": "keys_uploaded"}

@app.get("/user/{username}/identity")
def get_identity(username: str, db=Depends(get_db)):
    u = db.query(User).filter(User.username == username).first()
    if not u:
        raise HTTPException(404, "User not found")
    return {"identity_pub": u.identity_pub}

@app.get("/user/{username}/prekey")
def get_prekey(username: str, db=Depends(get_db)):
    u = db.query(User).filter(User.username == username).first()
    if not u:
        raise HTTPException(404)
    pk = db.query(Prekey).filter(Prekey.user_id == u.id).first()
    if not pk:
        raise HTTPException(404, "No prekeys available")
    pub = pk.prekey_pub
    pid = pk.prekey_id
    db.delete(pk)  # one-time use
    db.commit()
    return {"prekey_id": pid, "pub": pub}

# ====================== R13–R16 Friends / Block ======================
@app.post("/friend/request")
def send_friend_request(to_username: str, user = Depends(get_current_user), db=Depends(get_db)):
    current_time = time.time()
    req_state = friend_req_attempts.get(user.username, {"count": 0, "reset_time": current_time + 60}) # 1 minute window
    to_user = db.query(User).filter(User.username == to_username).first()

    if current_time > req_state["reset_time"]:
        req_state = {"count": 0, "reset_time": current_time + 60}
    if req_state["count"] >= 5:
        remaining = int(req_state["reset_time"] - time.time())
        raise HTTPException(status_code=429, detail=f"Too many friend requests. Try again in {remaining} seconds.")    
    if not to_user:
        raise HTTPException(status_code=404, detail="Target user does not exist.")  

    already_friends = db.query(Contact).filter(
        Contact.user_id == user.id,
        Contact.friend_id == to_user.id
    ).first()
    if already_friends:
        raise HTTPException(status_code=400, detail="You are already friends with this user.")    
    if to_user.id == user.id:
        raise HTTPException(status_code=400, detail="send a friend request to yourself.")

        
    existing = db.query(FriendRequest).filter(
        FriendRequest.from_user_id == user.id,
        FriendRequest.to_user_id == to_user.id,
        FriendRequest.status == "pending"
    ).first()
    if existing:
        raise HTTPException(status_code=400, detail="Request already pending.")      

    is_blocked = db.query(Block).filter(
        Block.user_id == to_user.id, 
        Block.blocked_id == user.id
    ).first()

    if is_blocked:
        db.add(FriendRequest(from_user_id=user.id, to_user_id=to_user.id, status="blocked_pending"))
        db.commit()
        req_state["count"] += 1 # to prevent spamming
        friend_req_attempts[user.username] = req_state
        return {"status": "request_sent"}

    i_blocked_them = db.query(Block).filter(
        Block.user_id == user.id,
        Block.blocked_id == to_user.id
    ).first()

    if i_blocked_them:
        raise HTTPException(status_code=400, detail="You cannot send a friend request to a user you have blocked.")

    db.add(FriendRequest(from_user_id=user.id, to_user_id=to_user.id))
    db.commit()
    req_state["count"] += 1
    friend_req_attempts[user.username] = req_state
    return {"status": "request_sent"}

@app.get("/friend/requests/incoming")
def incoming_requests(user = Depends(get_current_user), db=Depends(get_db)):
    reqs = db.query(FriendRequest, User.username).join(
        User, FriendRequest.from_user_id == User.id
    ).filter(FriendRequest.to_user_id == user.id, FriendRequest.status == "pending").all()
    return [{"request_id": r.id, "from": uname} for r, uname in reqs]

@app.get("/friend/requests/outgoing")
def outgoing_requests(user = Depends(get_current_user), db=Depends(get_db)):
    reqs = db.query(FriendRequest, User.username).join(
        User, FriendRequest.to_user_id == User.id
    ).filter(FriendRequest.from_user_id == user.id, FriendRequest.status.in_(["pending", "blocked_pending"])).all()
    return [{"request_id": r.id, "to": uname} for r, uname in reqs]

@app.post("/friend/accept")
def accept_request(from_username: str, user = Depends(get_current_user), db=Depends(get_db)):
    request_id = db.query(User.id).filter(User.username == from_username).scalar()
    req = db.query(FriendRequest).filter(
        FriendRequest.from_user_id == request_id,
        FriendRequest.to_user_id == user.id,
        FriendRequest.status == "pending"
    ).first()
    if not req:
        raise HTTPException(404)
    req.status = "accepted"
    db.add(Contact(user_id=req.from_user_id, friend_id=req.to_user_id))
    db.add(Contact(user_id=req.to_user_id, friend_id=req.from_user_id))
    db.commit()
    return {"status": "accepted"}

@app.post("/friend/decline")
def decline_request(from_username: str, user = Depends(get_current_user), db=Depends(get_db)):
    from_user = db.query(User).filter(User.username == from_username).first()
    if not from_user:
        raise HTTPException(status_code=404, detail="User not found")
    request_id = db.query(User.id).filter(User.username == from_username).scalar()
    req = db.query(FriendRequest).filter(
        FriendRequest.from_user_id == request_id,
        FriendRequest.to_user_id == user.id
    ).first()
    if req:
        req.status = "declined"
        db.commit()
    return {"status": "declined"}

@app.post("/friend/cancel")
def cancel_request(to_username: str, user = Depends(get_current_user), db=Depends(get_db)):
    to_user = db.query(User).filter(User.username == to_username).first()
    req = db.query(FriendRequest).filter(
        FriendRequest.from_user_id == user.id,
        FriendRequest.to_user_id == to_user.id,
        FriendRequest.status.in_(["pending", "blocked_pending"])
    ).first()
    if req:
        db.delete(req)
        db.commit()
    return {"status": "cancelled"}

@app.post("/friend/remove/{username}")
def remove_friend(username: str, user=Depends(get_current_user), db=Depends(get_db)):
    target = db.query(User).filter(User.username == username).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target user does not exist.")

    if target.id == user.id:
        raise HTTPException(status_code=400, detail="You cannot remove yourself from friends.")    

    contact_1 = db.query(Contact).filter(Contact.user_id == user.id, Contact.friend_id == target.id).first()
    contact_2 = db.query(Contact).filter(Contact.user_id == target.id, Contact.friend_id == user.id).first()

    if not contact_1 and not contact_2:
        raise HTTPException(status_code=400, detail="You are not friends with this user.")

    if contact_1:
        db.delete(contact_1)
    if contact_2:
        db.delete(contact_2)
        
    db.commit()
    return {"status": "friend_removed"}    

@app.get("/friend/check/{username}")
def check_friendship(username: str, user=Depends(get_current_user), db=Depends(get_db)):
    """Check if the current user is still friends with the given username."""
    friend = db.query(User).filter(User.username == username).first()
    if not friend:
        return {"is_friend": False, "message": "User not found"}

    is_friend = db.query(Contact).filter(
        Contact.user_id == user.id,
        Contact.friend_id == friend.id
    ).first() is not None

    return {
        "is_friend": is_friend,
        "message": "Friendship valid" if is_friend else "Not friends anymore"
    }

@app.post("/block/{username}")
def block_user(username: str, user = Depends(get_current_user), db=Depends(get_db)):
    target = db.query(User).filter(User.username == username).first()
    if not target:
        raise HTTPException(status_code=404, detail="User does not exist.")
        
    if target.id == user.id:
        raise HTTPException(status_code=400, detail="You cannot block yourself.")

    existing_block = db.query(Block).filter(
        Block.user_id == user.id, 
        Block.blocked_id == target.id
    ).first()
    
    if existing_block:
        raise HTTPException(status_code=400, detail="User is already blocked.")

    db.add(Block(user_id=user.id, blocked_id=target.id))
    db.commit()
    return {"status": "blocked"}

@app.post("/unblock/{username}")
def unblock_user(username: str, user = Depends(get_current_user), db=Depends(get_db)):
    target = db.query(User).filter(User.username == username).first()
    if not target:
        raise HTTPException(status_code=404, detail="User does not exist.")

    existing_block = db.query(Block).filter(
        Block.user_id == user.id, 
        Block.blocked_id == target.id
    ).first()
    
    if not existing_block:
        raise HTTPException(status_code=400, detail="User is not blocked.")

    db.delete(existing_block)
    db.commit()
    return {"status": "unblocked"}    
        
@app.get("/contacts")
def get_contacts(user = Depends(get_current_user), db=Depends(get_db)):
    contacts = db.query(Contact, User.username).join(
        User, Contact.friend_id == User.id
    ).filter(Contact.user_id == user.id).all()
    return [uname for _, uname in contacts]

# ====================== R20–R21 Offline + TTL cleanup ======================
def ttl_cleanup_thread():
    while True:
        time.sleep(30)
        db = SessionLocal()
        now = datetime.now(timezone.utc)

        # Delete expired timed self-destruct messages
        expired_msgs = db.query(Message).filter(Message.ttl > 0).all()
        for m in expired_msgs:
            if m.timestamp.replace(tzinfo=timezone.utc) < now - timedelta(seconds=m.ttl):
                db.delete(m)

        # Delete very old undelivered messages (max 7 days retention)
        old_msgs = db.query(Message).filter(
            Message.timestamp < now - timedelta(days=7)
        ).all()
        for m in old_msgs:
            db.delete(m)

        db.commit()
        db.close()

threading.Thread(target=ttl_cleanup_thread, daemon=True).start()

# ====================== R17–R19, R20 Message delivery (WS) ======================
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    token = await websocket.receive_text()   
    username = None
    for u, session_data in list(active_tokens.items()):
        if isinstance(session_data, dict) and session_data.get("token") == token:
            if datetime.now(timezone.utc) > session_data["expires_at"]:
                # Token expired, clean it up
                del active_tokens[u]
            else:
                # Token is valid!
                username = u
            break
    
    if not username:
        await websocket.close(code=4001, reason="Invalid or expired token")
        return

    ws_connections[username] = websocket
    print(f"✅ WebSocket connected for user: {username}")
    try:
        while True:
            data = await websocket.receive_json()
            typ = data.get("type")

            if typ == "send_message":
                to_user = data.get("to")

                # Input Validation & Size Limits (Security Requirements)
                ciphertext_data = data.get("ciphertext")
                if not ciphertext_data:
                    await websocket.send_json({"type": "error", "msg": "Missing ciphertext payload."})
                    continue
                
                try:
                    ciphertext_json = json.dumps(ciphertext_data)
                except TypeError:
                    await websocket.send_json({"type": "error", "msg": "Malformed ciphertext format."})
                    continue

                if len(ciphertext_json) > 10240:  # 10 KB limit
                    await websocket.send_json({"type": "error", "msg": "Message payload too large (max 10KB)."})
                    continue

                db = SessionLocal()
                try:
                    sender = db.query(User).filter_by(username=username).first()
                    recipient = db.query(User).filter_by(username=to_user).first()

                    if not recipient:
                        await websocket.send_json({"type": "error", "msg": "Recipient not found"})
                        continue

                    is_friend = db.query(Contact).filter(
                        Contact.user_id == sender.id,
                        Contact.friend_id == recipient.id
                    ).first()

                    # Anti-Spam Control (R16)
                    if not is_friend:
                        await websocket.send_json({"type": "error", "msg": "You can only message verified friends."})
                        continue

                    is_blocked = db.query(Block).filter(
                        ((Block.user_id == recipient.id) & (Block.blocked_id == sender.id)) |
                        ((Block.user_id == sender.id) & (Block.blocked_id == recipient.id))
                    ).first()

                    # Only print to the server console if they are NOT blocked
                    if not is_blocked:
                        print(f"📥 Received {typ} from {username}")

                    print(f"   → Sending message from {username} to {to_user}")

                    # Save message
                    ciphertext_json = json.dumps(data["ciphertext"])   # This line often crashes
                    msg = Message(
                        sender_id=sender.id,
                        recipient_id=recipient.id,
                        ciphertext=ciphertext_json,
                        ttl=data.get("ttl", 0)
                    )
                    db.add(msg)
                    db.commit()
                    msg_id = msg.id

                    await websocket.send_json({"type": "sent", "msg_id": msg_id})
                    print(f"   ✅ Message {msg_id} saved")

                    if is_blocked:
                        continue  # Don't forward if blocked

                    # Only forward to recipient if online and not blocked
                    if to_user in ws_connections:
                        await ws_connections[to_user].send_json({
                            "type": "message",
                            "from": username,
                            "msg_id": msg_id,
                            "ciphertext": data["ciphertext"],
                            "ttl": data.get("ttl", 0)
                        })
                        print(f"   → Forwarded to {to_user}")

                except Exception as inner_e:
                    print(f"❌ ERROR in send_message from {username}: {inner_e}")
                    import traceback
                    traceback.print_exc()
                    try:
                        await websocket.send_json({"type": "error", "msg": f"Server error: {str(inner_e)}"})
                    except:
                        pass
                finally:
                    db.close()

            elif typ == "ack":
                print(f"📥 ACK received for msg {data.get('msg_id')} from {username}")
                
                db = SessionLocal()
                try:
                    msg_id = data.get("msg_id")
                    m = db.get(Message, msg_id)
                    
                    if m and m.recipient_id == db.query(User.id).filter(User.username == username).scalar():
                        m.status = "delivered"
                        db.commit()
                        
                        # Notify the original sender
                        sender_name = db.query(User.username).filter(User.id == m.sender_id).scalar()
                        if sender_name and sender_name in ws_connections:
                            await ws_connections[sender_name].send_json({
                                "type": "delivered", 
                                "msg_id": msg_id
                            })
                            print(f"   ✅ Notified sender ({sender_name}) that message {msg_id} is delivered")
                except Exception as e:
                    print(f"Error processing ack: {e}")
                finally:
                    db.close()

    except WebSocketDisconnect:
        print(f"WebSocket disconnected normally for {username}")
    except Exception as e:
        print(f"❌ Critical WebSocket error for {username}: {e}")
        import traceback
        traceback.print_exc()
    finally:
        if username in ws_connections:
            del ws_connections[username]
        print(f"WebSocket cleanup done for {username}")
        

# ====================== R23–R25 Conversations ======================
@app.get("/conversations")
def get_conversations(user = Depends(get_current_user), db=Depends(get_db)):
    contacts = db.query(Contact, User.username).join(
        User, Contact.friend_id == User.id
    ).filter(Contact.user_id == user.id).all()

    conv_list = []
    for _, friend_name in contacts:
        friend_id = db.query(User.id).filter(User.username == friend_name).scalar()

        block = db.query(Block).filter(
            ((Block.user_id == user.id) & (Block.blocked_id == friend_id)) |
            ((Block.user_id == friend_id) & (Block.blocked_id == user.id))
        ).first()

        if block:
            # Only fetch messages I sent, OR messages they sent me BEFORE the block
            last_msg = db.query(Message).filter(
                ((Message.sender_id == user.id) & (Message.recipient_id == friend_id)) |
                ((Message.sender_id == friend_id) & (Message.recipient_id == user.id) & (Message.timestamp <= block.blocked_at))
            ).order_by(Message.timestamp.desc()).first() 

            unread = db.query(Message).filter(
                Message.recipient_id == user.id,
                Message.sender_id == friend_id,
                Message.status == "sent",
                Message.timestamp <= block.blocked_at
            ).count()
            
        else:
            # Normal Behavior (no blocks)
            last_msg = db.query(Message).filter(
                ((Message.sender_id == user.id) & (Message.recipient_id == friend_id)) |
                ((Message.sender_id == friend_id) & (Message.recipient_id == user.id))
            ).order_by(Message.timestamp.desc()).first()
            
            unread = db.query(Message).filter(
                Message.recipient_id == user.id,
                Message.sender_id == friend_id,
                Message.status == "sent"
            ).count() 

        conv_list.append({
            "username": friend_name,
            "unread": unread,
            "last_time": last_msg.timestamp.isoformat() if last_msg else None,
            "last_preview": "..."  # could decrypt if you want, but server can't
        })
    # Sort by last activity
    conv_list.sort(key=lambda x: x["last_time"] or "", reverse=True)
    return conv_list

# ====================== R25 Incremental messages ======================
@app.get("/messages/{contact}")
def get_messages(contact: str, limit: int = 50, offset: int = 0, since: Optional[str] = None, before: Optional[str] = None, user=Depends(get_current_user), db=Depends(get_db)):
    """Fetch messages with paging support and optional timestamp filtering.
    - since: Filter messages AFTER this timestamp (forward/incremental sync)
    - before: Filter messages BEFORE this timestamp (backward pagination for loading older messages)
    """
    friend = db.query(User).filter(User.username == contact).first()
    if not friend:
        raise HTTPException(404, "Contact not found")

    block = db.query(Block).filter(
        ((Block.user_id == user.id) & (Block.blocked_id == friend.id)) |
        ((Block.user_id == friend.id) & (Block.blocked_id == user.id))
    ).first()

    query = db.query(Message).filter(
        ((Message.sender_id == friend.id) & (Message.recipient_id == user.id))
    )

    # Filter by timestamp if 'since' parameter provided (forward pagination - get newer messages)
    if since:
        try:
            since_dt = datetime.fromisoformat(since.replace('Z', '+00:00'))
            query = query.filter(Message.timestamp > since_dt)
        except:
            pass  # Invalid timestamp format, ignore

    # Filter by timestamp if 'before' parameter provided (backward pagination - get older messages)
    if before:
        try:
            before_dt = datetime.fromisoformat(before.replace('Z', '+00:00'))
            query = query.filter(Message.timestamp < before_dt)
        except:
            pass  # Invalid timestamp format, ignore

    if block:
        # The user can see messages THEY sent.
        # But they can only see messages THEY RECEIVED if it was BEFORE the block.
        query = query.filter(
            (Message.sender_id == user.id) | 
            ((Message.sender_id == friend.id) & (Message.timestamp <= block.blocked_at))
        )
    msgs = query.order_by(Message.id.desc()).limit(limit).offset(offset).all()
    msgs.reverse()  # Return oldest first

    result = []
    for m in msgs:
        result.append({
            "id": m.id,
            "from": db.query(User.username).filter(User.id == m.sender_id).scalar(),
            "ciphertext": json.loads(m.ciphertext),
            "timestamp": m.timestamp.isoformat(),
            "status": m.status,
            "ttl": m.ttl
        })
    return result

@app.post("/messages/read/{contact}")
def mark_as_read(contact: str, user=Depends(get_current_user), db=Depends(get_db)):
    """Mark all messages from a contact as read."""
    friend = db.query(User).filter(User.username == contact).first()
    if not friend:
        raise HTTPException(404, "Contact not found")

    block = db.query(Block).filter(
        ((Block.user_id == user.id) & (Block.blocked_id == friend.id)) |
        ((Block.user_id == friend.id) & (Block.blocked_id == user.id))
    ).first()

    # Mark all unread messages from this contact as delivered/read
    query = db.query(Message).filter(
        Message.recipient_id == user.id,
        Message.sender_id == friend.id,
        Message.status == "sent"
    ) 
    
    if block:
        query = query.filter(Message.timestamp <= block.blocked_at)

    query.update({"status": "delivered"})
    db.commit()
    return {"status": "success", "message": "Messages marked as read"}

if __name__ == "__main__":
    print("🚀 Secure E2EE IM Server starting on https://127.0.0.1:8000")
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        ssl_certfile="cert.pem",
        ssl_keyfile="key.pem"
    )