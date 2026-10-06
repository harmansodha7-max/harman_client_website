import os
from datetime import datetime, timedelta, timezone
from typing import Dict, List

from authlib.integrations.starlette_client import OAuth
from fastapi import FastAPI, HTTPException, Request, status
from fastapi.responses import RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from email.message import EmailMessage
import smtplib
import uuid
from pydantic import BaseModel, EmailStr, Field
from pwdlib import PasswordHash
from jose import JWTError, jwt
from starlette.middleware.sessions import SessionMiddleware

app = FastAPI(title="Harman Profile Backend", version="1.1.0")

# Demo-only in-memory storage: no database and no disk persistence.
users: Dict[str, dict] = {}
password_hash = PasswordHash.recommended()

auth_secret = os.getenv("SESSION_SECRET", "CHANGE_THIS_SESSION_SECRET")
jwt_secret = os.getenv("JWT_SECRET", "CHANGE_THIS_JWT_SECRET")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:8000")

app.add_middleware(SessionMiddleware, secret_key=auth_secret, https_only=False)
app.add_middleware(CORSMiddleware, allow_origins=[FRONTEND_URL, "http://localhost:5500", "http://127.0.0.1:5500"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

oauth = OAuth()

oauth.register(
    name="google",
    client_id=os.getenv("GOOGLE_CLIENT_ID"),
    client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_kwargs={"scope": "openid email profile"},
)
oauth.register(
    name="github",
    client_id=os.getenv("GITHUB_CLIENT_ID"),
    client_secret=os.getenv("GITHUB_CLIENT_SECRET"),
    access_token_url="https://github.com/login/oauth/access_token",
    authorize_url="https://github.com/login/oauth/authorize",
    api_base_url="https://api.github.com/",
    client_kwargs={"scope": "read:user user:email"},
)
oauth.register(
    name="facebook",
    client_id=os.getenv("FACEBOOK_CLIENT_ID"),
    client_secret=os.getenv("FACEBOOK_CLIENT_SECRET"),
    access_token_url="https://graph.facebook.com/v20.0/oauth/access_token",
    authorize_url="https://www.facebook.com/v20.0/dialog/oauth",
    api_base_url="https://graph.facebook.com/v20.0/",
    client_kwargs={"scope": "email,public_profile"},
)


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


def create_access_token(email: str) -> str:
    expires = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {"sub": email, "exp": expires}
    return jwt.encode(payload, jwt_secret, algorithm=ALGORITHM)


def oauth_ready(provider: str) -> bool:
    prefix = provider.upper()
    return bool(os.getenv(f"{prefix}_CLIENT_ID") and os.getenv(f"{prefix}_CLIENT_SECRET"))


def save_oauth_user(email: str, provider: str, name: str | None = None):
    email = email.lower()
    if email not in users:
        users[email] = {
            "email": email,
            "password_hash": None,
            "provider": provider,
            "name": name,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
    else:
        users[email]["provider"] = provider
        if name:
            users[email]["name"] = name
    return users[email]


@app.get("/")
def health_check():
    return {"status": "ok", "service": "Harman Profile Backend"}


@app.post("/auth/register", status_code=status.HTTP_201_CREATED)
def register(data: RegisterRequest):
    email = data.email.lower()
    if email in users:
        raise HTTPException(status_code=409, detail="User already exists")
    users[email] = {
        "email": email,
        "password_hash": password_hash.hash(data.password),
        "provider": "password",
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    return {"message": "User registered successfully"}


@app.post("/auth/login", response_model=TokenResponse)
def login(data: LoginRequest):
    email = data.email.lower()
    user = users.get(email)
    if not user or not user.get("password_hash") or not password_hash.verify(data.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    return TokenResponse(access_token=create_access_token(email))


@app.get("/auth/{provider}")
async def oauth_login(provider: str, request: Request):
    if provider not in {"google", "github", "facebook"}:
        raise HTTPException(status_code=404, detail="Unsupported OAuth provider")
    if not oauth_ready(provider):
        raise HTTPException(
            status_code=503,
            detail=f"{provider.title()} OAuth is not configured. Add {provider.upper()}_CLIENT_ID and {provider.upper()}_CLIENT_SECRET.",
        )
    client = oauth.create_client(provider)
    redirect_uri = request.url_for("oauth_callback", provider=provider)
    return await client.authorize_redirect(request, redirect_uri)


@app.get("/auth/{provider}/callback", name="oauth_callback")
async def oauth_callback(provider: str, request: Request):
    if provider not in {"google", "github", "facebook"}:
        raise HTTPException(status_code=404, detail="Unsupported OAuth provider")
    client = oauth.create_client(provider)
    token = await client.authorize_access_token(request)

    if provider == "google":
        userinfo = token.get("userinfo") or await client.userinfo(token=token)
        email = userinfo.get("email")
        name = userinfo.get("name")
    elif provider == "github":
        profile = (await client.get("user", token=token)).json()
        email = profile.get("email")
        if not email:
            emails = (await client.get("user/emails", token=token)).json()
            primary = next((item for item in emails if item.get("primary")), emails[0] if emails else {})
            email = primary.get("email")
        name = profile.get("name") or profile.get("login")
    else:
        profile = (await client.get("me?fields=id,name,email", token=token)).json()
        email = profile.get("email")
        name = profile.get("name")

    if not email:
        raise HTTPException(status_code=400, detail="OAuth provider did not return an email address")

    save_oauth_user(email, provider, name)
    access_token = create_access_token(email)

    response = RedirectResponse(url=f"{FRONTEND_URL.rstrip('/')}/build.html?oauth=success")
    response.set_cookie(
        "access_token",
        access_token,
        httponly=True,
        secure=os.getenv("COOKIE_SECURE", "false").lower() == "true",
        samesite="lax",
        max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )
    return response


@app.get("/auth/me")
def me(request: Request, token: str | None = None):
    token = token or request.cookies.get("access_token")
    if not token:
        raise HTTPException(status_code=401, detail="Authentication required")
    try:
        payload = jwt.decode(token, jwt_secret, algorithms=[ALGORITHM])
        email = payload.get("sub")
        if not email or email not in users:
            raise HTTPException(status_code=401, detail="Invalid token")
        return {"email": email, "user": users[email]}
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")


book_requests: Dict[str, dict] = {}

class BookRequest(BaseModel):
    name: str = Field(min_length=1, max_length=160)
    email: EmailStr
    request_type: str = Field(default="Project", max_length=80)
    requirements: str = Field(min_length=1)

def send_book_notification(item: dict):
    host=os.getenv("SMTP_HOST")
    port=int(os.getenv("SMTP_PORT", "587"))
    username=os.getenv("SMTP_USERNAME")
    password=os.getenv("SMTP_PASSWORD")
    recipient=os.getenv("BOOK_NOTIFICATION_EMAIL", "Harmansodha7@gmail.com")
    if not all([host, username, password]):
        return False
    msg=EmailMessage()
    msg["Subject"]=f"New Book Request — {item['request_type']}"
    msg["From"]=username
    msg["To"]=recipient
    msg.set_content(f"New request from {item['name']} ({item['email']})\n\nType: {item['request_type']}\n\nRequirements:\n{item['requirements']}\n\nContact number: 8691953809")
    with smtplib.SMTP(host, port, timeout=20) as server:
        server.starttls()
        server.login(username, password)
        server.send_message(msg)
    return True

@app.post("/book/requests", status_code=status.HTTP_201_CREATED)
def create_book_request(data: BookRequest):
    item={"id": str(uuid.uuid4()), **data.model_dump(), "created_at": datetime.now(timezone.utc).isoformat(), "updated_at": datetime.now(timezone.utc).isoformat()}
    book_requests[item["id"]]=item
    try: send_book_notification(item)
    except Exception: pass
    return item

@app.put("/book/requests/{request_id}")
def update_book_request(request_id: str, data: BookRequest):
    if request_id not in book_requests: raise HTTPException(status_code=404, detail="Request not found")
    item={**book_requests[request_id], **data.model_dump(), "updated_at": datetime.now(timezone.utc).isoformat()}
    book_requests[request_id]=item
    return item

@app.get("/book/requests/{request_id}")
def get_book_request(request_id: str):
    if request_id not in book_requests: raise HTTPException(status_code=404, detail="Request not found")
    return book_requests[request_id]

@app.delete("/book/requests/{request_id}")
def delete_book_request(request_id: str):
    if request_id not in book_requests: raise HTTPException(status_code=404, detail="Request not found")
    del book_requests[request_id]
    return {"message":"Request deleted"}
