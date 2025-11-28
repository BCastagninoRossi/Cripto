from fastapi import FastAPI, Depends, HTTPException, Request, Response, status, Cookie
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr, constr
from typing import Optional, Dict, Any
from uuid import uuid4, UUID
from datetime import datetime, timedelta, timezone
import secrets
import hmac
import hashlib
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from argon2 import PasswordHasher
import bcrypt

app = FastAPI(title="Mock Secure Login System")

# =========================
# CONFIGURACIÓN BÁSICA
# =========================

SECRET_KEY = "CHANGE_THIS_SECRET_KEY_FOR_REAL_USE"
EMAIL_HMAC_KEY = b"another-server-side-secret-for-email-hmac"
EMAIL_TOKEN_SALT = "email-verification-salt"

EMAIL_TOKEN_TTL_SECONDS = 15 * 60       # 15 minutos
LOGIN_OTP_TTL_SECONDS = 10 * 60        # 10 minutos
RESET_TOKEN_TTL_SECONDS = 15 * 60      # 15 minutos
SESSION_TTL_SECONDS = 60 * 60          # 1 hora

serializer = URLSafeTimedSerializer(SECRET_KEY)
password_hasher = PasswordHasher()  # Argon2id

# =========================
# "BASE DE DATOS" EN MEMORIA
# =========================

users: Dict[UUID, Dict[str, Any]] = {}
sessions: Dict[str, Dict[str, Any]] = {}
otp_codes: Dict[UUID, Dict[str, Any]] = {}          # OTP asociados a user_id
password_reset_sessions: Dict[str, Dict[str, Any]] = {}  # reset_token -> info
email_verifications: Dict[str, Dict[str, Any]] = {}  # token_id -> info
audit_logs: list[Dict[str, Any]] = []

# =========================
# MODELOS Pydantic
# =========================

class RegisterRequest(BaseModel):
    username: constr(min_length=3, max_length=30)
    email: EmailStr
    password: constr(min_length=8, max_length=64)


class LoginRequest(BaseModel):
    identifier: str  # username o email
    password: str


class VerifyOtpRequest(BaseModel):
    identifier: str
    code: str


class PasswordResetRequest(BaseModel):
    email: EmailStr


class PasswordResetVerifyRequest(BaseModel):
    email: EmailStr
    code: str


class PasswordResetCompleteRequest(BaseModel):
    reset_token: str
    new_password: constr(min_length=8, max_length=64)


# =========================
# FUNCIONES AUXILIARES
# =========================

def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def normalize_email(email: str) -> str:
    return email.strip().lower()


def email_blind_index(email: str) -> str:
    normalized = normalize_email(email)
    return hmac.new(EMAIL_HMAC_KEY, normalized.encode("utf-8"), hashlib.sha256).hexdigest()


def hash_password(password: str) -> str:
    return password_hasher.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return password_hasher.verify(password_hash, password)
    except Exception:
        return False


def hash_with_bcrypt(value: str) -> str:
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(value.encode("utf-8"), salt).decode("utf-8")


def verify_with_bcrypt(value: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(value.encode("utf-8"), hashed.encode("utf-8"))
    except Exception:
        return False


def log_event(event_type: str, user_id: Optional[UUID], request: Optional[Request], details: Dict[str, Any] = None):
    details = details or {}
    ip = request.client.host if request else None
    ua = request.headers.get("user-agent") if request else None
    audit_logs.append(
        {
            "id": len(audit_logs) + 1,
            "user_id": str(user_id) if user_id else None,
            "event_type": event_type,
            "ip_address": ip,
            "user_agent": ua,
            "details": details,
            "created_at": now_utc().isoformat(),
        }
    )


def find_user_by_username_or_email(identifier: str) -> Optional[UUID]:
    identifier_norm = identifier.strip().lower()

    # Buscar por username
    for uid, data in users.items():
        if data["username"].lower() == identifier_norm:
            return uid

    # Buscar por email_blind_index
    blind = email_blind_index(identifier_norm)
    for uid, data in users.items():
        if data["email_blind_index"] == blind:
            return uid

    return None


def create_session(user_id: UUID, request: Request) -> str:
    session_token = secrets.token_urlsafe(32)
    now = now_utc()
    sessions[session_token] = {
        "user_id": user_id,
        "ip_address": request.client.host,
        "user_agent": request.headers.get("user-agent"),
        "expires_at": now + timedelta(seconds=SESSION_TTL_SECONDS),
        "last_activity": now,
    }
    log_event("LOGIN_SESSION_CREATED", user_id, request, {"session_token": session_token})
    return session_token


async def get_current_user(request: Request, session_id: Optional[str] = Cookie(default=None, alias="session_id")) -> Dict[str, Any]:
    if not session_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")

    session = sessions.get(session_id)
    if not session:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid session")

    if session["expires_at"] < now_utc():
        # Expirada
        sessions.pop(session_id, None)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session expired")

    # Actualizamos actividad
    session["last_activity"] = now_utc()
    user = users.get(session["user_id"])
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")

    return {"session_id": session_id, "user_id": session["user_id"], "user": user}


# =========================
# ENDPOINTS
# =========================

@app.post("/register")
def register(data: RegisterRequest, request: Request):
    # Validación simple de username (solo letras, números, _, -, .)
    import re
    if not re.fullmatch(r"[A-Za-z0-9_.-]{3,30}", data.username):
        raise HTTPException(status_code=400, detail="Invalid username format")

    # Chequear unicidad de username y email
    blind = email_blind_index(data.email)
    for u in users.values():
        if u["username"].lower() == data.username.lower():
            raise HTTPException(status_code=400, detail="Registration failed")
        if u["email_blind_index"] == blind:
            raise HTTPException(status_code=400, detail="Registration failed")

    user_id = uuid4()
    user = {
        "id": user_id,
        "username": data.username,
        "email_encrypted": f"ENCRYPTED::{normalize_email(data.email)}",  # Placeholder
        "email_blind_index": blind,
        "password_hash": hash_password(data.password),
        "status": "PENDING",
        "failed_login_attempts": 0,
        "locked_until": None,
        "created_at": now_utc(),
        "last_login_at": None,
    }
    users[user_id] = user

    # Crear token de verificación de email (magic link)
    token_id = str(uuid4())
    token = serializer.dumps(
        {"user_id": str(user_id), "token_id": token_id},
        salt=EMAIL_TOKEN_SALT,
    )
    email_verifications[token_id] = {
        "user_id": user_id,
        "is_consumed": False,
        "expires_at": now_utc() + timedelta(seconds=EMAIL_TOKEN_TTL_SECONDS),
    }

    print(f"[DEBUG] Magic link para verificación: http://localhost:8000/verify-email?token={token}")

    log_event("REGISTER_PENDING_EMAIL_VERIFICATION", user_id, request)
    return {
        "message": "Registro recibido. Si el email es válido, se enviará un enlace de verificación.",
        "debug_token": token,  
    }


@app.get("/verify-email")
def verify_email(token: str, request: Request):
    try:
        data = serializer.loads(token, salt=EMAIL_TOKEN_SALT, max_age=EMAIL_TOKEN_TTL_SECONDS)
    except SignatureExpired:
        raise HTTPException(status_code=400, detail="Token expirado")
    except BadSignature:
        raise HTTPException(status_code=400, detail="Token inválido")

    user_id = UUID(data["user_id"])
    token_id = data["token_id"]

    record = email_verifications.get(token_id)
    if not record or record["is_consumed"] or record["user_id"] != user_id or record["expires_at"] < now_utc():
        raise HTTPException(status_code=400, detail="Token inválido o ya utilizado")

    # Marcar como consumido y activar usuario
    record["is_consumed"] = True
    user = users.get(user_id)
    if user:
        user["status"] = "ACTIVE"
        log_event("EMAIL_VERIFIED", user_id, request)
    return {"message": "Email verificado correctamente. Ahora puede iniciar sesión."}


@app.post("/login")
def login(data: LoginRequest, request: Request):
    user_id = find_user_by_username_or_email(data.identifier)
    if not user_id:
        # Respuesta genérica
        log_event("LOGIN_FAILED", None, request, {"reason": "user_not_found"})
        raise HTTPException(status_code=401, detail="Credenciales inválidas")

    user = users[user_id]

    # Verificar bloqueo de cuenta
    if user["locked_until"] and user["locked_until"] > now_utc():
        log_event("LOGIN_FAILED", user_id, request, {"reason": "account_locked"})
        raise HTTPException(status_code=401, detail="Credenciales inválidas")

    if user["status"] != "ACTIVE":
        log_event("LOGIN_FAILED", user_id, request, {"reason": "inactive_or_unverified"})
        raise HTTPException(status_code=401, detail="Credenciales inválidas")

    # Verificar contraseña
    if not verify_password(data.password, user["password_hash"]):
        user["failed_login_attempts"] += 1
        details = {"reason": "wrong_password", "failed_attempts": user["failed_login_attempts"]}
        if user["failed_login_attempts"] >= 5:
            user["locked_until"] = now_utc() + timedelta(minutes=5)
            details["locked_until"] = user["locked_until"].isoformat()
        log_event("LOGIN_FAILED", user_id, request, details)
        raise HTTPException(status_code=401, detail="Credenciales inválidas")

    # Resetear contador de fallos
    user["failed_login_attempts"] = 0
    user["locked_until"] = None

    # Generar OTP 2FA numérico de 6 dígitos
    code = f"{secrets.randbelow(10**6):06d}"
    code_hash = hash_with_bcrypt(code)
    otp_id = uuid4()
    otp_codes[user_id] = {
        "id": otp_id,
        "user_id": user_id,
        "code_hash": code_hash,
        "type": "LOGIN_2FA",
        "attempts_count": 0,
        "expires_at": now_utc() + timedelta(seconds=LOGIN_OTP_TTL_SECONDS),
        "created_at": now_utc(),
        "used": False,
    }

    # En un sistema real, este código se enviaría por email
    print(f"[DEBUG] OTP de login para usuario {user['username']}: {code}")

    log_event("LOGIN_PASSWORD_OK_2FA_SENT", user_id, request)
    return {"message": "Se envió un código OTP al correo registrado (simulado).", "identifier": data.identifier}


@app.post("/verify-otp")
def verify_otp(data: VerifyOtpRequest, request: Request, response: Response):
    user_id = find_user_by_username_or_email(data.identifier)
    if not user_id:
        log_event("LOGIN_2FA_FAILED", None, request, {"reason": "user_not_found"})
        raise HTTPException(status_code=401, detail="Código inválido")

    record = otp_codes.get(user_id)
    if not record or record["type"] != "LOGIN_2FA" or record["used"]:
        log_event("LOGIN_2FA_FAILED", user_id, request, {"reason": "no_active_otp"})
        raise HTTPException(status_code=401, detail="Código inválido")

    if record["expires_at"] < now_utc():
        log_event("LOGIN_2FA_FAILED", user_id, request, {"reason": "otp_expired"})
        raise HTTPException(status_code=401, detail="Código inválido")

    # Verificar código
    if not verify_with_bcrypt(data.code, record["code_hash"]):
        record["attempts_count"] += 1
        log_event("LOGIN_2FA_FAILED", user_id, request, {"reason": "wrong_code", "attempts": record["attempts_count"]})
        if record["attempts_count"] >= 3:
            record["used"] = True
        raise HTTPException(status_code=401, detail="Código inválido")

    # Código correcto
    record["used"] = True
    user = users[user_id]
    user["last_login_at"] = now_utc()

    session_token = create_session(user_id, request)

    # Cookie de sesión (nota: Secure debería ser True en producción)
    response.set_cookie(
        key="session_id",
        value=session_token,
        httponly=True,
        secure=False,  # True en producción con HTTPS
        samesite="strict",
        max_age=SESSION_TTL_SECONDS,
        path="/",
    )

    log_event("LOGIN_SUCCESS", user_id, request, {"session_token": session_token})
    return {"message": "Inicio de sesión exitoso"}


@app.post("/logout")
def logout(request: Request, response: Response, session_info: Dict[str, Any] = Depends(get_current_user)):
    session_id = session_info["session_id"]
    user_id = session_info["user_id"]

    sessions.pop(session_id, None)
    response.delete_cookie("session_id", path="/")
    log_event("LOGOUT", user_id, request, {"session_id": session_id})
    return {"message": "Sesión cerrada correctamente."}


@app.get("/me")
def get_me(session_info: Dict[str, Any] = Depends(get_current_user)):
    user = session_info["user"].copy()
    # No exponemos hash de password ni email cifrado en claro
    user.pop("password_hash", None)
    return {"user": user}


# =========================
# RESET / CAMBIO DE CONTRASEÑA
# =========================

@app.post("/password-reset/request")
def password_reset_request(data: PasswordResetRequest, request: Request):
    # Respuesta siempre genérica
    user_id = None
    for uid, u in users.items():
        if u["email_blind_index"] == email_blind_index(data.email):
            user_id = uid
            break

    if user_id is not None:
        # Generar código alfanumérico de 8 caracteres
        alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        code = "".join(secrets.choice(alphabet) for _ in range(8))
        code_hash = hash_with_bcrypt(code)

        otp_codes[user_id] = {
            "id": uuid4(),
            "user_id": user_id,
            "code_hash": code_hash,
            "type": "PASSWORD_RESET",
            "attempts_count": 0,
            "expires_at": now_utc() + timedelta(seconds=RESET_TOKEN_TTL_SECONDS),
            "created_at": now_utc(),
            "used": False,
        }

        print(f"[DEBUG] Código de reseteo de contraseña para usuario {users[user_id]['username']}: {code}")
        log_event("PASSWORD_RESET_REQUESTED", user_id, request)

    # Mensaje genérico
    return {"message": "Si el correo existe, se enviaron instrucciones para restablecer la contraseña."}


@app.post("/password-reset/verify")
def password_reset_verify(data: PasswordResetVerifyRequest, request: Request):
    user_id = None
    for uid, u in users.items():
        if u["email_blind_index"] == email_blind_index(data.email):
            user_id = uid
            break

    if user_id is None:
        log_event("PASSWORD_RESET_VERIFY_FAILED", None, request, {"reason": "user_not_found"})
        raise HTTPException(status_code=400, detail="Código inválido")

    record = otp_codes.get(user_id)
    if not record or record["type"] != "PASSWORD_RESET" or record["used"]:
        log_event("PASSWORD_RESET_VERIFY_FAILED", user_id, request, {"reason": "no_active_reset_code"})
        raise HTTPException(status_code=400, detail="Código inválido")

    if record["expires_at"] < now_utc():
        log_event("PASSWORD_RESET_VERIFY_FAILED", user_id, request, {"reason": "reset_code_expired"})
        raise HTTPException(status_code=400, detail="Código inválido")

    if not verify_with_bcrypt(data.code, record["code_hash"]):
        record["attempts_count"] += 1
        log_event("PASSWORD_RESET_VERIFY_FAILED", user_id, request, {"reason": "wrong_code", "attempts": record["attempts_count"]})
        if record["attempts_count"] >= 5:
            record["used"] = True
        raise HTTPException(status_code=400, detail="Código inválido")

    # Código correcto → crear reset_token temporal
    record["used"] = True
    reset_token = secrets.token_urlsafe(32)
    password_reset_sessions[reset_token] = {
        "user_id": user_id,
        "expires_at": now_utc() + timedelta(seconds=RESET_TOKEN_TTL_SECONDS),
    }

    log_event("PASSWORD_RESET_CODE_VERIFIED", user_id, request)
    return {"message": "Código verificado. Puede establecer una nueva contraseña.", "reset_token": reset_token}


@app.post("/password-reset/complete")
def password_reset_complete(data: PasswordResetCompleteRequest, request: Request):
    reset_info = password_reset_sessions.get(data.reset_token)
    if not reset_info or reset_info["expires_at"] < now_utc():
        raise HTTPException(status_code=400, detail="Token de reseteo inválido o expirado")

    user_id = reset_info["user_id"]
    user = users.get(user_id)
    if not user:
        raise HTTPException(status_code=400, detail="Usuario no encontrado")

    # Validaciones simples de nueva contraseña (pueden ampliarla según su informe)
    if len(data.new_password) < 8:
        raise HTTPException(status_code=400, detail="Contraseña demasiado corta")

    # Actualizar contraseña
    old_hash = user["password_hash"]
    user["password_hash"] = hash_password(data.new_password)

    # Invalidar todas las sesiones activas del usuario
    to_delete = [sid for sid, s in sessions.items() if s["user_id"] == user_id]
    for sid in to_delete:
        sessions.pop(sid, None)

    # Eliminar reset_token
    password_reset_sessions.pop(data.reset_token, None)

    log_event("PASSWORD_RESET_COMPLETED", user_id, request, {"old_hash_fragment": old_hash[:20]})
    return {"message": "Contraseña restablecida exitosamente. Inicie sesión nuevamente."}
