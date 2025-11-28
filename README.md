# Sistema de Inicio de Sesión Seguro

Aplicación web completa que implementa un sistema de autenticación robusto con verificación de email, autenticación de dos factores (2FA) y recuperación segura de contraseñas. Incluye backend en FastAPI y frontend en HTML/JavaScript vanilla.

Este proyecto es una **prueba de concepto** desarrollada para demostrar las mejores prácticas de seguridad en sistemas de autenticación, basado en los principios de criptografía moderna y las recomendaciones de OWASP.

## Características

### Funcionalidades Implementadas

- **Registro de usuarios** con validación de datos
- **Verificación de email** mediante magic links firmados
- **Autenticación 2FA** con códigos OTP numéricos de 6 dígitos
- **Gestión de sesiones** segura con cookies HttpOnly
- **Recuperación de contraseña** en tres etapas con códigos alfanuméricos
- **Interfaz web responsive** con diseño moderno
- **Logging de auditoría** de todos los eventos de seguridad
- **Protección contra enumeración** de usuarios mediante respuestas genéricas
- **Rate limiting básico** con bloqueo temporal de cuentas

### Interfaz de Usuario

- Diseño moderno y responsive con Tailwind CSS
- 7 pantallas diferentes: Login, Registro, Verificación 2FA, Solicitud de reseteo, Verificación de código, Nueva contraseña, Dashboard
- Feedback visual inmediato con mensajes de éxito/error
- Animaciones suaves de transición
- Compatible con dispositivos móviles

---

## Requisitos

### Software Necesario

- **Python 3.10 o superior**
- **pip** (gestor de paquetes de Python)
- **Navegador web moderno** (Chrome, Firefox, Edge, Safari)

### Dependencias de Python

```
fastapi==0.104.1
uvicorn==0.24.0
pydantic[email]==2.5.0
itsdangerous==2.1.2
argon2-cffi==23.1.0
bcrypt==4.1.1
```

---

## Instalación

### 1. Clonar o descargar el proyecto

```bash
cd ~/tu-directorio-de-trabajo
# Asegúrate de tener los archivos: app.py, login-ui.html
```

### 2. Crear entorno virtual (recomendado)

**Linux/Mac:**
```bash
python3 -m venv venv
source venv/bin/activate
```

**Windows:**
```bash
python -m venv venv
venv\Scripts\activate
```

### 3. Instalar dependencias

```bash
pip install fastapi uvicorn itsdangerous argon2-cffi bcrypt pydantic[email]
```

**Nota:** Si obtienes error con `pydantic[email]`, puedes instalar manualmente:
```bash
pip install email-validator
```

---

## Configuración

### Estructura de archivos

```
proyecto/
│
├── app.py              # Backend FastAPI
├── login-ui.html       # Frontend (interfaz web)
├── cookies.txt         # (Generado automáticamente si se usa curl)
└── README.md           # Este archivo
```

### Configuración CORS

El archivo `app.py` ya incluye la configuración CORS necesaria:

```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:5500", "http://localhost:5500", "null"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

Si necesitas agregar más orígenes, modifica la lista `allow_origins`.

### Claves y Configuración de Seguridad

**IMPORTANTE:** Las siguientes claves en `app.py` están hardcodeadas solo para desarrollo:

```python
SECRET_KEY = "CHANGE_THIS_SECRET_KEY_FOR_REAL_USE"
EMAIL_HMAC_KEY = b"another-server-side-secret-for-email-hmac"
```

**En producción**, estas claves deben:
- Generarse aleatoriamente con alta entropía
- Almacenarse en variables de entorno o gestores de secretos (AWS Secrets Manager, HashiCorp Vault)
- Rotarse periódicamente

### Configuración de Tiempos de Expiración

Puedes modificar los TTL en `app.py`:

```python
EMAIL_TOKEN_TTL_SECONDS = 15 * 60       # Magic link: 15 minutos
LOGIN_OTP_TTL_SECONDS = 10 * 60        # OTP de login: 10 minutos
RESET_TOKEN_TTL_SECONDS = 15 * 60      # Código de reseteo: 15 minutos
SESSION_TTL_SECONDS = 60 * 60          # Sesión: 1 hora
```

---

## Ejecución

### 1. Iniciar el servidor backend

En una terminal, desde la carpeta del proyecto:

```bash
uvicorn app:app --reload
```

**Salida esperada:**
```
INFO:     Will watch for changes in these directories: ['/ruta/proyecto']
INFO:     Uvicorn running on http://127.0.0.1:8000 (Press CTRL+C to quit)
INFO:     Started reloader process [xxxxx] using StatReload
INFO:     Started server process [xxxxx]
INFO:     Waiting for application startup.
INFO:     Application startup complete.
```

**IMPORTANTE:** Mantén esta terminal visible durante todo el uso. Los códigos OTP y tokens de verificación se imprimen aquí con el prefijo `[DEBUG]`.

### 2. Abrir la interfaz web

Tienes varias opciones:

#### **Opción A: Abrir directamente (más simple)**
1. Navega a la carpeta del proyecto en tu explorador de archivos
2. Doble clic en `login-ui.html`
3. Se abre en tu navegador predeterminado

#### **Opción B: Servidor HTTP con Python**
```bash
# En otra terminal (mantén uvicorn corriendo)
python -m http.server 5500
```
Luego abre: `http://127.0.0.1:5500/login-ui.html`

#### **Opción C: Live Server (VS Code)**
Si usas VS Code con la extensión "Live Server":
1. Clic derecho en `login-ui.html`
2. "Open with Live Server"

### 3. Verificar funcionamiento

1. Deberías ver la pantalla de login con el título "Sistema Seguro"
2. La consola del navegador (F12) no debe mostrar errores de CORS
3. El backend debe estar respondiendo en `http://127.0.0.1:8000/docs` (FastAPI Swagger UI)

---

## Uso de la Aplicación

### Flujo 1: Registro de Usuario

**1. Crear cuenta**
- En la interfaz, clic en "Crear cuenta nueva"
- Completa el formulario:
  ```
  Usuario: alice
  Email: alice@example.com
  Contraseña: Sup3rStr0ng!
  ```
- Clic en "Registrar"

**2. Verificar email**
- Busca en la terminal del servidor:
  ```
  [DEBUG] Magic link para verificación: http://localhost:8000/verify-email?token=eyJ...
  ```
- Copia la URL completa
- Pégala en una nueva pestaña del navegador
- Verás: `{"message":"Email verificado correctamente. Ahora puede iniciar sesión."}`

**Usuario creado y verificado**

---

### Flujo 2: Inicio de Sesión con 2FA

**1. Iniciar sesión**
- En la pantalla de login:
  ```
  Usuario o Email: alice
  Contraseña: Sup3rStr0ng!
  ```
- Clic en "Continuar"

**2. Verificar OTP**
- En la terminal del servidor:
  ```
  [DEBUG] OTP de login para usuario alice: 123456
  ```
- Ingresa el código de 6 dígitos en la interfaz
- Clic en "Verificar"

**Acceso al Dashboard**

---

### Flujo 3: Dashboard

En el dashboard verás:
- **Usuario:** Tu nombre de usuario
- **Estado:** ACTIVE
- **Último acceso:** Fecha y hora del login

**Cerrar sesión:**
- Clic en "Cerrar Sesión"
- Todas las sesiones se invalidan
- Redirige al login

---

### Flujo 4: Recuperación de Contraseña

**1. Solicitar código**
- En el login, clic en "¿Olvidaste tu contraseña?"
- Ingresa tu email: `alice@example.com`
- Clic en "Enviar código"

**2. Verificar código**
- En la terminal:
  ```
  [DEBUG] Código de reseteo de contraseña para usuario alice: aBcD1234
  ```
- Ingresa el código alfanumérico de 8 caracteres
- Clic en "Verificar"

**3. Nueva contraseña**
- Ingresa una nueva contraseña: `N3wP4ssw0rd!`
- Clic en "Restablecer contraseña"
- Todas las sesiones previas se invalidan

**4. Iniciar sesión con nueva contraseña**
- Usa las nuevas credenciales para acceder

**Contraseña cambiada exitosamente**

---

## Arquitectura

### Backend (FastAPI)

**Tecnologías:**
- **Framework:** FastAPI 0.104+
- **Servidor:** Uvicorn (ASGI)
- **Hash de contraseñas:** Argon2id (vía argon2-cffi)
- **Hash de OTP:** bcrypt
- **Firma de tokens:** itsdangerous (URLSafeTimedSerializer)
- **Blind index:** HMAC-SHA256

**Estructura de datos en memoria:**

```python
users: Dict[UUID, Dict]                    # Usuarios registrados
sessions: Dict[str, Dict]                  # Sesiones activas
otp_codes: Dict[UUID, Dict]                # Códigos OTP/reset
password_reset_sessions: Dict[str, Dict]   # Tokens de reseteo
email_verifications: Dict[str, Dict]       # Tokens de verificación
audit_logs: list[Dict]                     # Logs de auditoría
```

**Endpoints principales:**
- `POST /register` - Registro de usuario
- `GET /verify-email` - Verificación de email
- `POST /login` - Fase 1: Validar credenciales
- `POST /verify-otp` - Fase 2: Verificar OTP
- `POST /logout` - Cerrar sesión
- `GET /me` - Info del usuario autenticado
- `POST /password-reset/request` - Solicitar reseteo
- `POST /password-reset/verify` - Verificar código
- `POST /password-reset/complete` - Establecer nueva contraseña

### Frontend (HTML/JavaScript)

**Tecnologías:**
- **HTML5** - Estructura semántica
- **Tailwind CSS** (CDN) - Estilos modernos
- **Vanilla JavaScript** - Lógica de aplicación
- **Fetch API** - Comunicación con backend

**Características:**
- SPA (Single Page Application) simulada
- Estado reactivo con re-renderizado completo
- Gestión automática de cookies para sesiones
- Validaciones client-side
- Mensajes temporales (5 segundos)

---

## Seguridad Implementada

### Criptografía

| Componente | Algoritmo | Propósito |
|------------|-----------|-----------|
| Contraseñas | Argon2id | Hash resistente a GPU/ASIC |
| Códigos OTP | bcrypt | Hash de códigos temporales |
| Blind index | HMAC-SHA256 | Búsqueda de emails sin revelarlos |
| Magic links | HMAC (itsdangerous) | Firma criptográfica con TTL |
| Sesiones | secrets.token_urlsafe(32) | Tokens opacos aleatorios |

### Protecciones

- **Anti-enumeración:** Respuestas genéricas en login y reseteo
- **Rate limiting:** Contador de intentos fallidos con bloqueo temporal (5 intentos → 5 minutos)
- **Expiración de códigos:** TTL en todos los tokens temporales
- **Consumo único:** Los OTP y tokens de reset solo pueden usarse una vez
- **Invalidación de sesiones:** Logout y cambio de contraseña invalidan todas las sesiones
- **Cookies seguras:** HttpOnly, SameSite=Strict (Secure=False solo para desarrollo)
- **Audit logging:** Todos los eventos de seguridad se registran

### Validaciones

**Contraseñas:**
- Mínimo 8 caracteres, máximo 64
- Sin validación de complejidad avanzada (solo longitud)

**Usernames:**
- 3-30 caracteres
- Solo letras, números, guiones bajos, guiones y puntos
- Pattern: `[A-Za-z0-9_.-]{3,30}`

**Emails:**
- Validación con Pydantic EmailStr
- Normalización (lowercase, trim)

---

## Limitaciones y Alcance

### Implementado

- Hash de contraseñas con Argon2id
- Blind index de emails con HMAC-SHA256
- Verificación de email mediante magic links firmados
- Autenticación 2FA con OTP hasheados (bcrypt)
- Sesiones opacas server-side con cookies HttpOnly
- Flujo completo de recuperación de contraseña
- Rate limiting básico con lockout temporal
- Audit logging completo
- Protección contra enumeración de usuarios

### Limitaciones (PoC Académica)

**Almacenamiento:**
- Todo vive en memoria (se pierde al reiniciar el servidor)
- No hay base de datos persistente
- Email se guarda como `ENCRYPTED::<email>` (placeholder, no cifrado real)

**Seguridad:**
- Claves hardcodeadas (deben estar en gestores de secretos en producción)
- Cookie `Secure=False` para permitir HTTP en desarrollo
- Sin rate limiting por IP (solo por usuario)
- Sin CAPTCHA para prevenir bots
- Sin complejidad avanzada de contraseñas (solo longitud)
- Sin historial de contraseñas

**Funcionalidad:**
- Sin envío real de emails (códigos en terminal)
- Sin persistencia de datos
- Sin múltiples sesiones por usuario
- Sin notificaciones de login desde nuevos dispositivos

### NO usar en producción

Este código es **exclusivamente académico**. Para producción necesitas:

1. **Base de datos real** (PostgreSQL, MySQL)
2. **Cifrado de emails** (AES-GCM con KMS)
3. **Servicio de email** (SendGrid, AWS SES)
4. **HTTPS obligatorio** con certificados válidos
5. **Rate limiting por IP** (Redis + nginx)
6. **CAPTCHA** (reCAPTCHA v3)
7. **Logging centralizado** (ELK Stack)
8. **Monitoreo** (Prometheus + Grafana)
9. **Backups automáticos**
10. **Auditoría de seguridad profesional**

---

## Uso con curl (CLI)

Si prefieres probar la API desde la línea de comandos:

```bash
# Definir cookie jar
COOKIE_JAR=cookies.txt

# 1. Registrar
curl -s -X POST http://127.0.0.1:8000/register \
  -H "Content-Type: application/json" \
  -d '{"username":"bob","email":"bob@example.com","password":"Test1234!"}'

# 2. Verificar email (copiar token del log)
curl -s "http://127.0.0.1:8000/verify-email?token=TOKEN_AQUI"

# 3. Login
curl -i -c "$COOKIE_JAR" -X POST http://127.0.0.1:8000/login \
  -H "Content-Type: application/json" \
  -d '{"identifier":"bob","password":"Test1234!"}'

# 4. Verificar OTP (copiar código del log)
curl -i -c "$COOKIE_JAR" -X POST http://127.0.0.1:8000/verify-otp \
  -H "Content-Type: application/json" \
  -d '{"identifier":"bob","code":"123456"}'

# 5. Acceder a recurso protegido
curl -s -b "$COOKIE_JAR" http://127.0.0.1:8000/me

# 6. Logout
curl -s -X POST -b "$COOKIE_JAR" http://127.0.0.1:8000/logout
```

---

## Autores

- Matias Antezana
- Bruno Castagnino Rossi
- Mateo Giacometti
- Tiziano Levi Martín Bernal

