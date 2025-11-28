# Mock de Sistema de Inicio de Sesion Seguro

Playground en FastAPI que simula un flujo de autenticacion reforzado (registro + verificacion de email, login con password + OTP, reseteo de password y cookies de sesion) usando los almacenes en memoria definidos en `app.py`.

## Requisitos
- Python 3.10+
- `pip`
- (Opcional) `python3 -m venv venv` y `source venv/bin/activate`

Instala las dependencias una vez que tengas el entorno activo:

```bash
pip install fastapi uvicorn itsdangerous argon2-cffi bcrypt
```

## Ejecutar la API

```bash
uvicorn app:app --reload
```

El servidor imprime lineas `[DEBUG]` con tokens de magic link, codigos OTP y codigos de reseteo; manten la terminal visible mientras sigues los flujos. Todos los datos se reinician cada vez que el proceso se reinicia porque todo vive en memoria.

## Recorridos con curl

Define un cookie jar para las etapas autenticadas:

```bash
COOKIE_JAR=cookies.txt
```

### 1. Registrar un usuario

```bash
curl -s -X POST http://127.0.0.1:8000/register \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","email":"alice@example.com","password":"Sup3rStr0ng!"}'
```

Busca en la terminal del servidor una linea `[DEBUG] Magic link...token=...`.

### 2. Verificar email (magic link)

```bash
curl -s "http://127.0.0.1:8000/verify-email?token=<TOKEN_DEL_LOG>"
```

Una vez verificado, el usuario queda `ACTIVE` y puede iniciar sesion.

### 3. Login con password (inicia OTP)

```bash
curl -i -c "$COOKIE_JAR" -X POST http://127.0.0.1:8000/login \
  -H "Content-Type: application/json" \
  -d '{"identifier":"alice","password":"Sup3rStr0ng!"}'
```

La respuesta confirma que se "envio" un OTP. Toma el codigo de 6 digitos del log `[DEBUG] OTP de login ...`.

### 4. Verificar OTP y capturar la cookie de sesion

```bash
curl -i -c "$COOKIE_JAR" -X POST http://127.0.0.1:8000/verify-otp \
  -H "Content-Type: application/json" \
  -d '{"identifier":"alice","code":"<OTP_DEL_LOG>"}'
```

Esta respuesta entrega la cookie `session_id` que queda guardada en `cookies.txt`.

### 5. Consumir endpoints autenticados

```bash
curl -s -b "$COOKIE_JAR" http://127.0.0.1:8000/me
```

### 6. Logout

```bash
curl -s -X POST -b "$COOKIE_JAR" http://127.0.0.1:8000/logout
```

### 7. Flujo de reseteo de password

1. **Solicitar reseteo (respuesta generica):**
   ```bash
   curl -s -X POST http://127.0.0.1:8000/password-reset/request \
     -H "Content-Type: application/json" \
     -d '{"email":"alice@example.com"}'
   ```
   Busca `[DEBUG] Codigo de reseteo...` para obtener el codigo alfanumerico.

2. **Verificar el codigo:**
   ```bash
   curl -s -X POST http://127.0.0.1:8000/password-reset/verify \
     -H "Content-Type: application/json" \
     -d '{"email":"alice@example.com","code":"<CODIGO_DEL_LOG>"}'
   ```
   La respuesta devuelve un `reset_token`.

3. **Completar el reseteo:**
   ```bash
   curl -s -X POST http://127.0.0.1:8000/password-reset/complete \
     -H "Content-Type: application/json" \
     -d '{"reset_token":"<RESET_TOKEN>","new_password":"N3wSup3rStr0ng!"}'
   ```

Despues de resetear, el usuario debe iniciar sesion otra vez (todas las sesiones previas quedan revocadas).
