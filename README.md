# Mock de Sistema de Inicio de Sesión Seguro

Playground en FastAPI que simula un flujo de autenticación reforzado (registro + verificación de email, login con password + OTP, reseteo de password y cookies de sesión) usando almacenes en memoria definidos en `app.py`.

Este proyecto es una **prueba de concepto** basada en el diseño presentado en el informe final de la materia de Criptografía y Ciberseguidad. No está pensado para uso en producción.

## Requisitos

- Python 3.10+
- `pip`
- (Opcional) `python3 -m venv venv` y `source venv/bin/activate`

Instalar las dependencias:

```bash
pip install fastapi uvicorn itsdangerous argon2-cffi bcrypt
````

## Ejecutar la API

```bash
uvicorn app:app --reload
```

El servidor imprime líneas `[DEBUG]` con tokens de magic link, códigos OTP y códigos de reseteo; mantené la terminal visible mientras seguís los flujos. Todos los datos se reinician cada vez que el proceso se reinicia porque todo vive en memoria.

---

## Alcance y limitaciones de la PoC

Este mock implementa las ideas centrales del diseño:

* Hash de contraseñas con **Argon2id**.
* **Blind index** de email con HMAC-SHA256.
* Verificación de email mediante **magic link** firmado y con TTL.
* Login con **password + OTP** (2FA) donde el OTP se guarda sólo como hash (bcrypt), con TTL y límite de intentos.
* **Sesiones opacas** server-side con cookie `HttpOnly`.
* Flujo completo de **reseteo de contraseña** (código + reset token), invalidando sesiones previas.

Y tiene las siguientes simplificaciones, intencionales para una PoC local:

* El email se guarda como `ENCRYPTED::<email_normalizado>` a modo de **placeholder** en lugar de un cifrado simétrico real.
* No se implementa historial de contraseñas ni política avanzada de complejidad (sólo longitud mínima).
* No hay base de datos real: todos los datos (usuarios, sesiones, OTP, logs) viven en estructuras en memoria.
* No hay rate limiting por IP ni mecanismos avanzados anti-fuerza bruta, más allá de contadores de intentos y lockout temporal.
* La cookie de sesión tiene `Secure=False` para permitir pruebas en `http://127.0.0.1`; en un entorno real debe ser `Secure=True` con HTTPS.
* Las claves (`SECRET_KEY`, `EMAIL_HMAC_KEY`) están hardcodeadas para la demo; en producción deberían gestionarse mediante un KMS/secret manager.

**No usar este código en producción.** Su propósito es exclusivamente académico y de demostración del modelo criptográfico.

---

## Recorridos con curl

Definir un cookie jar para las etapas autenticadas:

```bash
COOKIE_JAR=cookies.txt
```

### 1. Registrar un usuario

```bash
curl -s -X POST http://127.0.0.1:8000/register \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","email":"alice@example.com","password":"Sup3rStr0ng!"}'
```

Buscar en la terminal del servidor una línea `[DEBUG] Magic link...token=...`.

### 2. Verificar email (magic link)

```bash
curl -s "http://127.0.0.1:8000/verify-email?token=<TOKEN_DEL_LOG>"
```

Una vez verificado, el usuario queda `ACTIVE` y puede iniciar sesión.

### 3. Login con password (inicia OTP)

```bash
curl -i -c "$COOKIE_JAR" -X POST http://127.0.0.1:8000/login \
  -H "Content-Type: application/json" \
  -d '{"identifier":"alice","password":"Sup3rStr0ng!"}'
```

La respuesta confirma que se "envió" un OTP. Tomar el código de 6 dígitos del log `[DEBUG] OTP de login ...`.

### 4. Verificar OTP y capturar la cookie de sesión

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

1. **Solicitar reseteo (respuesta genérica):**

   ```bash
   curl -s -X POST http://127.0.0.1:8000/password-reset/request \
     -H "Content-Type: application/json" \
     -d '{"email":"alice@example.com"}'
   ```

   Buscar `[DEBUG] Código de reseteo...` para obtener el código alfanumérico.

2. **Verificar el código:**

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

Después de resetear, el usuario debe iniciar sesión otra vez (todas las sesiones previas quedan revocadas).

