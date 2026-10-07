# TechStore – Gestión de Inventario seguro

Laboratorio calificado de Desarrollo de Soluciones en la Nube (Tecsup).
Aplicación web con registro, login con JWT, bloqueo tras 5 intentos fallidos, MFA con TOTP, login con Google y GitHub, y control de acceso por roles (Administrador, Gerente, Ventas y Auditor).

## Tecnologías
Node.js, Express, JWT, bcryptjs, speakeasy (TOTP), passport (Google y GitHub).

## Instalación

```bash
git clone https://github.com/eder3105/TechStore.git
cd TechStore
npm install
copy .env.example .env
```

Edita `.env` con tus claves (el login social es opcional) e inicia el servidor:

```bash
npm start
```

Abre http://localhost:3000