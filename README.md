<p align="center">
  <a href="http://nestjs.com/" target="blank"><img src="https://nestjs.com/img/logo-small.svg" width="200" alt="Nest Logo" /></a>
</p>

[circleci-image]: https://img.shields.io/circleci/build/github/nestjs/nest/master?token=abc123def456
[circleci-url]: https://circleci.com/gh/nestjs/nest

<p align="center">SISTEMA BASICO DE AUTENTICACION EN NESTJS</p>

## Description

API de autenticación incluye varias funcionalidades importantes. Documentada con Swipper en /api-docs

Login de Usuario
Descripción: Autenticación usando usuario o email mas la contraseña, Devuelve un token de acceso y una cookie con el refresh token; si tiene activo el multifactor emite un token y envía un código al correo utilizando resend, esto genera un sesión, en efecto se permite hasta 5 sesiones abiertas, al intentar crear una nueva elimina la sesión mas antigua.

Registro de Usuario
Descripción: Devuelve el usuario registrado.

Validación de Código de Login para MFA
Descripción: Valida el código y devuelve un token y cookie con refresh, usuario.

Refresh Token
Descripción: Sirve para validar la sesión o en su defecto refrescar el token de acceso, Recibe la cookie, valida el refresh token y devuelve un nuevo access token.

Código de Recuperación de Contraseña
Descripción: Valida el correo y envía un código para recuperar por correo.

Validación Código Contraseña
Descripción: Recibe el código válido y devuelve un token para que pueda actualizar la contraseña.

Recuperación de Contraseña
Descripción: Valida y devuelve si fue efectivo el restablecimiento.

Revocación de Tokens:
Descripción: se implementa de dos forma, la primera es el logout del usuario, donde elimina la sesión desde donde se utiliza, y la segunda sirve para eliminar todas las sesiones de un usuario especifico, actualmente solo los administradores pueden usar esta función

Auditoría y Monitoreo:
En proceso de desarrollo, por los momentos crea log si hay intentos fallidos de validación de código y de recuperación de contraseña

## Instalación

```bash
$ pnpm install

$ Configurar variables de entorno

# create the model to the database
$ pnpm prisma db push

# generates the model in prisma
$ pnpm prisma generate

# seed the database
$ pnpm prisma db seed
```

## Ejecutando la aplicación

```bash
# development
$ pnpm run start

# watch mode
$ pnpm run start:dev

# production mode
$ pnpm run start:prod
```

## Colaboracion

Cualquier sugerencia o recomendaciones, puede enviar correo [aqui](zonastartceo@gmail.com).

## Mantente en contacto

- Author - Sergio Ramirez CEO Zona Start
- Website - [https://zonastart.com](https://zonastart.com)
- Instagram - [zonastart](https://www.instagram.com/zonastart)

## Licencia

[MIT licensed](LICENSE).
