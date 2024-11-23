import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { PrismaService } from 'src/common/prisma/prisma.service';
import { LoginDto } from './dto/login.dto';
import { envs } from 'src/config';
import {
  DecodeJwt,
  JwtPayload,
  ValidationInput,
  VerificationToken,
} from './types';
import { UsersService } from '../users/users.service';
import { compare } from 'bcrypt';
import { RegisterDto } from './dto/register.dto';
import { LoginAuthResponse, SessionInput } from './types/login';
import {
  getExpiry,
  getExpiryCode,
  isDateExpired,
} from 'src/common/utils/dateTimeUtility';
import { generateOTP } from 'src/common/utils/otpCode';
import {
  EmailPasswordDto,
  RecoveryPasswordDto,
} from './dto/recoveryPassword.dto';
import { sendMail } from 'src/common/utils/resend';
import { User } from '../users/entities/user.entity';

@Injectable()
export class AuthService {
  private readonly MAX_SESSIONS = 5; // Maximum number of active sessions
  private readonly EXPIRES_CODE = 5; // Maximum number of active sessions
  constructor(
    private readonly prisma: PrismaService,
    private readonly userService: UsersService,
    private readonly jwtService: JwtService,
  ) {}

  //metodo para obtener la ip desde donde se hace la peticion
  private decodeClientIp(ip: string): string {
    if (ip.startsWith('::ffff:')) {
      return ip.substring(7);
    }
    return ip;
  }

  // Método para decodificar el token y obtener los datos completos
  private decodeToken(token: string): {
    iss?: string;
    id?: string;
    user?: string;
    email?: string;
    role?: string;
    iat?: number;
    exp?: number;
  } | null {
    try {
      const decoded = this.jwtService.decode(token) as {
        iss?: string;
        id?: string;
        user?: string;
        email?: string;
        role?: string;
        iat?: number;
        exp?: number;
      };

      // Validar que contiene los datos esenciales
      if (!decoded || !decoded.exp || !decoded.iat) {
        throw new Error('Token lacks required fields');
      }

      return decoded;
    } catch (error) {
      console.error('Error decoding token:', error.message);
      return null; // Manejo de errores si la decodificación falla
    }
  }

  //sirve para verificar si un token es valido o no
  private async verifyToken(token: string, secret?: string): Promise<boolean> {
    try {
      await this.jwtService.verifyAsync(token, { secret });
      return true;
    } catch (error) {
      return false;
    }
  }

  //sirve para generar un token ya sea acceso o de refresh o de valacion
  private async generateToken(
    payload: JwtPayload,
    secret?: string,
    expiresIn?: string,
  ): Promise<{ token: string; expiresAt: number }> {
    const token = await this.jwtService.signAsync(payload, {
      secret,
      expiresIn,
    });

    // Decodificar el token para obtener la expiración
    const decoded = this.decodeToken(token);
    const expiresAt = decoded ? decoded.exp : null;

    return { token, expiresAt };
  }

  //metodo para generar un acces token y refreshtoken a la vez
  private async getTokens(payload: JwtPayload): Promise<{
    access_token: string;
    refreshToken: string;
    accessExpiresAt?: number;
    refreshExpiresAt?: number;
  }> {
    // Generar ambos tokens y sus respectivas fechas de expiración
    const [accessTokenData, refreshTokenData] = await Promise.all([
      this.generateToken(payload, envs.jwtSecret, envs.expire_token), // Token de acceso
      this.generateToken(
        payload,
        envs.jwtRefresh,
        envs.time_expires_refreshtoken,
      ), // Token de refresco
    ]);

    return {
      access_token: accessTokenData.token,
      refreshToken: refreshTokenData.token,
      accessExpiresAt: accessTokenData.expiresAt, // Fecha de expiración del token de acceso
      refreshExpiresAt: refreshTokenData.expiresAt, // Fecha de expiración del token de refresco
    };
  }

  //valida el limite de sessiones abiertas
  private async limitActiveSessions(userId: string): Promise<void> {
    const activeSessionsCount = await this.prisma.session.count({
      where: { user_id: userId, is_active: true },
    });

    if (activeSessionsCount >= envs.max_sesion_user) {
      const oldestSession = await this.prisma.session.findFirst({
        where: { user_id: userId, is_active: true },
        orderBy: { createdAt: 'asc' },
      });

      if (oldestSession) {
        await this.prisma.session.update({
          where: { id: oldestSession.id },
          data: { is_active: false },
        });
      }
    }
  }

  //metodo que valida si existe un token ya creado en la validacion
  private async findVerificationToken(
    userId: string,
  ): Promise<VerificationToken | null> {
    return await this.prisma.verificationToken.findFirst({
      where: { identifier: userId },
    });
  }

  //metodo para validar codigo enviado desde el backend
  private async validateVerificationCode(
    code: number,
    token: string,
    data?: { user_id: string; userIp: string },
  ): Promise<boolean> {
    // Validar el token
    const isTokenValid = await this.verifyToken(token, envs.jwtValidation);

    if (!isTokenValid) {
      // Registrar intento fallido
      await this.prisma.auditLog.create({
        data: {
          user_id: data?.user_id,
          action: 'login_failed',
          ip: data?.user_id,
          details: { reason: 'Invalid verification code' },
        },
      });

      throw new HttpException(
        'Invalid token provided',
        HttpStatus.UNAUTHORIZED,
      );
    }

    // Buscar el código y el token en la base de datos
    const verification = await this.prisma.verificationToken.findFirst({
      where: {
        code,
        session_token: token,
      },
    });

    if (!verification) {
      // Registrar intento fallido
      const res = await this.prisma.auditLog.create({
        data: {
          user_id: data?.user_id,
          action: 'login_failed',
          ip: data?.user_id,
          details: { reason: 'Invalid verification code' },
        },
      });
      throw new HttpException(
        'Invalid verification code',
        HttpStatus.UNAUTHORIZED,
      );
    }

    // Verificar si el código ha expirado
    if (isDateExpired(verification.expires)) {
      throw new HttpException(
        'Verification code expired',
        HttpStatus.UNAUTHORIZED,
      );
    }

    // Si todo es válido, eliminar el token usado
    await this.prisma.verificationToken.delete({
      where: {
        session_token: token,
        code,
      },
    });

    return true; // Confirmar que el código es válido
  }

  //metodo para actualizar el usuario verificado
  private async updateUserVerificationStatus(userId: string): Promise<void> {
    await this.prisma.user.update({
      where: { id: userId },
      data: {
        email_verified: new Date(),
        two_fa: true,
      },
    });
  }

  //METODO QUE GENERA UN COODIGO DE VALIDACION CON UN TOKEN
  async createCodeValidation(
    validationInput: ValidationInput,
  ): Promise<{ tokenValidate: string; code: number }> {
    const { user_id, ip } = validationInput;

    const maxAttempts = 3;

    // Verificar intentos fallidos en los últimos 10 minutos
    const failedAttempts = await this.prisma.auditLog.count({
      where: {
        user_id: user_id,
        action: 'login_failed',
        timestamp: {
          gte: new Date(Date.now() - 10 * 60 * 1000), // Últimos 10 minutos
        },
      },
    });

    // Eliminar el token de verificación existente
    const existingVerification = await this.findVerificationToken(user_id);
    if (existingVerification) {
      await this.deleteTokenVerification(existingVerification.session_token);
    }

    const user = await this.userService.findUserById(user_id);

    const payload = {
      iss: envs.issuer,
      id: user.id,
      user: user.username,
      email: user.email,
      role: user.rol.name,
    };

    const ipClient = this.decodeClientIp(ip);
    const tokenValidate = await this.generateToken(
      payload,
      envs.jwtValidation,
      '5m',
    );
    const codeOtp = generateOTP();

    const expires = getExpiryCode(envs.expire_code);

    await this.prisma.verificationToken.create({
      data: {
        session_token: tokenValidate.token,
        code: codeOtp,
        identifier: user_id,
        expires,
        ip: ipClient,
      },
    });

    if (failedAttempts >= maxAttempts) {
      await this.prisma.auditLog.deleteMany({
        where: {
          user_id: user_id,
          action: 'login_failed',
        },
      });
    }

    return { tokenValidate: tokenValidate.token, code: codeOtp };
  }

  // metodo para crear una session
  async createSession(sessionInput: SessionInput): Promise<string> {
    const { user_id } = sessionInput;

    // Limitar sesiones activas
    await this.limitActiveSessions(user_id);

    const res = await this.prisma.session.create({
      data: sessionInput,
    });

    if (!res)
      throw new HttpException('Failed to create session', HttpStatus.NOT_FOUND);

    return 'Session created successfully';
  }

  //metodo que elimina si existe un token ya creado en la validacion
  async deleteTokenVerification(session_token: string): Promise<void> {
    await this.prisma.verificationToken.delete({
      where: { session_token },
    });
  }

  //Metodo para cerrar una session de un usuario
  async logout(user_id: string, token: string): Promise<string> {
    const isValidRefreshToken = await this.verifyToken(token, envs.jwtRefresh);

    if (!isValidRefreshToken)
      throw new HttpException('Invalid refresh token', HttpStatus.NOT_FOUND);

    const find = await this.prisma.session.findFirst({
      where: {
        user_id: user_id,
        session_token: token,
      },
    });

    if (!find)
      throw new HttpException('No active session found', HttpStatus.NOT_FOUND);

    const res = await this.prisma.session.delete({
      where: {
        user_id: user_id,
        session_token: token,
      },
    });

    if (!res)
      throw new HttpException('No active session found', HttpStatus.NOT_FOUND);

    return 'Logout successful';
  }

  //metodo para hacer login de usuario
  async login(loginDto: LoginDto, ip?: string): Promise<LoginAuthResponse> {
    const { username, email, password } = loginDto;
    let findUser: User;

    if (username) {
      findUser = await this.userService.findUserByUsername(username, true);
    } else if (email) {
      findUser = await this.userService.findUserById(email, true);
    }

    if (findUser === null)
      throw new HttpException('user not found', HttpStatus.NOT_FOUND);

    //compares the password with the database, if they do not match it returns an error
    const checkPassword = await compare(password, findUser.password);
    if (!checkPassword)
      throw new HttpException('password incorret', HttpStatus.FORBIDDEN);

    //build the data for the token
    const payload = {
      iss: envs.issuer,
      id: findUser.id,
      user: username,
      email: findUser.email,
      role: findUser.rol.name,
    };

    const ipClient = this.decodeClientIp(ip);

    if (findUser.two_fa) {
      // Check if double verification is active and if the email is already validated
      //Generates a token and creates a record to validate which is sent by email to be able to enter and obtain a valid token
      const res = await this.createCodeValidation({
        user_id: findUser.id,
        ip: ipClient,
      });

      const dataEmail = {
        from: envs.supportEmail,
        to: [`${findUser.email}`],
        subject: 'CÓDGIO DE VALIDACIÓN',
        html: `
        <div>
            <h2>Hola, ${findUser.fullname}</h2>
            <p>Este es un mensaje contiene el código de validación para ingresar al sistema.</p>
            <p style="font-size: 16px;"><strong>Tu código es: ${res.code}</strong></p>
            <p>¡Gracias por favor no responder este mensaje!</p>
        </div>
        `,
      };

      try {
        await sendMail(
          dataEmail.from,
          dataEmail.to,
          dataEmail.subject,
          dataEmail.html,
        );
      } catch (error) {
        throw error instanceof HttpException
          ? error
          : new HttpException(
              'Internal server error, verifid env resend email',
              HttpStatus.INTERNAL_SERVER_ERROR,
            );
      }

      return {
        token_validation: res.tokenValidate,
        msg: 'You must validate your income by email',
      };
    }

    //generates the access token and the refresh token, extract token expiration time
    const { access_token, refreshToken, accessExpiresAt, refreshExpiresAt } =
      await this.getTokens(payload);

    await this.createSession({
      session_token: refreshToken,
      user_id: findUser.id,
      expires: refreshExpiresAt,
      is_active: true,
      ip: ipClient,
    });

    return {
      access_token: access_token,
      expiration: accessExpiresAt,
      refresh_token: refreshToken,
      expiration_refreshToken: refreshExpiresAt,
      user: {
        id: findUser.id,
        username: findUser.username,
        fullname: findUser.fullname,
        email: findUser.email,
        phone: findUser.phone,
        role: findUser.rol,
      },
    };
  }

  /// register user
  async register(registerDto: RegisterDto) {
    const { username, email, password } = registerDto;
    const data = {
      username,
      fullname: username ?? email,
      email,
      phone: null,
      password,
      image: null,
      rol_id: 2,
    };
    return await this.userService.create(data);
  }

  //refresh session token
  async refreshSession(token: string, ip: string): Promise<LoginAuthResponse> {
    // Verificar la validez del token de refresco
    const validRefreshToken = await this.verifyToken(token, envs.jwtRefresh);
    if (!validRefreshToken) {
      throw new HttpException('Invalid refresh token', HttpStatus.UNAUTHORIZED);
    }

    const decodedToken = this.decodeToken(token);

    // Verificar si la sesión está activa
    const session = await this.prisma.session.findFirst({
      where: {
        user_id: decodedToken.id,
        session_token: token,
        is_active: true,
      },
    });

    if (!session) {
      throw new HttpException(
        'No active session found',
        HttpStatus.UNAUTHORIZED,
      );
    }

    // Verificar si la sesión ha expirado
    const currentTime = Math.floor(Date.now() / 1000); // Tiempo actual en segundos
    if (session.expires < currentTime) {
      throw new HttpException('Session has expired', HttpStatus.UNAUTHORIZED);
    }

    const payload = {
      iss: envs.issuer,
      id: decodedToken.id,
      user: decodedToken.user,
      email: decodedToken.email,
      role: decodedToken.role,
    };

    const ipClient = this.decodeClientIp(ip);

    // Generar nuevos tokens
    const { access_token, refreshToken, accessExpiresAt, refreshExpiresAt } =
      await this.getTokens(payload);

    // Actualizar la última actividad de la sesión
    await this.prisma.session.update({
      where: { session_token: token },
      data: {
        session_token: refreshToken,
        expires: refreshExpiresAt,
        last_activity: new Date(),
        ip: ipClient,
      },
    });

    return {
      access_token,
      expiration: accessExpiresAt,
      refresh_token: refreshToken,
      expiration_refreshToken: refreshExpiresAt,
    };
  }

  // metodo para validar el ingreso con doble verificacion activa
  async verifyTwoFactorLogin(code: number, token: string, ip?: string) {
    try {
      const maxAttempts = 3;
      const userIp = this.decodeClientIp(ip);

      // Decodificar el token para obtener los datos del usuario
      const decodedToken = this.decodeToken(token);
      if (!decodedToken) {
        throw new HttpException(
          'Invalid or malformed token',
          HttpStatus.UNAUTHORIZED,
        );
      }

      const { id, user, email, role } = decodedToken;

      // Verificar intentos fallidos en los últimos 10 minutos
      const failedAttempts = await this.prisma.auditLog.count({
        where: {
          user_id: id,
          action: 'login_failed',
          timestamp: {
            gte: new Date(Date.now() - 10 * 60 * 1000), // Últimos 10 minutos
          },
        },
      });

      if (failedAttempts >= maxAttempts) {
        throw new HttpException(
          'Maximum verification attempts exceeded. Please request a new code.',
          HttpStatus.TOO_MANY_REQUESTS,
        );
      }

      // Verificar el código y token de doble autenticación
      const isValidCode = await this.validateVerificationCode(code, token, {
        user_id: id,
        userIp: userIp,
      });
      if (!isValidCode) {
        // Registrar intento fallido
        const res = await this.prisma.auditLog.create({
          data: {
            user_id: id,
            action: 'login_failed',
            ip: userIp,
            details: { reason: 'Invalid verification code' },
          },
        });
        throw new HttpException(
          'Invalid verification code',
          HttpStatus.UNAUTHORIZED,
        );
      }

      // Generar tokens y extraer tiempos de expiración
      const { access_token, refreshToken, accessExpiresAt, refreshExpiresAt } =
        await this.getTokens({
          iss: envs.issuer,
          id,
          user,
          email,
          role,
        });

      // Crear la sesión para el usuario
      await this.createSession({
        session_token: refreshToken,
        user_id: id,
        expires: refreshExpiresAt,
        is_active: true,
        ip: this.decodeClientIp(ip),
      });

      // Verificar y actualizar datos del usuario si es necesario
      const userRecord = await this.userService.findUserById(id);
      if (!userRecord.email_verified) {
        await this.updateUserVerificationStatus(id);
      }

      // Opcional: Limpiar intentos fallidos si el inicio de sesión es exitoso
      await this.prisma.auditLog.deleteMany({
        where: {
          user_id: id,
          action: 'login_failed',
        },
      });

      return {
        access_token: access_token,
        expiration: accessExpiresAt,
        refresh_token: refreshToken,
        expiration_refreshToken: refreshExpiresAt,
        user: {
          id: userRecord.id,
          username: userRecord.username,
          fullname: userRecord.fullname,
          email: userRecord.email,
          phone: userRecord.phone,
          role: userRecord.rol,
        },
      };
    } catch (error) {
      throw error instanceof HttpException
        ? error
        : new HttpException(
            'Internal server error',
            HttpStatus.INTERNAL_SERVER_ERROR,
          );
    }
  }

  // Servicio para enviar código de recuperación
  async sendRecoveryCode(ip: string, emailPasswordDto: EmailPasswordDto) {
    const { email } = emailPasswordDto;

    // Buscar al usuario por email
    const user = await this.prisma.user.findUnique({
      where: { email },
    });

    if (!user) {
      throw new HttpException('Email not registered', HttpStatus.NOT_FOUND);
    }

    // Crear el código de validación
    const codeValidation = await this.createCodeValidation({
      user_id: user.id,
      ip,
    });

    // Configurar datos para el correo electrónico
    const emailData = {
      from: envs.supportEmail,
      to: [user.email],
      subject: 'Código de validación para recuperación de contraseña',
      html: `
      <div>
        <h2>Hola, ${user.fullname}</h2>
        <p>Este es un mensaje que contiene el código de validación para recuperar tu contraseña.</p>
        <p style="font-size: 16px;"><strong>Tu código es: ${codeValidation.code}</strong></p>
        <p>¡Gracias! Por favor, no respondas a este mensaje.</p>
      </div>
    `,
    };

    // Enviar el correo
    await sendMail(
      emailData.from,
      emailData.to,
      emailData.subject,
      emailData.html,
    );

    return {
      tokenValidation: codeValidation.tokenValidate,
      message: 'Recovery code sent to your email',
    };
  }

  // Servicio para verificar el código de recuperación
  async verifyRecoveryCode(
    code: number,
    token: string,
    ip: string,
  ): Promise<{ msg: string; token: string }> {
    const decodeToken = this.decodeToken(token);
    const isValid = await this.validateVerificationCode(code, token);

    if (!isValid) {
      throw new HttpException(
        'Invalid or expired code',
        HttpStatus.UNAUTHORIZED,
      );
    }

    // Crear el código de validación
    const codeValidation = await this.createCodeValidation({
      user_id: decodeToken.id,
      ip,
    });

    return {
      msg: 'Code verified successfully',
      token: codeValidation.tokenValidate,
    };
  }

  // Servicio para restablecer la contraseña
  async resetPassword(recoveryPasswordDto: RecoveryPasswordDto, ip: string) {
    const { id, new_password, confir_password, token_reset_pass } =
      recoveryPasswordDto;

    // Asegúrate de que el ID de usuario sea válido
    const user = await this.prisma.user.findUnique({
      where: { id },
    });

    if (!user) {
      await this.prisma.auditLog.create({
        data: {
          user_id: id,
          action: 'user_not_found_recovery_password',
          ip: ip,
          details: { reason: 'Invalid verification user' },
        },
      });
      throw new HttpException('User not found', HttpStatus.NOT_FOUND);
    }

    const findTokenSession = await this.prisma.verificationToken.findFirst({
      where: {
        session_token: token_reset_pass,
      },
    });

    if (!findTokenSession) {
      await this.prisma.auditLog.create({
        data: {
          user_id: id,
          action: 'token_invalid_reset_pass',
          ip: ip,
          details: { reason: 'Invalid verification token' },
        },
      });
      throw new HttpException(
        'Invalid or expired token',
        HttpStatus.UNAUTHORIZED,
      );
    }

    //Actualizar la contraseña
    await this.userService.updatePassword(id, {
      new_password,
      confir_password,
    });

    await this.prisma.verificationToken.delete({
      where: {
        session_token: token_reset_pass,
      },
    });

    await this.prisma.auditLog.deleteMany({
      where: {
        user_id: id,
        action: {
          in: ['token_invalid_reset_pass', 'user_not_found_recovery_password'], // Usa "in" para múltiples valores
        },
      },
    });

    return { success: true, message: 'Password has been reset successfully' };
  }

  async revoke_tokens(user_id: string) {
    try {
      await this.prisma.session.deleteMany({
        where: {
          user_id: user_id,
        },
      });
      return 'sessions revoke user success';
    } catch (error) {
      return 'error, sessions revoke user failed';
    }
  }
}
