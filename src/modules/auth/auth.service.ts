import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { PrismaService } from 'src/common/prisma/prisma.service';
import { LoginDto} from './dto/login.dto';
import { envs } from 'src/config';
import {
  DecodeJwt,
  JwtPayload,
  ValidationInput,
  VerificationToken,
} from './types';
import { UsersService } from '../users/users.service';
import { compare } from 'bcrypt';
import { RegisterAuthInput } from './dto/register.dto';
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

   // Método para decodificar el token y obtener la expiración
   private decodeToken(token: string): { exp: number } | null {
    try {
      const decoded = this.jwtService.decode(token) as { exp: number };
      return decoded;
    } catch (error) {
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
  private async generateToken(payload: JwtPayload, secret?: string, expiresIn?: string): Promise<{ token: string; expiresAt: number }> {
    const token = await this.jwtService.signAsync(payload, { secret, expiresIn });
  
    // Decodificar el token para obtener la expiración
    const decoded = this.decodeToken(token);
    const expiresAt = decoded ? decoded.exp : null;

    return { token, expiresAt };
   
  }

  //metodo para generar un acces token y refreshtoken a la vez 
  private async getTokens(payload: JwtPayload):Promise<{ access_token: string; refreshToken: string; accessExpiresAt?: number; refreshExpiresAt?: number }> {
    // Generar ambos tokens y sus respectivas fechas de expiración
    const [accessTokenData, refreshTokenData] = await Promise.all([
      this.generateToken(payload, envs.jwtSecret, envs.expire_token), // Token de acceso
      this.generateToken(payload, envs.jwtRefresh, envs.time_expires_refreshtoken), // Token de refresco
  ]);

  return {
      access_token: accessTokenData.token,
      refreshToken: refreshTokenData.token,
      accessExpiresAt: accessTokenData.expiresAt, // Fecha de expiración del token de acceso
      refreshExpiresAt: refreshTokenData.expiresAt, // Fecha de expiración del token de refresco
  };
  }


  //METODO QUE GENERA UN COODIGO DE VALIDACION CON UN TOKEN
  async createCodeValidation(validationInput: ValidationInput): Promise<{ tokenValidate: string; code: number }> {
    const { user_id, ip } = validationInput;

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
    const tokenValidate = await this.generateToken(payload, envs.jwtValidation);
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

    return { tokenValidate: tokenValidate.token, code: codeOtp };
  }

  async createSession(sessionInput: SessionInput): Promise<string> {
    const { session_token, user_id } = sessionInput;

    // Limitar sesiones activas
    await this.limitActiveSessions(user_id);

    const res = await this.prisma.session.create({
      data: sessionInput,
    });

    if (!res) throw new HttpException('Failed to create session', HttpStatus.NOT_FOUND);
    
    return 'Session created successfully';
  }

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
  private async findVerificationToken(userId: string): Promise<VerificationToken | null> {
    return await this.prisma.verificationToken.findFirst({
      where: { identifier: userId },
    });
  }

  //metodo que elimina si existe un token ya creado en la validacion
  async deleteTokenVerification(session_token: string): Promise<void> {
    await this.prisma.verificationToken.delete({
      where: { session_token },
    });
  }

  async logout(user_id: string, token: string): Promise<string> {
    const isValidRefreshToken = await this.verifyToken(token, envs.jwtRefresh);
    
    if (!isValidRefreshToken) throw new HttpException('Invalid refresh token', HttpStatus.NOT_FOUND);

    const res = await this.prisma.session.updateMany({
      where: { user_id, is_active: true, session_token: token },
      data: { is_active: false },
    });

    if (!res.count) throw new HttpException('No active session found', HttpStatus.NOT_FOUND);

    return 'Logout successful';
  }



  async login(loginDto: LoginDto, ip?: string): Promise<LoginAuthResponse> {
    const { username, email, password } = loginDto;
    let msg: string;
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

      await sendMail(
        dataEmail.from,
        dataEmail.to,
        dataEmail.subject,
        dataEmail.html,
      );

      return {
        token_validation: res.tokenValidate,
        msg: 'You must validate your income by email',
      };
    }


    //generates the access token and the refresh token, extract token expiration time
    const { access_token,refreshToken, accessExpiresAt, refreshExpiresAt } = await this.getTokens(payload);


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

  // /// register user
  // async register(registerAuthInput: RegisterAuthInput) {
  //   return await this.userService.create(registerAuthInput);
  // }

  // //refresh token

  // async validateSession(token: string, ip: string): Promise<LoginAuthResponse> {
  //   // Verificar la validez del token de refresco
  //   const validRefreshToken = await this.verifyRefreshToken(token);
  //   if (!validRefreshToken)
  //     throw new HttpException('Invalid refresh token', HttpStatus.UNAUTHORIZED);

  //   const decodeRefreshToken = this.decodeToken(token);
  //   // Verificar si la sesión está activa
  //   const session = await this.prisma.session.findFirst({
  //     where: {
  //       user_id: decodeRefreshToken.id,
  //       session_token: token,
  //       is_active: true,
  //     },
  //   });

  //   if (!session) {
  //     throw new HttpException(
  //       'No active session found',
  //       HttpStatus.UNAUTHORIZED,
  //     );
  //   }

  //   // Verificar si la sesión ha expirado
  //   const currentTime = Math.floor(Date.now() / 1000); // Tiempo actual en segundos
  //   if (session.expires < currentTime) {
  //     throw new HttpException('Session has expired', HttpStatus.UNAUTHORIZED);
  //   }

  //   //build the data for the token
  //   const payload = {
  //     iss: envs.issuer,
  //     id: decodeRefreshToken.id,
  //     user: decodeRefreshToken.user,
  //     email: decodeRefreshToken.email,
  //     role: decodeRefreshToken.role,
  //   };

  //   const ipClient = this.decodeClientIp(ip);

  //   //generates the access token , extract token expiration time
  //   const access_token = await this.generateAccesToken(payload);
  //   const decodeToken = this.decodeToken(access_token);
  //   await this.prisma.session.update({
  //     where: {
  //       session_token: token,
  //     },
  //     data: {
  //       last_activity: new Date(),
  //       ip: ipClient,
  //     },
  //   });

  //   return {
  //     accessToken: access_token,
  //     accessTokenExpiration: decodeToken.exp,
  //     msg: 'successful entry',
  //   };
  // }

  // //validate code session
  // async validateCode(code: number, token: string): Promise<boolean> {
  //   // Verificar la validez del token
  //   const validToken = await this.verifyValidationToken(token);

  //   if (!validToken)
  //     throw new HttpException(
  //       'Invalid validate token ',
  //       HttpStatus.UNAUTHORIZED,
  //     );

  //   const res = await this.prisma.verificationToken.findFirst({
  //     where: {
  //       code: code,
  //       session_token: token,
  //     },
  //   });
  //   if (res === null)
  //     throw new HttpException('invalid code', HttpStatus.UNAUTHORIZED);

  //   const expiresCode = isDateExpired(res.expires);

  //   if (expiresCode)
  //     throw new HttpException('code expired', HttpStatus.UNAUTHORIZED);

  //   if (validToken && res !== null && !expiresCode) {
  //     await this.prisma.verificationToken.delete({
  //       where: {
  //         session_token: token,
  //         code: code,
  //       },
  //     });
  //     return true;
  //   } else {
  //     throw new HttpException('invalid code', HttpStatus.UNAUTHORIZED);
  //   }
  // }

  // async validateCodeLogin(
  //   code: number,
  //   token: string,
  //   ip?: string,
  // ): Promise<LoginAuthResponse> {
  //   // Verificar la validez del token de refresco
  //   const validateToken = await this.validateCode(code, token);

  //   if (!validateToken)
  //     throw new HttpException('invalid code', HttpStatus.UNAUTHORIZED);

  //   const ipClient = this.decodeClientIp(ip);
  //   const decodeValidateToken = this.decodeToken(token);

  //   const payload = {
  //     iss: envs.issuer,
  //     id: decodeValidateToken.id,
  //     user: decodeValidateToken.user,
  //     email: decodeValidateToken.email,
  //     role: decodeValidateToken.role,
  //   };

  //   //generates the access token and the refresh token, extract token expiration time
  //   const { access_token, refreshToken }: Record<string, string> =
  //     await this.getTokens(payload);
  //   const decodeToken = this.decodeToken(access_token);
  //   const decodeRefresh = this.decodeToken(refreshToken);

  //   await this.createSession({
  //     session_token: refreshToken,
  //     user_id: decodeValidateToken.id,
  //     expires: decodeRefresh.exp,
  //     is_active: true,
  //     ip: ipClient,
  //   });

  //   const findUser = await this.userService.findUserById(
  //     decodeValidateToken.id,
  //   );
  //   if (findUser.emailVerified === null) {
  //     await this.prisma.user.update({
  //       where: {
  //         id: decodeValidateToken.id,
  //       },
  //       data: {
  //         emailVerified: new Date(),
  //         two_fa: true,
  //       },
  //     });
  //   }

  //   return {
  //     accessToken: access_token,
  //     accessTokenExpiration: decodeToken.exp,
  //     refreshToken: refreshToken,
  //     refreshTokenExpiration: decodeRefresh.exp,
  //     msg: 'successful entry',
  //     user: {
  //       id: findUser.id,
  //       username: findUser.username,
  //       fullname: findUser.fullname,
  //       email: findUser.email,
  //       phone: findUser.phone,
  //       role: findUser.rol,
  //     },
  //   };
  // }

  // async codeRecoveryPassword(ip: string, emailPasswordDto: EmailPasswordDto) {
  //   const { email } = emailPasswordDto;
  //   const findUser = await this.prisma.user.findFirst({
  //     where: {
  //       email: email,
  //     },
  //     include: {
  //       role: {
  //         include: {
  //           rol: {
  //             select: {
  //               name: true,
  //             },
  //           },
  //         },
  //       },
  //     },
  //   });
  //   if (findUser === null)
  //     throw new HttpException(
  //       'Email not registered for any user ',
  //       HttpStatus.UNAUTHORIZED,
  //     );

  //   const res = await this.createValidation({
  //     user_id: findUser.id,
  //     ip: ip,
  //   });

  //   const dataEmail = {
  //     from: envs.supportEmail,
  //     to: [`${findUser.email}`],
  //     subject: 'CÓDGIO DE VALIDACIÓN RECUPERACIÓN CONTRASEÑA',
  //     html: `
  //     <div>
  //         <h2>Hola, ${findUser.fullname}</h2>
  //         <p>Este es un mensaje contiene el código de validación para recuperar tu contraseña.</p>
  //         <p style="font-size: 16px;"><strong>Tu código es: ${res.code}</strong></p>
  //         <p>¡Gracias por favor no responder este mensaje!</p>
  //     </div>
  //     `,
  //   };

  //   await sendMail(
  //     dataEmail.from,
  //     dataEmail.to,
  //     dataEmail.subject,
  //     dataEmail.html,
  //   );

  //   return {
  //     two_fa: true,
  //     tokenValidation: res.tokenValidate,
  //     msg: 'You must validate your income by email',
  //   };
  // }

  // async validateCodePassword(code: number, token: string): Promise<string> {
  //   // Verificar la validez del token de refresco

  //   const validateToken = await this.validateCode(code, token);
  //   if (!validateToken)
  //     throw new HttpException('invalid code', HttpStatus.UNAUTHORIZED);
  //   return 'valid code';
  // }

  // async recovery_password(recoveryPasswordDto: RecoveryPasswordDto) {
  //   const { id, ...dtoWithoutId } = recoveryPasswordDto;
  //   return await this.userService.updatePasswordByAdmin(id, dtoWithoutId);
  // }
}

