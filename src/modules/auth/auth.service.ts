import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { PrismaService } from 'src/common/prisma/prisma.service';
import { LoginAuthInput } from './dto/login.dto';
import { envs } from 'src/config';
import {
  DecodeJwt,
  JwtPayload,
  ValidationInput,
  Verification_Tokens,
} from './types';
import { UsersService } from '../users/users.service';
import { ConfigAuthService } from '../config_auth/config_auth.service';
import { compare } from 'bcrypt';
import { RegisterAuthInput } from './dto/register.dto';
import { LoginAuthResponse, LoginSessionInput } from './types/login';
import {
  getExpiry,
  getExpiryCode,
  isDateExpired,
} from 'src/common/utils/dateTimeUtility';
import { generateOTP } from 'src/common/utils/otpCode';
import { UseCase } from '@prisma/client';
import {
  EmailPasswordDto,
  RecoveryPasswordDto,
} from './dto/recoveryPassword.dto';
import { sendMail } from 'src/common/utils/resend';

@Injectable()
export class AuthService {
  private readonly MAX_SESSIONS = 5; // Maximum number of active sessions
  constructor(
    private readonly prisma: PrismaService,
    private readonly userService: UsersService,
    private readonly configAuthService: ConfigAuthService,

    private jwtService: JwtService,
  ) {}

  decodeClientIp(ip: string): string {
    if (ip.startsWith('::ffff:')) {
      return ip.substring(7);
    }
    return ip;
  }

  decodeToken(token: string): DecodeJwt {
    try {
      const decoded = this.jwtService.decode(token);
      return decoded;
    } catch (error) {
      throw new Error('Invalid token');
    }
  }

  async verifyAccessToken(token: string): Promise<boolean> {
    try {
      // Check refresh token validity
      await this.jwtService.verifyAsync(token);
      return true;
    } catch (error) {
      return false;
    }
  }

  async verifyRefreshToken(refreshToken: string): Promise<boolean> {
    try {
      // Check refresh token validity
      await this.jwtService.verifyAsync(refreshToken, {
        secret: envs.jwtRefresh,
      });
      return true;
    } catch (error) {
      return false;
    }
  }

  async verifyValidationToken(validationToken: string): Promise<boolean> {
    try {
      // Check refresh token validity
      await this.jwtService.verifyAsync(validationToken, {
        secret: envs.jwtValidation,
      });
      return true;
    } catch (error) {
      return false;
    }
  }

  async generateAccesToken(payload: JwtPayload): Promise<string> {
    return await this.jwtService.signAsync(payload);
  }

  async generateRefresToken(payload: JwtPayload): Promise<string> {
    return await this.jwtService.signAsync(payload, {
      secret: envs.jwtRefresh,
      expiresIn: '24h',
    });
  }

  async generateTokenValidation(
    payload: JwtPayload,
    expirationSeconds: number,
  ): Promise<string> {
    return await this.jwtService.signAsync(payload, {
      secret: envs.jwtValidation,
      expiresIn: expirationSeconds,
    });
  }

  async getTokens(
    payload: JwtPayload,
  ): Promise<{ access_token: string; refreshToken: string }> {
    const [access_token, refreshToken] = await Promise.all([
      this.jwtService.signAsync(payload),
      this.jwtService.signAsync(payload, {
        secret: envs.jwtRefresh,
        expiresIn: '24h',
      }),
    ]);

    return {
      access_token,
      refreshToken,
    };
  }

  async createValidation(
    validationInput: ValidationInput,
  ): Promise<{ tokenValidate: string; code: number; url: string }> {
    const { userId, useCase, ip } = validationInput;
    const findVerification = await this.findVerificationToken(userId, useCase);

    if (findVerification) {
      await this.deleteTokenVerification(findVerification.jwt);
    }

    const findUser = await this.userService.findUserById(userId);

    const payload = {
      iss: envs.issuer,
      id: findUser.id,
      user: findUser.username,
      email: findUser.email,
      role: findUser.rol.name,
    };

    const ipClient = this.decodeClientIp(ip);
    const findConfigAuth = await this.configAuthService.findAll(); //look for the general auth configuration

    const generateToken = await this.generateTokenValidation(
      payload,
      findConfigAuth.time_life_code,
    );
    const codeOtp = generateOTP();

    const expires = getExpiryCode(findConfigAuth.time_life_code);
    const res = await this.prisma.verification_tokens.create({
      data: {
        useCase: useCase,
        jwt: generateToken,
        code: codeOtp,
        userId: userId,
        expireAt: expires,
        ip: ipClient,
      },
    });
    if (res === null)
      throw new HttpException(
        'Failed to create verification token',
        HttpStatus.NOT_FOUND,
      );

    return {
      tokenValidate: generateToken,
      code: codeOtp,
      url: envs.issuer + `/validate_code?token=${generateToken}`,
    };
  }

  async createSession(loginSessionInput: LoginSessionInput): Promise<string> {
    const { jwt, userId, expireAt, is_active, ip } = loginSessionInput;

    // Check how many active sessions the user has
    const activeSessions = await this.prisma.sessions_auth.count({
      where: { userId: userId, is_active: true },
    });

    // If the user already has the maximum number of sessions, delete the oldest one
    if (activeSessions >= this.MAX_SESSIONS) {
      const oldestSession = await this.prisma.sessions_auth.findFirst({
        where: { userId: userId, is_active: true },
        orderBy: { createdAt: 'asc' }, // Assuming you have a createdAt field
      });

      if (oldestSession) {
        await this.prisma.sessions_auth.update({
          where: { id: oldestSession.id }, // delete the session if you prefer
          data: {
            is_active: false,
          },
        });
      }
    }

    // Create the new session
    const res = await this.prisma.sessions_auth.create({
      data: {
        userId: userId,
        jwt: jwt,
        expireAt: expireAt,
        is_active: is_active,
        ip: ip,
      },
    });
    if (res === null)
      throw new HttpException('Failed to create session', HttpStatus.NOT_FOUND);
    return 'successful create session';
  }

  async findVerificationToken(
    userdId: string,
    useCase: UseCase,
  ): Promise<Verification_Tokens> {
    return await this.prisma.verification_tokens.findFirst({
      where: {
        userId: userdId,
        AND: {
          useCase: useCase,
        },
      },
    });
  }

  async deleteTokenVerification(jwt: string) {
    return await this.prisma.verification_tokens.delete({
      where: {
        jwt,
      },
    });
  }

  async logout(userId: string, token: string): Promise<String> {
    const verifiedToken = await this.verifyRefreshToken(token);
    if (!verifiedToken)
      throw new HttpException('Invalid refresh token', HttpStatus.NOT_FOUND);

    const res = await this.prisma.sessions_auth.update({
      where: { userId: userId, is_active: true, jwt: token },
      data: {
        is_active: false,
      },
    });

    if (!res)
      throw new HttpException('No active session found', HttpStatus.NOT_FOUND);

    return 'Logout successful';
  }

  async login(
    loginAuthInput: LoginAuthInput,
    ip?: string,
  ): Promise<LoginAuthResponse> {
    const { username, password } = loginAuthInput;
    let msg: string;
    const findUser = await this.userService.findUserByUsername(username);

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

    if (
      (findUser.twoFA && findUser.isEmailVerified === false) ||
      (findUser.twoFA && findUser.isEmailVerified)
    ) {
      // Check if double verification is active and if the email is already validated
      //Generates a token and creates a record to validate which is sent by email to be able to enter and obtain a valid token
      const res = await this.createValidation({
        useCase: 'E2FA',
        userId: findUser.id,
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
        twoFA: true,
        tokenValidation: res.tokenValidate,
        msg: 'You must validate your income by email',
        url: res.url,
      };

      //falta el envio por correo del codigo y quitar de la respuesta el codigo
    }

    //valid date expires password
    const expiredPass = isDateExpired(findUser.expirepass);
    if (expiredPass || findUser.force_new_pass) {
      msg = 'Password needs to be updated';
    } else {
      msg = 'successful entry';
    }

    //generates the access token and the refresh token, extract token expiration time
    const { access_token, refreshToken }: Record<string, string> =
      await this.getTokens(payload);
    const decodeToken = this.decodeToken(access_token);
    const decodeRefresh = this.decodeToken(refreshToken);

    await this.createSession({
      jwt: refreshToken,
      userId: findUser.id,
      expireAt: decodeRefresh.exp,
      is_active: true,
      ip: ipClient,
    });

    return {
      access_token: access_token,
      expire_access_token: decodeToken.exp,
      refreshToken: refreshToken,
      expire_refresh_token: decodeRefresh.exp,
      msg: msg,
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
  async register(registerAuthInput: RegisterAuthInput) {
    return await this.userService.create(registerAuthInput);
  }

  //refresh token

  async validateSession(token: string, ip: string): Promise<LoginAuthResponse> {
    // Verificar la validez del token de refresco
    const validRefreshToken = await this.verifyRefreshToken(token);
    if (!validRefreshToken)
      throw new HttpException('Invalid refresh token', HttpStatus.UNAUTHORIZED);

    const decodeRefreshToken = await this.decodeToken(token);
    // Verificar si la sesión está activa
    const session = await this.prisma.sessions_auth.findFirst({
      where: {
        userId: decodeRefreshToken.id,
        jwt: token,
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
    if (session.expireAt < currentTime) {
      throw new HttpException('Session has expired', HttpStatus.UNAUTHORIZED);
    }

    //build the data for the token
    const payload = {
      iss: envs.issuer,
      id: decodeRefreshToken.id,
      user: decodeRefreshToken.user,
      email: decodeRefreshToken.email,
      role: decodeRefreshToken.role,
    };

    const ipClient = this.decodeClientIp(ip);

    //generates the access token , extract token expiration time
    const access_token = await this.generateAccesToken(payload);
    const decodeToken = await this.decodeToken(access_token);
    await this.prisma.sessions_auth.update({
      where: {
        jwt: token,
      },
      data: {
        last_activity: new Date(),
        ip: ipClient,
      },
    });

    return {
      access_token: access_token,
      expire_access_token: decodeToken.exp,
      msg: 'successful entry',
    };
  }

  //validate code session
  async validateCode(code: number, token: string): Promise<boolean> {
    // Verificar la validez del token
    const validToken = await this.verifyValidationToken(token);

    if (!validToken)
      throw new HttpException(
        'Invalid validate token ',
        HttpStatus.UNAUTHORIZED,
      );

    const res = await this.prisma.verification_tokens.findFirst({
      where: {
        code: code,
        jwt: token,
      },
    });
    if (res === null)
      throw new HttpException('invalid code', HttpStatus.UNAUTHORIZED);

    const expiresCode = isDateExpired(res.expireAt);

    if (expiresCode)
      throw new HttpException('code expired', HttpStatus.UNAUTHORIZED);

    if (validToken && res !== null && !expiresCode) {
      await this.prisma.verification_tokens.delete({
        where: {
          jwt: token,
          code: code,
        },
      });
      return true;
    } else {
      throw new HttpException('invalid code', HttpStatus.UNAUTHORIZED);
    }
  }

  async validateCodeLogin(
    code: number,
    token: string,
    ip?: string,
  ): Promise<LoginAuthResponse> {
    // Verificar la validez del token de refresco
    const validateToken = await this.validateCode(code, token);

    if (!validateToken)
      throw new HttpException('invalid code', HttpStatus.UNAUTHORIZED);

    const ipClient = this.decodeClientIp(ip);
    const decodeValidateToken = this.decodeToken(token);

    const payload = {
      iss: envs.issuer,
      id: decodeValidateToken.id,
      user: decodeValidateToken.user,
      email: decodeValidateToken.email,
      role: decodeValidateToken.role,
    };

    //generates the access token and the refresh token, extract token expiration time
    const { access_token, refreshToken }: Record<string, string> =
      await this.getTokens(payload);
    const decodeToken = this.decodeToken(access_token);
    const decodeRefresh = this.decodeToken(refreshToken);

    await this.createSession({
      jwt: refreshToken,
      userId: decodeValidateToken.id,
      expireAt: decodeRefresh.exp,
      is_active: true,
      ip: ipClient,
    });

    const findUser = await this.userService.findUserById(
      decodeValidateToken.id,
    );
    if (findUser.isEmailVerified === false) {
      await this.prisma.users.update({
        where: {
          id: decodeValidateToken.id,
        },
        data: {
          isEmailVerified: true,
          twoFA: true,
        },
      });
    }

    return {
      access_token: access_token,
      expire_access_token: decodeToken.exp,
      refreshToken: refreshToken,
      expire_refresh_token: decodeRefresh.exp,
      msg: 'successful entry',
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

  async codeRecoveryPassword(ip: string, emailPasswordDto: EmailPasswordDto) {
    const { email } = emailPasswordDto;
    const findUser = await this.prisma.users.findFirst({
      where: {
        email: email,
      },
      include: {
        roles: {
          include: {
            rol: {
              select: {
                name: true,
              },
            },
          },
        },
      },
    });
    if (findUser === null)
      throw new HttpException(
        'Email not registered for any user ',
        HttpStatus.UNAUTHORIZED,
      );

    const res = await this.createValidation({
      useCase: 'VEM',
      userId: findUser.id,
      ip: ip,
    });

    const dataEmail = {
      from: envs.supportEmail,
      to: [`${findUser.email}`],
      subject: 'CÓDGIO DE VALIDACIÓN RECUPERACIÓN CONTRASEÑA',
      html: `
      <div>
          <h2>Hola, ${findUser.fullname}</h2>
          <p>Este es un mensaje contiene el código de validación para recuperar tu contraseña.</p>
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
      twoFA: true,
      tokenValidation: res.tokenValidate,
      msg: 'You must validate your income by email',
      url: res.url,
    };
  }

  async validateCodePassword(code: number, token: string): Promise<string> {
    // Verificar la validez del token de refresco

    const validateToken = await this.validateCode(code, token);
    if (!validateToken)
      throw new HttpException('invalid code', HttpStatus.UNAUTHORIZED);
    return 'valid code';
  }

  async recovery_password(recoveryPasswordDto: RecoveryPasswordDto) {
    const { id, ...dtoWithoutId } = recoveryPasswordDto;
    return await this.userService.updatePasswordByAdmin(id, dtoWithoutId);
  }
}
