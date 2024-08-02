import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { PrismaService } from 'src/common/prisma/prisma.service';
import { LoginAuthInput } from './dto/login.dto';
import { envs } from 'src/config';
import { JwtPayload, ValidationInput } from './types';
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

@Injectable()
export class AuthService {
  private readonly MAX_SESSIONS = 5; // Maximum number of active sessions
  constructor(
    private readonly prisma: PrismaService,
    private readonly userService: UsersService,
    private readonly configAuthService: ConfigAuthService,

    private jwtService: JwtService,
  ) {}

  decodeAccessToken(token: string) {
    try {
      const decoded = this.jwtService.decode(token);
      return decoded;
    } catch (error) {
      throw new Error('Invalid token');
    }
  }

  decodeRefreshToken(refreshToken: string) {
    try {
      const decoded = this.jwtService.decode(refreshToken);
      return decoded;
    } catch (error) {
      throw new Error('Invalid token');
    }
  }

  decodeValidateToken(Token: string) {
    try {
      const decoded = this.jwtService.decode(Token);
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

  async createValidation(validationInput: ValidationInput) {
    const { useCase, jwt, code, userId, expireAt } = validationInput;
    const expires = getExpiryCode(expireAt);
    const res = await this.prisma.verification_tokens.create({
      data: {
        useCase: useCase,
        jwt: jwt,
        code: code,
        userId: userId,
        expireAt: expires,
      },
    });
    return res;
  }

  async createSession(loginSessionInput: LoginSessionInput) {
    const { jwt, userId, expireAt, is_active } = loginSessionInput;

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
        await this.prisma.sessions_auth.delete({
          where: { id: oldestSession.id }, // delete the session if you prefer
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
      },
    });
    return res;
  }

  async findVerificationToken(userdId: string, useCase: UseCase) {
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

  async logout(userId: string, token: string) {
    const verifiedToken = await this.verifyRefreshToken(token);
    if (!verifiedToken)
      throw new HttpException('Invalid refresh token', HttpStatus.NOT_FOUND);

    const res = await this.prisma.sessions_auth.delete({
      where: { userId: userId, is_active: true, jwt: token },
    });

    if (!res)
      throw new HttpException('No active session found', HttpStatus.NOT_FOUND);

    return 'Logout successful';
  }

  async login(loginAuthInput: LoginAuthInput): Promise<LoginAuthResponse> {
    const { username, password } = loginAuthInput;
    let msg: string;
    const findUser = await this.userService.findUserByUsername(username);
    const findConfigAuth = await this.configAuthService.findAll(); //look for the general auth configuration

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

    if (
      (findUser.twoFA && findUser.isEmailVerified === false) ||
      (findUser.twoFA && findUser.isEmailVerified)
    ) {
      // Check if double verification is active and if the email is already validated
      //Generates a token and creates a record to validate which is sent by email to be able to enter and obtain a valid token
      const findVerification = await this.findVerificationToken(
        findUser.id,
        'E2FA',
      );

      if (findVerification) {
        await this.deleteTokenVerification(findVerification.jwt);
      }

      const validationToken = await this.generateTokenValidation(
        payload,
        findConfigAuth.time_life_code,
      );
      const codeOtp = generateOTP();
      await this.createValidation({
        useCase: 'E2FA',
        jwt: validationToken,
        code: codeOtp,
        userId: findUser.id,
        expireAt: findConfigAuth.time_life_code,
        url: envs.issuer + `validar?token=${validationToken}`,
      });
      return {
        twoFA: true,
        tokenValidation: validationToken,
        code: codeOtp,
        msg: 'You must validate your income by email',
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
    const decodeToken = this.decodeAccessToken(access_token);
    const decodeRefresh = this.decodeRefreshToken(refreshToken);

    await this.createSession({
      jwt: refreshToken,
      userId: findUser.id,
      expireAt: decodeRefresh.exp,
      is_active: true,
    });

    return {
      access_token: access_token,
      expire_access_token: decodeToken.exp,
      refreshToken: refreshToken,
      expire_refresh_token: decodeRefresh.exp,
      msg: msg,
    };
  }

  /// register user
  async register(registerAuthInput: RegisterAuthInput) {
    return await this.userService.create(registerAuthInput);
  }

  //refresh token

  async validateSession(token: string): Promise<LoginAuthResponse> {
    // Verificar la validez del token de refresco
    const validRefreshToken = await this.verifyRefreshToken(token);
    if (!validRefreshToken)
      throw new HttpException('Invalid refresh token', HttpStatus.UNAUTHORIZED);

    const decodeRefreshToken = await this.decodeRefreshToken(token);
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

    //generates the access token , extract token expiration time
    const access_token = await this.generateAccesToken(payload);
    const decodeToken = await this.decodeAccessToken(access_token);
    await this.prisma.sessions_auth.update({
      where: {
        jwt: token,
      },
      data: {
        last_activity: new Date(),
      },
    });

    return {
      access_token: access_token,
      expire_access_token: decodeToken.exp,
      msg: 'successful entry',
    };
  }

  async validateCode(code: number, token: string) {
    // Verificar la validez del token de refresco
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

    const decodeValidateToken = this.decodeValidateToken(token);

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
    const decodeToken = this.decodeAccessToken(access_token);
    const decodeRefresh = this.decodeRefreshToken(refreshToken);

    await this.createSession({
      jwt: refreshToken,
      userId: decodeValidateToken.id,
      expireAt: decodeRefresh.exp,
      is_active: true,
    });

    await this.prisma.verification_tokens.delete({
      where: {
        jwt: token,
        code: code,
      },
    });

    return {
      access_token: access_token,
      expire_access_token: decodeToken.exp,
      refreshToken: refreshToken,
      expire_refresh_token: decodeRefresh.exp,
      msg: 'successful entry',
    };
  }
}