import {
  Body,
  Res,
  Controller,
  Get,
  HttpCode,
  Ip,
  Post,
  Query,
  Req,
  UseGuards,
  HttpException,
  HttpStatus,
} from '@nestjs/common';
import { Request, Response } from 'express';
import { Public } from './decorators/public-decorator';
import { LoginDto } from './dto/login.dto';
import { AuthService } from './auth.service';
import { RegisterDto } from './dto/register.dto';
import { LoginAuthResponse } from './types/login';
import { JwtAuthGuard } from './guards/jwt-auth-guard';
import {
  EmailPasswordDto,
  RecoveryPasswordDto,
} from './dto/recoveryPassword.dto';
import { envs } from 'src/config';
import { Auth } from './decorators/auth.decorator';
import { Role } from './types';
import {
  ApiBearerAuth,
  ApiTags,
  ApiUnauthorizedResponse,
} from '@nestjs/swagger';

@ApiTags('auth')
@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Public()
  @Post('login')
  @HttpCode(200)
  async login(
    @Ip() ip: string,
    @Body() loginDto: LoginDto,
    @Res({ passthrough: true }) res: Response,
  ): Promise<Partial<LoginAuthResponse>> {
    const authResponse = await this.authService.login(loginDto, ip);
    // Verificar si la respuesta incluye los tokens (el usuario no tiene doble verificación activa)
    if (authResponse.refresh_token && authResponse.expiration_refreshToken) {
      const refreshExpiresAt = authResponse.expiration_refreshToken * 1000; // Convertir a milisegundos
      const now = Date.now();
      const maxAge = refreshExpiresAt - now;

      // Configurar la cookie solo si la duración es válida
      if (maxAge > 0) {
        res.cookie('auth_session_token', authResponse.refresh_token, {
          httpOnly: true, // Solo accesible desde el servidor
          secure: envs.node_env === 'production', // Requiere HTTPS
          sameSite: 'strict', // Evita el uso en contextos de terceros
          maxAge, // Duración en milisegundos
        });
      }
      const { refresh_token, expiration_refreshToken, ...filteredResponse } =
        authResponse;
      return filteredResponse;
    } else {
      const { refresh_token, expiration_refreshToken, ...filteredResponse } =
        authResponse;
      return filteredResponse;
    }
  }

  @Public()
  @Post('register')
  @HttpCode(201)
  register(@Body() registerDto: RegisterDto) {
    return this.authService.register(registerDto);
  }

  @Public()
  @Get('refresh-token')
  @HttpCode(200)
  async refreshToken(
    @Ip() ip: string,
    @Res({ passthrough: true }) res: Response,
    @Req() req: Request, // Obtenemos el request completo para acceder a las cookies
  ) {
    // Obtener el refresh token de la cookie
    const refreshToken = req.cookies?.auth_session_token;

    if (!refreshToken) {
      throw new HttpException(
        'Refresh token not found in cookies',
        HttpStatus.UNAUTHORIZED,
      );
    }

    const authResponse = await this.authService.refreshSession(
      refreshToken,
      ip,
    );

    const refreshExpiresAt = authResponse.expiration_refreshToken * 1000; // Convertir a milisegundos
    const now = Date.now();
    const maxAge = refreshExpiresAt - now;

    if (maxAge > 0) {
      res.cookie('auth_session_token', authResponse.refresh_token, {
        httpOnly: true, // Solo accesible desde el servidor
        secure: process.env.NODE_ENV === 'production', // Solo HTTPS en producción
        sameSite: 'strict', // Estricto para evitar CSRF
        maxAge, // Tiempo de expiración en milisegundos
      });
    }

    // Filtramos la respuesta para no incluir datos sensibles
    const { refresh_token, expiration_refreshToken, ...filteredResponse } =
      authResponse;

    return filteredResponse;
  }

  @ApiBearerAuth()
  @ApiUnauthorizedResponse({
    description: 'Unauthorized Bearer Token Auth',
  })
  @UseGuards(JwtAuthGuard)
  @Get('logout')
  @HttpCode(200)
  logout(
    @Req() req: Request, // Obtenemos el request completo para acceder a las cookies
  ) {
    // Acceder al userId desde la request (anexado por JwtAuthGuard)
    const { userId }: any = req.user; // Aquí obtienes el userId del token
    const refreshToken = req.cookies?.auth_session_token;

    // Pasar el loggedInUserId al servicio, en lugar de userId
    return this.authService.logout(userId, refreshToken);
  }

  @Public()
  @Get('verifyTwoFactorLogin')
  @HttpCode(200)
  async verifyTwoFactorLogin(
    @Ip() ip: string,
    @Query('token') token: string,
    @Query('code') code: string,
    @Res({ passthrough: true }) res: Response,
  ) {
    const authResponse = await this.authService.verifyTwoFactorLogin(
      parseInt(code),
      token,
      ip,
    );
    // Verificar si la respuesta incluye los tokens (el usuario no tiene doble verificación activa)

    const refreshExpiresAt = authResponse.expiration_refreshToken * 1000; // Convertir a milisegundos
    const now = Date.now();
    const maxAge = refreshExpiresAt - now;

    // Configurar la cookie solo si la duración es válida
    if (maxAge > 0) {
      res.cookie('auth_session_token', authResponse.refresh_token, {
        httpOnly: true, // Solo accesible desde el servidor
        secure: envs.node_env === 'production', // Requiere HTTPS
        sameSite: 'strict', // Evita el uso en contextos de terceros
        maxAge, // Duración en milisegundos
      });
    }
    const { refresh_token, expiration_refreshToken, ...filteredResponse } =
      authResponse;
    return filteredResponse;
  }

  @Public()
  @Post('send-code-recovery-password')
  @HttpCode(200)
  async sendRecoveryCode(
    @Ip() ip: string,
    @Body() emailPasswordDto: EmailPasswordDto,
  ) {
    return this.authService.sendRecoveryCode(ip, emailPasswordDto);
  }

  @Public()
  @Get('verify-code-recovery-password')
  @HttpCode(200)
  async verifyRecoveryCode(
    @Query('token') token: string,
    @Query('code') code: string,
    @Ip() ip: string,
  ) {
    return this.authService.verifyRecoveryCode(parseInt(code), token, ip);
  }

  @Public()
  @Post('reset-password')
  @HttpCode(200)
  async resetPassword(
    @Ip() ip: string,
    @Body() recoveryPasswordDto: RecoveryPasswordDto,
  ) {
    return this.authService.resetPassword(recoveryPasswordDto, ip);
  }

  @UseGuards(JwtAuthGuard)
  @Auth(Role.ADMIN)
  @Post('revoke-user-session')
  @HttpCode(200)
  async revoke_tokens(@Body() userd_id: string) {
    return this.authService.revoke_tokens(userd_id);
  }
}
