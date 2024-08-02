import {
  Body,
  Controller,
  Get,
  HttpCode,
  Post,
  Query,
  Req,
  UseGuards,
} from '@nestjs/common';
import { Public } from './decorators/public-decorator';
import { LoginAuthInput } from './dto/login.dto';
import { AuthService } from './auth.service';
import { RegisterAuthInput } from './dto/register.dto';
import { LoginAuthResponse } from './types/login';
import { RefreshTokenInput } from './dto/refreshToken.dto';
import { LogoutDtoInput } from './dto/logout.dto';
import { JwtAuthGuard } from './guards/jwt-auth-guard';
import { ValidateCodeInput } from './dto/validateCode.dto';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Public()
  @Post('login')
  @HttpCode(200)
  login(@Body() loginAuthInput: LoginAuthInput): Promise<LoginAuthResponse> {
    return this.authService.login(loginAuthInput);
  }

  @Public()
  @Post('register')
  @HttpCode(201)
  register(@Body() registerAuthInput: RegisterAuthInput) {
    return this.authService.register(registerAuthInput);
  }

  @Public()
  @Post('refresh_token')
  @HttpCode(200)
  async refreshToken(@Body() refreshTokenInput: RefreshTokenInput) {
    return await this.authService.validateSession(
      refreshTokenInput.refreshToken,
    );
  }

  @UseGuards(JwtAuthGuard)
  @Post('logout')
  @HttpCode(200)
  logout(@Body() logoutDtoInput: LogoutDtoInput) {
    const { userId, refreshToken } = logoutDtoInput;
    return this.authService.logout(userId, refreshToken);
  }

  @Public()
  @Get('validate_code')
  @HttpCode(200)
  validate_code(@Query('token') token: string, @Query('code') code: string) {
    return this.authService.validateCode(parseInt(code), token);
  }
}
