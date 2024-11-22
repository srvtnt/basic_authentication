import {
  Body,
  Controller,
  Get,
  HttpCode,
  Ip,
  Param,
  Post,
  Query,
  Req,
  UseGuards,
} from '@nestjs/common';
import { Public } from './decorators/public-decorator';
import {  LoginDto } from './dto/login.dto';
import { AuthService } from './auth.service';
import { RegisterAuthInput } from './dto/register.dto';
import { LoginAuthResponse } from './types/login';
import { RefreshTokenInput } from './dto/refreshToken.dto';
import { LogoutDtoInput } from './dto/logout.dto';
import { JwtAuthGuard } from './guards/jwt-auth-guard';
import {
  EmailPasswordDto,
  RecoveryPasswordDto,
} from './dto/recoveryPassword.dto';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Public()
  @Post('login')
  @HttpCode(200)
  login(
    @Ip() ip: string,
    @Body() loginDto: LoginDto,
  ): Promise<LoginAuthResponse> {
    return this.authService.login(loginDto, ip);
  }

  // @Public()
  // @Post('register')
  // @HttpCode(201)
  // register(@Body() registerAuthInput: RegisterAuthInput) {
  //   return this.authService.register(registerAuthInput);
  // }

  // @Public()
  // @Post('refresh_token')
  // @HttpCode(200)
  // async refreshToken(
  //   @Ip() ip: string,
  //   @Body() refreshTokenInput: RefreshTokenInput,
  // ) {
  //   return await this.authService.validateSession(
  //     refreshTokenInput.refreshToken,
  //     ip,
  //   );
  // }

  // @UseGuards(JwtAuthGuard)
  // @Post('logout')
  // @HttpCode(200)
  // logout(@Body() logoutDtoInput: LogoutDtoInput) {
  //   const { userId, refreshToken } = logoutDtoInput;
  //   return this.authService.logout(userId, refreshToken);
  // }

  // @Public()
  // @Get('validate_code_login')
  // @HttpCode(200)
  // validate_code_login(
  //   @Ip() ip: string,
  //   @Query('token') token: string,
  //   @Query('code') code: string,
  // ) {
  //   return this.authService.validateCodeLogin(parseInt(code), token, ip);
  // }

  // @Public()
  // @Get('validate_code_password')
  // @HttpCode(200)
  // validate_code_password(
  //   @Query('token') token: string,
  //   @Query('code') code: string,
  // ) {
  //   return this.authService.validateCodePassword(parseInt(code), token);
  // }

  // @Public()
  // @Post('email_password')
  // @HttpCode(200)
  // email_password(@Ip() ip: string, @Body() emailPasswordDto: EmailPasswordDto) {
  //   return this.authService.codeRecoveryPassword(ip, emailPasswordDto);
  // }

  // @Public()
  // @Post('recovery_password')
  // @HttpCode(200)
  // recovery_password(@Body() recoveryPasswordDto: RecoveryPasswordDto) {
  //   return this.authService.recovery_password(recoveryPasswordDto);
  // }
}
