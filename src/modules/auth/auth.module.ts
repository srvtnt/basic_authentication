import { Module } from '@nestjs/common';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { PrismaService } from 'src/common/prisma/prisma.service';
import { PassportModule } from '@nestjs/passport';
import { JwtModule } from '@nestjs/jwt';
import { envs } from 'src/config';
import { UsersModule } from '../users/users.module';
import { ConfigAuthModule } from '../config_auth/config_auth.module';
import { ConfigAuthService } from '../config_auth/config_auth.service';
import { JwtStrategy } from './strategies/jwt.strategy';
import { UsersService } from '../users/users.service';

@Module({
  imports: [
    JwtModule.register({
      secret: envs.jwtSecret,
      signOptions: { expiresIn: '1h' },
    }),
    UsersModule,
    ConfigAuthModule,
    PassportModule,
  ],
  controllers: [AuthController],
  providers: [
    AuthService,
    PrismaService,
    ConfigAuthService,
    UsersService,
    JwtStrategy,
  ],
})
export class AuthModule {}
