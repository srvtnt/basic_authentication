import { Module } from '@nestjs/common';
import { UsersService } from './users.service';
import { UsersController } from './users.controller';
import { PrismaService } from 'src/common/prisma/prisma.service';
import { ConfigAuthService } from '../config_auth/config_auth.service';

@Module({
  controllers: [UsersController],
  providers: [UsersService, PrismaService, ConfigAuthService],
})
export class UsersModule {}
