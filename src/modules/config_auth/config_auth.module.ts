import { Module } from '@nestjs/common';
import { ConfigAuthService } from './config_auth.service';
import { ConfigAuthController } from './config_auth.controller';
import { PrismaService } from 'src/common/prisma/prisma.service';

@Module({
  controllers: [ConfigAuthController],
  providers: [ConfigAuthService, PrismaService],
  exports: [ConfigAuthService],
})
export class ConfigAuthModule {}
