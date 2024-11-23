import { Module } from '@nestjs/common';
import { ProfilesService } from './profiles.service';
import { ProfilesController } from './profiles.controller';
import { PrismaService } from 'src/common/prisma/prisma.service';

@Module({
  controllers: [ProfilesController],
  providers: [ProfilesService, PrismaService],
})
export class ProfilesModule {}
