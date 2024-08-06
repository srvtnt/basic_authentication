import { Module } from '@nestjs/common';
import { AuthModule } from './modules/auth/auth.module';
import { UsersModule } from './modules/users/users.module';
import { RolesModule } from './modules/roles/roles.module';
import { ConfigAuthModule } from './modules/config_auth/config_auth.module';

@Module({
  imports: [AuthModule, UsersModule, RolesModule, ConfigAuthModule],
  controllers: [],
  providers: [],
})
export class AppModule {}
