import { Module } from '@nestjs/common';
import { AuthModule } from './modules/auth/auth.module';
import { UsersModule } from './modules/users/users.module';
import { RolesModule } from './modules/roles/roles.module';

@Module({
  imports: [AuthModule, UsersModule, RolesModule],
  controllers: [],
  providers: [],
})
export class AppModule {}
