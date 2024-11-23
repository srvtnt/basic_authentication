import { Module } from '@nestjs/common';
import { AuthModule } from './modules/auth/auth.module';
import { UsersModule } from './modules/users/users.module';
import { RolesModule } from './modules/roles/roles.module';
import { ProfilesModule } from './modules/profiles/profiles.module';

@Module({
  imports: [AuthModule, UsersModule, RolesModule, ProfilesModule],
  controllers: [],
  providers: [],
})
export class AppModule {}
