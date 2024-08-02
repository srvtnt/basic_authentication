import { applyDecorators, SetMetadata, UseGuards } from '@nestjs/common';
import { Role } from '../types';
import { RolesGuard } from '../guards/roles-guard';
import { JwtAuthGuard } from '../guards/jwt-auth-guard';

export function Auth(...roles: Role[]) {
  return applyDecorators(
    SetMetadata('roles', roles),
    UseGuards(JwtAuthGuard, RolesGuard),
  );
}
