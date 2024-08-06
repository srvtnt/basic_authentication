import { Prisma } from '@prisma/client';
import { Roles } from '../../roles/entities/role.entity';

export class Users {
  id: string;
  username: string;
  fullname?: string;
  email: string;
  phone?: string;
  password?: string;
  metadata?: Prisma.JsonValue;
  lastpass?: string[];
  expirepass?: Date;
  force_new_pass?: boolean;
  twoFA?: boolean;
  isEmailVerified?: boolean;
  status?: string;
  createdAt?: Date;
  updatedAt?: Date;
  rol?: Roles;
}
