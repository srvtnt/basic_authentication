import { Role } from '../../roles/entities/role.entity';

export class User {
  id: string;
  username: string;
  fullname?: string;
  email: string;
  phone?: string;
  password?: string;
  lastpass?: string[];
  expirepass?: Date;
  twoFA?: boolean;
  emailVerified?: Date;
  image?: string;
  status?: string;
  createdAt?: Date;
  updatedAt?: Date;
  rol?: Role;
}
