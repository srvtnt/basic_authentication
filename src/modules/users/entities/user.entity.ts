import { Role } from '../../roles/entities/role.entity';

export class User {
  id: string;
  username: string;
  fullname?: string;
  email: string;
  phone?: string;
  password?: string;
  two_fa?: boolean;
  email_verified?: Date;
  image?: string;
  status?: string;
  created_at?: Date;
  updated_at?: Date;
  rol?: Role;
}
