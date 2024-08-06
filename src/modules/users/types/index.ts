import { Prisma } from '@prisma/client';
export interface ProfileDB {
  id: number;
  userId: string;
  firstname: string;
  second_name: string;
  last_name: string;
  second_surname: string;
  birthday: Date;
  gender: string;
  phone: string;
  metadata: Prisma.JsonValue;
  localityId: number;
  picture: string;
  createdAt: Date;
  updatedAt: Date;
}

export interface UserRol {
  id: number;
  user_id: string;
  rol_id: number;
  createdAt?: Date;
  updatedAt?: Date;
}
