import { Prisma } from '@prisma/client';
export class Profile {
  id: number;
  user_id: string;
  firstname: string;
  second_name: string;
  last_name: string;
  second_surname: string;
  birthday: Date;
  gender: string;
  metadata: Prisma.JsonValue;
  locality_id: number;
  picture: string;
  created_at: Date;
  updated_at: Date;
}
