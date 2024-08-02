import { UseCase } from '@prisma/client';
export interface ValidationInput {
  useCase: UseCase;
  jwt: string;
  code: number;
  userId: string;
  expireAt: number;
  url: string;
}
