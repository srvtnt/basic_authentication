import { UseCase } from '@prisma/client';
export interface ValidationInput {
  userId: string;
  useCase: UseCase;
  ip: string;
}

export interface Verification_Tokens {
  id: string;
  useCase: UseCase;
  jwt: string;
  code: number;
  userId: string;
  expireAt: Date;
  createdAt: Date;
  updatedAt: Date;
}
