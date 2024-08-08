export interface ValidationInput {
  userId: string;
  ip: string;
}

export interface VerificationToken {
  sessionToken: string;
  code: number;
  identifier: string;
  expires: Date;
}
