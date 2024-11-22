export interface ValidationInput {
  user_id: string;
  ip: string;
}

export interface VerificationToken {
  session_token: string;
  code: number;
  identifier: string;
  expires: Date;
}
