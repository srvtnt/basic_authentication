export interface JwtPayload {
  iss: string;
  id: string;
  user: string;
  email: string;
  role: string;
}

export interface DecodeJwt {
  iss: string;
  id: string;
  user: string;
  email: string;
  role: string;
  iat: number;
  exp: number;
}
