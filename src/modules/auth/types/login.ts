export interface LoginAuthResponse {
  code?: number;
  twoFa?: boolean;
  accessToken?: string;
  expire_pass?: boolean;
  refreshToken?: string;
  accessTokenExpiration?: number;
  msg?: string;
  refreshTokenExpiration?: number;
  tokenValidation?: string;
  user?: UserLogin;
}

export interface SessionInput {
  userId: string;
  sessionToken: string;
  expires: number;
  last_activity?: Date;
  is_active?: boolean;
  ip: string;
}

export interface UserLogin {
  id: string;
  username: string;
  fullname: string;
  email: string;
  phone: string;
  role: RolLogin;
}

export interface RolLogin {
  id: number;
  name: string;
}
