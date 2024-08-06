export interface LoginAuthResponse {
  code?: number;
  twoFA?: boolean;
  access_token?: string;
  expire_pass?: boolean;
  refreshToken?: string;
  expire_access_token?: number;
  msg?: string;
  expire_refresh_token?: number;
  tokenValidation?: string;
  url?: string;
  user?: UserLogin;
}

export interface LoginSessionInput {
  userId: string;
  jwt: string;
  expireAt: number;
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
