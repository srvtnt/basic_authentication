export interface LoginAuthResponse {
  code?: number;
  access_token?: string;
  expiration?: number;
  refresh_token?: string;
  expiration_refreshToken?: number;
  msg?: string;
  token_validation?: string;
  user?: UserLogin;
}

export interface SessionInput {
  user_id: string;
  session_token: string;
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
