import { envs } from './envs';

export const ConfigIssuer = {
  issuer: envs.issuer,
};

export const jwtRefreshConstants = {
  secret: envs.jwtRefresh,
};

export const jwtTokenConstants = {
  secret: envs.jwtSecret,
};
