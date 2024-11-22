import 'dotenv/config';
import * as joi from 'joi';

interface EnvVars {
  PORT: number;
  DATABASE_URL: string;
  ISSUER: string;
  JWTSECRET: string;
  JWTREFRESH: string;
  JWTVALIDATION: string;
  APIKEYRESEND?: string;
  SUPPORTEMAIL?: string;
  EXPIRE_REFRESH_TOKEN: string;
  MAX_SESSIONS_USER: number;
  EXPIRES_CODE: number;
  EXPIRE_TOKEN: string;
}

const envsSchema = joi
  .object({
    PORT: joi.number().required(),
    DATABASE_URL: joi.string().required(),
    ISSUER: joi.string().required(),
    JWTSECRET: joi.string().required(),
    JWTREFRESH: joi.string().required(),
    JWTVALIDATION: joi.string().required(),
    APIKEYRESEND: joi.string(),
    SUPPORTEMAIL: joi.string(),
    EXPIRE_REFRESH_TOKEN: joi.string(),
    MAX_SESSIONS_USER: joi.number(),
    EXPIRES_CODE: joi.number(),
    EXPIRE_TOKEN: joi.string(),
  })
  .unknown(true);

const { error, value } = envsSchema.validate(process.env);

if (error) {
  throw new Error(`Config validation error: ${error.message}`);
}

const envVars: EnvVars = value;

export const envs = {
  port: envVars.PORT,
  dataBaseUrl: envVars.DATABASE_URL,
  issuer: envVars.ISSUER,
  jwtSecret: envVars.JWTSECRET,
  jwtRefresh: envVars.JWTREFRESH,
  jwtValidation: envVars.JWTVALIDATION,
  apyKeyResend: envVars.APIKEYRESEND,
  supportEmail: envVars.SUPPORTEMAIL,
  time_expires_refreshtoken: envVars.EXPIRE_REFRESH_TOKEN,
  max_sesion_user: envVars.MAX_SESSIONS_USER,
  expire_code: envVars.EXPIRES_CODE,
  expire_token: envVars.EXPIRE_TOKEN
};
