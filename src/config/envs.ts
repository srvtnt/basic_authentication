import 'dotenv/config';
import * as joi from 'joi';

interface EnvVars {
  PORT: number;
  DATABASE_URL: string;
  ISSUER: string;
  JWTSECRET: string;
  JWTREFRESH: string;
  JWTVALIDATION: string;
}

const envsSchema = joi
  .object({
    PORT: joi.number().required(),
    DATABASE_URL: joi.string().required(),
    ISSUER: joi.string().required(),
    JWTSECRET: joi.string().required(),
    JWTREFRESH: joi.string().required(),
    JWTVALIDATION: joi.string().required(),
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
};
