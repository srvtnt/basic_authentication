import {
  IsNotEmpty,
  IsString,
  IsEmail,
  MinLength,
  MaxLength,
  IsBoolean,
  IsOptional,
  IsInt,
} from 'class-validator';

export class RegisterAuthInput {
  @IsNotEmpty()
  @IsString()
  username: string;

  @IsString()
  @IsOptional()
  fullname?: string;

  @IsString()
  @IsEmail()
  email: string;

  @IsString()
  @IsOptional()
  phone?: string;

  @IsNotEmpty()
  @IsString()
  @MinLength(6)
  @MaxLength(16)
  password: string;

  @IsNotEmpty()
  @IsString()
  @MinLength(6)
  @MaxLength(16)
  repassword: string;

  @IsString()
  @IsOptional()
  image: string;

  @IsNotEmpty()
  @IsInt()
  rol_id: number;
}
