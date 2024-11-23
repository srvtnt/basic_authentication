import { Transform } from 'class-transformer';
import {
  IsNotEmpty,
  IsString,
  IsEmail,
  MinLength,
  MaxLength,
  IsOptional,
} from 'class-validator';

export class RegisterDto {
  @IsOptional()
  @Transform(({ value }) => value.trim())
  @IsString()
  @MinLength(5)
  username: string;

  @IsNotEmpty()
  @Transform(({ value }) => value.trim())
  @IsEmail()
  email: string;

  @MinLength(6)
  @MaxLength(16)
  @IsNotEmpty()
  @IsString()
  @Transform(({ value }) => value.trim())
  password: string;
}
