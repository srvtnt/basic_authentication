import { IsString, IsNotEmpty, MinLength, MaxLength, IsEmail, IsOptional } from 'class-validator';
import { Transform } from 'class-transformer';

export class LoginDto {
  @IsOptional()
  @Transform(({ value }) => value.trim())
  @IsString()
  @MinLength(5)
  username?: string;

  @IsOptional()
  @Transform(({ value }) => value.trim())
  @IsEmail()
  email?: string;

  @MinLength(6)
  @MaxLength(16)
  @IsNotEmpty()
  @IsString()
  @Transform(({ value }) => value.trim())
  password: string;
}
