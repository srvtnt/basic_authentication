import { Transform } from 'class-transformer';
import { IsEmail, IsNotEmpty, IsString } from 'class-validator';
export class RecoveryPasswordDto {
  @IsString()
  @IsNotEmpty()
  id: string;

  @IsString()
  @IsNotEmpty()
  @Transform(({ value }) => value.trim())
  new_password?: string;

  @IsString()
  @IsNotEmpty()
  @Transform(({ value }) => value.trim())
  confir_password?: string;

  @IsString()
  @IsNotEmpty()
  token_reset_pass?: string;
}

export class EmailPasswordDto {
  @IsNotEmpty()
  @IsEmail()
  email?: string;
}
