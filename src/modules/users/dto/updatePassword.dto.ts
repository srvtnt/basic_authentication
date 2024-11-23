import { Transform } from 'class-transformer';
import { IsNotEmpty, IsString } from 'class-validator';

export class UpdateUserPasswordDto {
  @IsString()
  @IsNotEmpty()
  @Transform(({ value }) => value.trim())
  new_password?: string;

  @IsString()
  @IsNotEmpty()
  @Transform(({ value }) => value.trim())
  confir_password?: string;
}

export class UpdateUserPasswordByAdmin {
  @IsString()
  @IsNotEmpty()
  @Transform(({ value }) => value.trim())
  new_password?: string;

  @IsString()
  @IsNotEmpty()
  @Transform(({ value }) => value.trim())
  confir_password?: string;
}
