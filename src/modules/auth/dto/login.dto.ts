import { IsString, IsNotEmpty, MinLength, MaxLength } from 'class-validator';
import { Transform } from 'class-transformer';

export class LoginAuthInput {
  @IsNotEmpty()
  @Transform(({ value }) => value.trim())
  @IsString()
  @MinLength(5)
  username: string;

  @MinLength(6)
  @MaxLength(16)
  @IsNotEmpty()
  @IsString()
  @Transform(({ value }) => value.trim())
  password: string;
}
