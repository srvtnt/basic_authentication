import { IsNotEmpty, IsString, MaxLength, MinLength } from 'class-validator';

export class ValidateCodeInput {
  @IsNotEmpty()
  @IsString()
  @MinLength(4)
  @MaxLength(8)
  code: string;
}
