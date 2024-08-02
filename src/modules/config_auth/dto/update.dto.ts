import { IsNotEmpty, IsBoolean, IsOptional, IsInt } from 'class-validator';

export class UpdateConfigAuthDto {
  @IsBoolean()
  @IsNotEmpty()
  @IsOptional()
  https?: boolean;

  @IsInt()
  @IsNotEmpty()
  @IsOptional()
  max_last_pass?: number;

  @IsInt()
  @IsNotEmpty()
  @IsOptional()
  time_life_pass?: number;

  @IsBoolean()
  @IsNotEmpty()
  @IsOptional()
  twoFA?: boolean;

  @IsInt()
  @IsNotEmpty()
  @IsOptional()
  time_life_code?: number;
}
