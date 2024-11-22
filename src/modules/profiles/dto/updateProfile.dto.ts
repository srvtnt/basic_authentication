import { IsInt, IsJSON, IsOptional, IsString } from 'class-validator';
import { Prisma } from '@prisma/client';

export class UpdateProfileDto {
  @IsOptional()
  @IsString()
  firstname?: string;

  @IsString()
  @IsOptional()
  second_name?: string;

  @IsString()
  @IsOptional()
  last_name?: string;

  @IsString()
  @IsOptional()
  second_surname?: string;

  @IsString()
  @IsOptional()
  birthday?: Date;

  @IsString()
  @IsOptional()
  gender?: string;

  @IsString()
  @IsOptional()
  phone?: string;

  @IsJSON()
  @IsOptional()
  metadata?: Prisma.JsonObject;

  @IsInt()
  @IsOptional()
  locality_id?: number;

  @IsString()
  @IsOptional()
  picture?: string;
}
