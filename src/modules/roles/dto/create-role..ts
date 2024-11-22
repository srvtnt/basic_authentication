import { IsString, IsOptional, IsNotEmpty } from 'class-validator';

export class CreateRole {
  @IsNotEmpty()
  @IsString()
  name: string;

  @IsOptional()
  @IsString()
  description?: string;
}
