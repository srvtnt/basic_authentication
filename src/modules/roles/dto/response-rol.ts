import {
    IsString,
    IsOptional,
    IsNotEmpty,
    IsNumber
  } from 'class-validator';
  
export class ResponseRolDto {

      @IsNotEmpty()
      @IsNumber()
      id: number;

      @IsNotEmpty()
      @IsString()
      name: string;
  
      @IsOptional()
      @IsString()
      description?: string
  }
  