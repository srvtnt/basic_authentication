import { IsInt, IsNotEmpty } from 'class-validator';
export class UpdateUserRolDto {
  @IsInt()
  @IsNotEmpty()
  rol_id?: string;
}
