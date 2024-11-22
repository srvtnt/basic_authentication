import { IsString, IsNotEmpty } from 'class-validator';

export class LogoutDtoInput {
  @IsNotEmpty()
  @IsString()
  user_id: string;

  @IsNotEmpty()
  @IsString()
  refresh_token: string;
}
