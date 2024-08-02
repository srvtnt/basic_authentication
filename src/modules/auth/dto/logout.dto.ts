import { IsString, IsNotEmpty } from 'class-validator';

export class LogoutDtoInput {
  @IsNotEmpty()
  @IsString()
  userId: string;

  @IsNotEmpty()
  @IsString()
  refreshToken: string;
}
