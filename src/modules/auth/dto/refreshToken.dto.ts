import { IsString, IsNotEmpty } from 'class-validator';

export class RefreshTokenInput {
  @IsNotEmpty()
  @IsString()
  refreshToken: string;
}
