import { IsString, IsNotEmpty } from 'class-validator';

export class RefreshTokenInput {
  @IsNotEmpty()
  @IsString()
  refresh_token: string;
}
