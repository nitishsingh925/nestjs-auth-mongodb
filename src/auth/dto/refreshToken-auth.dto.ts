import { IsString } from 'class-validator';

export class RefreshTokenAuthDto {
  @IsString()
  refreshToken: string;
}
