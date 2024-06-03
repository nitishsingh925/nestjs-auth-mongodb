import { IsString, Matches, MinLength } from 'class-validator';

export class ChangePasswordAuthDto {
  @IsString()
  @MinLength(6)
  @Matches(
    /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{6,}$/,
    {
      message:
        'password must contain at least one uppercase letter, one lowercase letter, one digit, and one special character',
    },
  )
  oldPassword: string;

  @IsString()
  @MinLength(6)
  @Matches(
    /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{6,}$/,
    {
      message:
        'password must contain at least one uppercase letter, one lowercase letter, one digit, and one special character',
    },
  )
  newPassword: string;
}
