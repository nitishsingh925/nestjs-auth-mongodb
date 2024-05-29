import { IsEmail, IsString, Matches, MinLength } from 'class-validator';

export class CreateAuthDto {
  @IsString()
  name: string;

  @IsEmail()
  email: string;

  @IsString()
  @MinLength(6)
  @Matches(
    /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{6,}$/,
    {
      message:
        'password must contain at least one uppercase letter, one lowercase letter, one digit, and one special character',
    },
  )
  password: string;
}
