import { Controller, Post, Body, Res } from '@nestjs/common';
import { AuthService } from './auth.service';
import { CreateAuthDto } from './dto/create-auth.dto';
import { SignInAuthDto } from './dto/signin-auth.dto';
import { Response } from 'express';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('signup')
  signup(@Body() createAuthDto: CreateAuthDto) {
    return this.authService.signup(createAuthDto);
  }

  @Post('signin')
  async signin(@Body() signInAuthDto: SignInAuthDto, @Res() res: Response) {
    const result = await this.authService.signin(signInAuthDto);
    res.cookie('accessToken', result.accessToken, {
      httpOnly: true,
      secure: true,
      maxAge: 3600000, // 1 hour
    });
    return res.json({
      message: result.message,
      accessToken: result.accessToken,
    });
  }
}
