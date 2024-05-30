import { Controller, Post, Body, Res } from '@nestjs/common';
import { AuthService } from './auth.service';
import { CreateAuthDto } from './dto/create-auth.dto';
import { SignInAuthDto } from './dto/signin-auth.dto';
import { Response } from 'express';
import { RefreshTokenAuthDto } from './dto/refreshToken-auth.dto';

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
      userId: result.userId,
      accessToken: result.accessToken,
      refreshToken: result.refreshToken,
    });
  }

  @Post('refreshToken')
  async refreshTokens(@Body() RefreshTokenAuthDto: RefreshTokenAuthDto) {
    return this.authService.refreshTokens(RefreshTokenAuthDto);
  }
}
