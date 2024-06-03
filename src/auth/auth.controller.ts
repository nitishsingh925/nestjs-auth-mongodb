import {
  Controller,
  Post,
  Body,
  Res,
  Req,
  UseGuards,
  Put,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { CreateAuthDto } from './dto/create-auth.dto';
import { SignInAuthDto } from './dto/signin-auth.dto';
import { Response } from 'express';
import { RefreshTokenAuthDto } from './dto/refreshToken-auth.dto';
import { AuthGuard } from 'src/guards/auth.guard';
import { ChangePasswordAuthDto } from './dto/changePassword.auth.dto';
import { ForgotPasswordAuthDto } from './dto/forgotPassword.auth.dto';
import { resetPasswordAuthDto } from './dto/resetPassword.auth.dto';

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

  @UseGuards(AuthGuard)
  @Post('signout')
  async signout(@Req() req, @Res() res) {
    const userId = req.user.userId;
    await this.authService.signout(userId);
    res.clearCookie('accessToken');
    return res.json({ message: 'User successfully logged out' });
  }

  @UseGuards(AuthGuard)
  @Put('changePassword')
  async changePassword(
    @Body() ChangePasswordAuthDto: ChangePasswordAuthDto,
    @Req() req,
  ) {
    return this.authService.changePassword(
      req.user.email,
      ChangePasswordAuthDto.oldPassword,
      ChangePasswordAuthDto.newPassword,
    );
  }

  @Post('forgotPassword')
  async forgotPassword(@Body() forgotPasswordAuthDto: ForgotPasswordAuthDto) {
    return this.authService.forgotPassword(forgotPasswordAuthDto.email);
  }

  @Put('resetPassword')
  async resetPassword(@Body() resetPasswordAuthDto: resetPasswordAuthDto) {
    return this.authService.resetPassword(
      resetPasswordAuthDto.newPassword,
      resetPasswordAuthDto.resetToken,
    );
  }

  @Post('refreshToken')
  async refreshTokens(@Body() RefreshTokenAuthDto: RefreshTokenAuthDto) {
    return this.authService.refreshTokens(RefreshTokenAuthDto);
  }
}
