import {
  ConflictException,
  Injectable,
  InternalServerErrorException,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { CreateAuthDto } from './dto/create-auth.dto';
import { InjectModel } from '@nestjs/mongoose';
import { User } from './schemas/user.schema';
import { Model } from 'mongoose';
import * as bcrypt from 'bcrypt';
import { SignInAuthDto } from './dto/signin-auth.dto';
import { JwtService } from '@nestjs/jwt';
import { RefreshToken } from './schemas/refresh-token.schema';
import { v4 as uuidv4 } from 'uuid';
import { RefreshTokenAuthDto } from './dto/refreshToken-auth.dto';
import { ResetToken } from './schemas/reset-token.schema';
import { MailService } from 'src/services/mail.service';
import { randomBytes } from 'crypto';

interface AuthResult {
  accessToken: string;
  message: string;
  refreshToken: string;
  userId: string;
}

const bcryptSoltRounds = 10;

@Injectable()
export class AuthService {
  constructor(
    @InjectModel(User.name) private UserMode: Model<User>,
    @InjectModel(RefreshToken.name)
    private RefreshTokenModel: Model<RefreshToken>,
    @InjectModel(ResetToken.name)
    private ResetTokenModel: Model<ResetToken>,
    private readonly jwtService: JwtService,
    private mailService: MailService,
  ) {}

  async signup(signupDto: CreateAuthDto) {
    const { name, email, password } = signupDto;
    // Check if user already exists
    const emailExists = await this.UserMode.findOne({ email });
    if (emailExists) throw new ConflictException('Email already exists');

    // Hash password

    const hashedPassword = await bcrypt.hash(password, bcryptSoltRounds);

    await this.UserMode.create({ name, email, password: hashedPassword });
    return 'User successfully registered';
  }

  async signin(signinDto: SignInAuthDto): Promise<AuthResult> {
    const { email, password } = signinDto;

    // Check if user alreay exists
    const user = await this.UserMode.findOne({ email });
    if (!user) throw new NotFoundException('email not Exists');

    // Password validation
    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) throw new UnauthorizedException('Invalid password');

    // Create JWT payload and token
    const payload = { userId: user._id, email };
    const { accessToken, refreshToken } =
      await this.generateAccessToken(payload);

    return {
      message: 'User successfully logged in',
      userId: String(user._id),
      accessToken,
      refreshToken,
    };
  }

  async signout(userId: string) {
    await this.RefreshTokenModel.deleteOne({ userId });
  }

  async changePassword(email, oldPassword: string, newPassword: string) {
    if (oldPassword === newPassword)
      throw new UnauthorizedException(
        'New password cannot be same as old password',
      );
    const user = await this.UserMode.findOne({ email });
    const passwordMatch = await bcrypt.compare(oldPassword, user.password);

    if (!passwordMatch) throw new UnauthorizedException('Wrong Credentials');
    const hashedPassword = await bcrypt.hash(newPassword, bcryptSoltRounds);
    user.password = hashedPassword;
    await user.save();
    return { message: 'Password changed successfully' };
  }

  async forgotPassword(email: string) {
    const user = await this.UserMode.findOne({ email });

    if (user) {
      const expiryDate = new Date();
      expiryDate.setHours(expiryDate.getHours() + 1);
      // Use crypto to generate a secure random token
      const resetToken = randomBytes(64).toString('hex');
      await this.ResetTokenModel.create({
        token: resetToken,
        userId: String(user._id),
        expiryDate,
      });

      this.mailService.sendPasswordResetEmail(email, resetToken);
    }

    return { message: 'If this email exists, we will send you a reset link' };
  }

  async resetPassword(newPassword: string, resetToken: string) {
    // Find the reset token in the database
    const resetTokenRecord = await this.ResetTokenModel.findOne({
      token: resetToken,
      expiryDate: { $gte: new Date() },
    });
    if (!resetTokenRecord)
      throw new UnauthorizedException('Invalid reset link or expired');

    const user = await this.UserMode.findById(resetTokenRecord.userId);
    if (!user) throw new InternalServerErrorException();
    user.password = await bcrypt.hash(newPassword, bcryptSoltRounds);
    await user.save();
  }

  async refreshTokens(refreshTokenAuthDto: RefreshTokenAuthDto) {
    const token = await this.RefreshTokenModel.findOne({
      token: refreshTokenAuthDto.refreshToken,
      expiryDate: { $gte: new Date() },
    });

    if (!token) throw new UnauthorizedException('Invalid refresh token');
    const userId = token.userId.toString();
    return this.generateAccessToken({ userId });
  }

  async generateAccessToken(user) {
    const accessToken = this.jwtService.sign({ user });
    const refreshToken = uuidv4();
    await this.storeRefreshToken(refreshToken, user.userId.toString());

    return { accessToken, refreshToken };
  }

  async storeRefreshToken(token: string, userId) {
    // Calculate expiry date 3 days from now
    const expiryDate = new Date();
    expiryDate.setDate(expiryDate.getDate() + 3);

    await this.RefreshTokenModel.updateOne(
      {
        userId,
      },
      { $set: { expiryDate, token } },
      { upsert: true },
    );
  }
}
