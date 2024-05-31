import {
  ConflictException,
  Injectable,
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

interface AuthResult {
  accessToken: string;
  message: string;
  refreshToken: string;
  userId: string;
}

@Injectable()
export class AuthService {
  constructor(
    @InjectModel(User.name) private UserMode: Model<User>,
    @InjectModel(RefreshToken.name)
    private RefreshTokenModel: Model<RefreshToken>,
    private readonly jwtService: JwtService,
  ) {}

  async signup(signupDto: CreateAuthDto) {
    const { name, email, password } = signupDto;
    // Check if user already exists
    const emailExists = await this.UserMode.findOne({ email });
    if (emailExists) throw new ConflictException('Email already exists');

    // Hash password

    const hashedPassword = await bcrypt.hash(password, 10);

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

  async refreshTokens(refreshTokenAuthDto: RefreshTokenAuthDto) {
    const token = await this.RefreshTokenModel.findOneAndDelete({
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
    await this.storeRefreshToken(refreshToken, user.userId);

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
