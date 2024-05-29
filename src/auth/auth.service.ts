import { ConflictException, Injectable } from '@nestjs/common';
import { CreateAuthDto } from './dto/create-auth.dto';
import { InjectModel } from '@nestjs/mongoose';
import { User } from './schemas/user.schema';
import { Model } from 'mongoose';
import * as bcrypt from 'bcrypt';

@Injectable()
export class AuthService {
  constructor(@InjectModel(User.name) private UserMode: Model<User>) {}

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
}
