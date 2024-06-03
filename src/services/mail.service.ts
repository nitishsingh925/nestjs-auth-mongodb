import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as nodemailer from 'nodemailer';
@Injectable()
export class MailService {
  private transporter: nodemailer.Transporter;

  constructor(private configService: ConfigService) {
    this.transporter = nodemailer.createTransport({
      host: this.configService.getOrThrow<string>('mail.host'),
      // port: this.configService.getOrThrow<number>('mail.port'),
      auth: {
        user: this.configService.getOrThrow<string>('mail.user'),
        pass: this.configService.getOrThrow<string>('mail.pass'),
      },
    });
  }
  async sendPasswordResetEmail(to: string, token: string) {
    const resetLink = `http://localhost:3000/resetPassword?token=${token}`;
    const mailOptions = {
      from: 'nestjs-auth-mongodb',
      to: to,
      subject: 'Reset Password',
      html: `<p> You requested a password reset. Click the link below to reset your password:</p> 
      <p><a href="${resetLink}">Reset Password</a></p>`,
    };
    await this.transporter.sendMail(mailOptions);
  }
}
