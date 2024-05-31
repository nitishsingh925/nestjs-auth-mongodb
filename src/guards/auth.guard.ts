import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { Request } from 'express';
import { Observable } from 'rxjs';

@Injectable()
export class AuthGuard implements CanActivate {
  constructor(private jwtService: JwtService) {}
  canActivate(
    context: ExecutionContext,
  ): boolean | Promise<boolean> | Observable<boolean> {
    const req = context.switchToHttp().getRequest();
    const token = this.extractTokenFromHeader(req);
    if (!token) throw new UnauthorizedException('token Not Found in header');
    try {
      const payload = this.jwtService.verify(token);
      req.user = payload.user;
    } catch (e) {
      throw new UnauthorizedException(`Invalid Token ${e.message}`);
    }
    return true;
  }
  private extractTokenFromHeader(req: Request): string | undefined {
    return req.headers.authorization?.split(' ')[1];
  }
}
