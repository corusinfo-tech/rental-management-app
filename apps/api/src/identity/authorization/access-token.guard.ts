import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import type { Environment } from '../../config/environment';
import type { AccessTokenClaims, IdentityRequest } from './request-context';
import { IdentityRepository } from '../repositories/identity.repository';

@Injectable()
export class AccessTokenGuard implements CanActivate {
  constructor(
    private readonly jwt: JwtService,
    private readonly config: ConfigService<Environment, true>,
    private readonly repository: IdentityRepository,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest<IdentityRequest>();
    const authorization = request.header('authorization');
    const token = authorization?.match(/^Bearer\s+(.+)$/i)?.[1];
    if (!token) {
      throw new UnauthorizedException('Bearer token is required');
    }

    try {
      const jwtConfig = this.config.getOrThrow('jwt');
      const claims = await this.jwt.verifyAsync<AccessTokenClaims>(token, {
        secret: jwtConfig.accessSecret,
        algorithms: [jwtConfig.algorithm],
        issuer: jwtConfig.issuer,
        audience: jwtConfig.audience,
      });
      const session = await this.repository.findActiveSessionForAccess(claims.sid);
      if (!session || session.userId !== claims.sub) throw new Error('session is not active');
      request.identity = claims;
      return true;
    } catch {
      throw new UnauthorizedException('Access token is invalid or expired');
    }
  }
}
