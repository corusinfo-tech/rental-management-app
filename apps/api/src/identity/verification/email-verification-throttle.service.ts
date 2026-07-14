import { HttpException, HttpStatus, Injectable, OnModuleDestroy, OnModuleInit } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import Redis from 'ioredis';
import { createHmac } from 'node:crypto';
import type { Request } from 'express';
import type { Environment } from '../../config/environment';
import { PrismaService } from '../../database/prisma.service';
import { normalizeEmail } from '../registration/normalization';

@Injectable()
export class EmailVerificationThrottleService implements OnModuleInit, OnModuleDestroy {
  private readonly redis: Redis;

  constructor(private readonly config: ConfigService<Environment, true>, private readonly prisma: PrismaService) {
    this.redis = new Redis(this.config.getOrThrow('redisUrl'), { lazyConnect: true, maxRetriesPerRequest: 1 });
  }

  async onModuleInit(): Promise<void> { await this.redis.connect(); }
  async onModuleDestroy(): Promise<void> { await this.redis.quit(); }

  async enforce(email: string, request: Request): Promise<void> {
    const settings = this.config.getOrThrow('verification');
    const ipFingerprint = this.fingerprint(request.ip || request.socket.remoteAddress || 'unknown');
    const emailFingerprint = this.fingerprint(normalizeEmail(email));
    const [ipCount, emailCount] = await Promise.all([
      this.increment(`email-verification:ip:${ipFingerprint}`, settings.requestWindowSeconds),
      this.increment(`email-verification:email:${emailFingerprint}`, settings.requestWindowSeconds),
    ]);
    if (ipCount <= settings.requestIpLimit && emailCount <= settings.requestEmailLimit) return;
    await this.prisma.identityAuditEvent.create({
      data: { action: 'identity.email_verification.throttled', metadata: { ipFingerprint, emailFingerprint } },
    });
    throw new HttpException('Too many verification requests. Please try again later.', HttpStatus.TOO_MANY_REQUESTS);
  }

  private async increment(key: string, ttl: number): Promise<number> {
    const value = await this.redis.eval(
      "local count = redis.call('INCR', KEYS[1]); if count == 1 then redis.call('EXPIRE', KEYS[1], ARGV[1]); end; return count;",
      1, key, ttl,
    );
    return Number(value);
  }

  private fingerprint(value: string): string {
    return createHmac('sha256', this.config.getOrThrow('registration').throttleHashSecret).update(value).digest('base64url');
  }
}
