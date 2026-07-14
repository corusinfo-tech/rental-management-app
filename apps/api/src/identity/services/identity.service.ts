import { Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { UserStatus, type Prisma } from '@prisma/client';
import * as argon2 from 'argon2';
import { randomUUID } from 'node:crypto';
import type { Environment } from '../../config/environment';
import { IdentityRepository } from '../repositories/identity.repository';

const AUTH_FAILURE = 'Invalid credentials';

@Injectable()
export class IdentityService {
  constructor(private readonly repository: IdentityRepository, private readonly jwt: JwtService, private readonly config: ConfigService<Environment, true>) {}

  async login(input: { identifier: string; password: string; deviceId?: string; userAgent?: string; ipAddress?: string }) {
    const identifier = this.normalizeIdentifier(input.identifier);
    const user = await this.repository.findUserByIdentifier(identifier.includes('@') ? { email: identifier } : { mobile: identifier });
    if (!user || user.status !== UserStatus.ACTIVE || !(await argon2.verify(user.passwordHash, input.password))) {
      await this.repository.createAuditEvent({ subjectUserId: user?.id, action: 'identity.login.failed', metadata: { identifierType: identifier.includes('@') ? 'email' : 'mobile' } });
      throw new UnauthorizedException(AUTH_FAILURE);
    }
    const membership = await this.repository.findDefaultMembershipForUser(user.id);
    const issued = await this.issueTokens(user.id, { membershipId: membership?.id, organizationId: membership?.organizationId, deviceId: input.deviceId, userAgent: input.userAgent, ipAddress: input.ipAddress });
    await this.repository.createAuditEvent({ subjectUserId: user.id, action: 'identity.login.succeeded', metadata: { sessionId: issued.sessionId } });
    return issued;
  }

  async refresh(refreshToken: string) {
    const payload = await this.verifyRefreshToken(refreshToken);
    try {
      return await this.repository.withTransaction(async (transaction) => {
        const session = await this.repository.findSession(payload.sid, transaction);
        if (!session || session.userId !== payload.sub || !(await argon2.verify(session.refreshTokenHash, refreshToken)) || session.expiresAt <= new Date()) throw new Error('invalid');
        if (session.revokedAt) { await this.repository.revokeSessionFamily(session.familyId, 'REUSE_DETECTED', transaction); await this.repository.createAuditEvent({ subjectUserId: session.userId, action: 'identity.refresh.failed', metadata: { sessionId: session.id, reason: 'reuse' } }, transaction); throw new Error('reuse'); }
        if ((await this.repository.revokeActiveSession(session.id, transaction)).count !== 1) { await this.repository.revokeSessionFamily(session.familyId, 'REUSE_DETECTED', transaction); throw new Error('race'); }
        const issued = await this.issueTokens(session.userId, { familyId: session.familyId, parentSessionId: session.id, membershipId: session.membershipId ?? undefined, organizationId: session.organizationId ?? undefined, deviceId: session.deviceId ?? undefined, userAgent: session.userAgent ?? undefined, ipAddress: session.ipAddress ?? undefined }, transaction);
        await this.repository.createAuditEvent({ subjectUserId: session.userId, action: 'identity.refresh.succeeded', metadata: { sessionId: issued.sessionId } }, transaction);
        return issued;
      });
    } catch { throw new UnauthorizedException('Invalid refresh token'); }
  }

  async logout(userId: string, sessionId: string) { const changed = await this.repository.revokeSessionForUser(sessionId, userId, 'LOGOUT'); if (changed.count) await this.repository.createAuditEvent({ subjectUserId: userId, action: 'identity.logout', metadata: { sessionId } }); }
  async logoutAll(userId: string) { const changed = await this.repository.revokeAllSessionsForUser(userId, 'LOGOUT_ALL'); await this.repository.createAuditEvent({ subjectUserId: userId, action: 'identity.logout_all', metadata: { count: changed.count } }); }
  async sessions(userId: string) { return this.repository.listActiveSessions(userId); }
  async revokeSession(userId: string, sessionId: string) { const changed = await this.repository.revokeSessionForUser(sessionId, userId, 'SESSION_REVOKED'); if (changed.count) await this.repository.createAuditEvent({ subjectUserId: userId, action: 'identity.session.revoked', metadata: { sessionId } }); }

  private async issueTokens(userId: string, meta: { familyId?: string; parentSessionId?: string; membershipId?: string; organizationId?: string; deviceId?: string; userAgent?: string; ipAddress?: string }, transaction?: Prisma.TransactionClient) {
    const sessionId = randomUUID(); const refreshToken = await this.signRefreshToken(userId, sessionId);
    await this.repository.createSession({ id: sessionId, userId, familyId: meta.familyId ?? randomUUID(), parentSessionId: meta.parentSessionId, membershipId: meta.membershipId, organizationId: meta.organizationId, deviceId: meta.deviceId, userAgent: meta.userAgent, ipAddress: meta.ipAddress, refreshTokenHash: await argon2.hash(refreshToken), expiresAt: this.refreshExpiry() }, transaction);
    return { sessionId, accessToken: await this.signAccessToken(userId, sessionId), refreshToken, expiresIn: this.config.getOrThrow('jwt').accessTtlSeconds };
  }
  private async verifyRefreshToken(token: string) { try { const j = this.config.getOrThrow('jwt'); return await this.jwt.verifyAsync<{ sub: string; sid: string }>(token, { secret: j.refreshSecret, algorithms: [j.algorithm], issuer: j.issuer, audience: j.audience }); } catch { throw new UnauthorizedException('Invalid refresh token'); } }
  private async signAccessToken(userId: string, sessionId: string) { const j = this.config.getOrThrow('jwt'); return this.jwt.signAsync({ sub: userId, sid: sessionId }, { secret: j.accessSecret, algorithm: j.algorithm, issuer: j.issuer, audience: j.audience, expiresIn: j.accessTtlSeconds }); }
  private async signRefreshToken(userId: string, sessionId: string) { const j = this.config.getOrThrow('jwt'); return this.jwt.signAsync({ sub: userId, sid: sessionId }, { secret: j.refreshSecret, algorithm: j.algorithm, issuer: j.issuer, audience: j.audience, expiresIn: j.refreshTtlSeconds }); }
  private refreshExpiry() { return new Date(Date.now() + this.config.getOrThrow('jwt').refreshTtlSeconds * 1000); }
  private normalizeIdentifier(value: string) { const identifier = value.trim(); return identifier.includes('@') ? identifier.toLowerCase() : identifier.replace(/[\s()-]/g, ''); }
}
