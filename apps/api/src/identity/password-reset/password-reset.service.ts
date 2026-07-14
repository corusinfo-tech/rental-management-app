import { Injectable } from '@nestjs/common';
import { VerificationChannel, VerificationPurpose } from '@prisma/client';
import * as argon2 from 'argon2';
import { GenericAcceptedDto } from '../dto/auth.dto';
import { IdentityRepository } from '../repositories/identity.repository';
import { VerificationEngine } from '../verification-engine/verification-engine.service';

const ACCEPTED: GenericAcceptedDto = { accepted: true };

/** Password reset is an adapter over VerificationEngine, never a separate token implementation. */
@Injectable()
export class PasswordResetService {
  constructor(private readonly repository: IdentityRepository, private readonly verificationEngine: VerificationEngine) {}

  async request(identifierInput: string, correlationId?: string): Promise<GenericAcceptedDto> {
    const identifier = this.normalizeIdentifier(identifierInput);
    const user = await this.repository.findUserByIdentifier(identifier.includes('@') ? { email: identifier } : { mobile: identifier });
    if (!user || user.deletedAt) return ACCEPTED;
    const organizationId = await this.repository.withTransaction((transaction) => this.repository.findOrganizationIdForUser(user.id, transaction));
    await this.verificationEngine.resendVerification({ userId: user.id, organizationId: organizationId ?? null, channel: VerificationChannel.EMAIL, purpose: VerificationPurpose.PASSWORD_RESET, correlationId });
    return ACCEPTED;
  }

  async confirm(token: string, newPassword: string, correlationId?: string): Promise<GenericAcceptedDto> {
    const parsed = this.parse(token); if (!parsed) return ACCEPTED;
    const passwordHash = await argon2.hash(newPassword);
    await this.verificationEngine.verify({
      ...parsed, expectedPurpose: VerificationPurpose.PASSWORD_RESET, correlationId,
      afterVerified: async (verification, transaction) => {
        if (!verification.userId) throw new Error('Password reset requires a user subject');
        await this.repository.updatePasswordHash(verification.userId, passwordHash, transaction);
        const revoked = await this.repository.revokeAllSessionsForUser(verification.userId, 'PASSWORD_RESET', transaction);
        await this.repository.createAuditEvent({ subjectUserId: verification.userId, action: 'identity.password_reset.completed', metadata: { verificationId: verification.id, subjectType: verification.subjectType, subjectReferenceId: verification.subjectReferenceId, revokedSessionCount: revoked.count, correlationId: correlationId ?? null } }, transaction);
        await this.repository.createOutboxEvent({ eventType: 'PasswordResetCompleted', aggregateType: 'User', aggregateId: verification.userId, payload: { verificationId: verification.id, organizationId: null, userId: verification.userId, correlationId: correlationId ?? null } }, transaction);
      },
    });
    return ACCEPTED;
  }

  private normalizeIdentifier(value: string) { const identifier = value.trim(); return identifier.includes('@') ? identifier.toLowerCase() : identifier.replace(/[\s()-]/g, ''); }
  private parse(token: string): { verificationId: string; secret: string } | undefined { const dot = token.indexOf('.'); if (dot < 1 || dot === token.length - 1) return undefined; const verificationId = token.slice(0, dot); const secret = token.slice(dot + 1); return /^[0-9a-f-]{36}$/i.test(verificationId) && /^[A-Za-z0-9_-]{32,}$/.test(secret) ? { verificationId, secret } : undefined; }
}
