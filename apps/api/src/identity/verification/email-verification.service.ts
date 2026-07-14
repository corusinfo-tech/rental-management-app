import { Injectable } from '@nestjs/common';
import { UserStatus, VerificationChannel, VerificationPurpose } from '@prisma/client';
import { GenericAcceptedDto } from '../dto/auth.dto';
import { IdentityRepository } from '../repositories/identity.repository';
import { normalizeEmail } from '../registration/normalization';
import { VerificationEngine } from '../verification-engine/verification-engine.service';

const ACCEPTED: GenericAcceptedDto = { accepted: true };

/** Public email adapter. All verification persistence and security behavior belongs to VerificationEngine. */
@Injectable()
export class EmailVerificationService {
  constructor(private readonly repository: IdentityRepository, private readonly engine: VerificationEngine) {}

  async request(emailInput: string, correlationId?: string): Promise<GenericAcceptedDto> {
    const user = await this.repository.findUserByEmail(normalizeEmail(emailInput));
    if (!user || !this.isEligible(user)) return ACCEPTED;
    const organizationId = await this.repository.withTransaction((transaction) => this.repository.findOrganizationIdForUser(user.id, transaction));
    await this.engine.resendVerification({ userId: user.id, organizationId: organizationId ?? null, channel: VerificationChannel.EMAIL, purpose: VerificationPurpose.EMAIL_VERIFICATION, correlationId });
    return ACCEPTED;
  }

  async confirm(token: string, correlationId?: string): Promise<GenericAcceptedDto> {
    const parsed = this.parse(token); if (!parsed) return ACCEPTED;
    const verification = await this.engine.verify({ ...parsed, correlationId, afterVerified: async (verified, transaction) => {
      if (!verified.userId || !verified.user) throw new Error('Email verification requires a user subject');
      const user = await this.repository.transitionEmailVerifiedUser(verified.userId, verified.user.status as UserStatus, transaction);
      const organizationId = await this.repository.findOrganizationIdForUser(user.id, transaction);
      await this.repository.createAuditEvent({ subjectUserId: user.id, action: 'identity.email_verification.succeeded', metadata: { verificationId: verified.id, subjectType: verified.subjectType, subjectReferenceId: verified.subjectReferenceId, organizationId: organizationId ?? null, correlationId: correlationId ?? null } }, transaction);
      await this.repository.createOutboxEvent({ eventType: 'EmailVerified', aggregateType: 'User', aggregateId: user.id, organizationId, payload: { verificationId: verified.id, organizationId: organizationId ?? null, userId: user.id, correlationId: correlationId ?? null } }, transaction);
    } });
    if (!verification || !this.isEligible(verification.user)) return ACCEPTED;
    return ACCEPTED;
  }

  private parse(token: string): { verificationId: string; secret: string } | undefined {
    const separator = token.indexOf('.'); if (separator < 1 || separator === token.length - 1) return undefined;
    const verificationId = token.slice(0, separator); const secret = token.slice(separator + 1);
    return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(verificationId) && /^[A-Za-z0-9_-]{32,}$/.test(secret) ? { verificationId, secret } : undefined;
  }
  private isEligible(user: { status: UserStatus; emailVerifiedAt: Date | null; deletedAt?: Date | null } | null): boolean { return Boolean(user && !user.deletedAt && !user.emailVerifiedAt && (user.status === UserStatus.PENDING_EMAIL || user.status === UserStatus.PENDING_REVIEW)); }
}
