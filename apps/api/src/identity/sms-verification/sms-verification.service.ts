import { Injectable } from '@nestjs/common';
import { VerificationChannel, VerificationPurpose } from '@prisma/client';
import { GenericAcceptedDto } from '../dto/auth.dto';
import { IdentityRepository } from '../repositories/identity.repository';
import { VerificationEngine } from '../verification-engine/verification-engine.service';

const ACCEPTED: GenericAcceptedDto = { accepted: true };

@Injectable()
export class SmsVerificationService {
  constructor(private readonly repository: IdentityRepository, private readonly verificationEngine: VerificationEngine) {}

  async request(mobile: string, correlationId?: string): Promise<GenericAcceptedDto> {
    const user = await this.repository.findUserByIdentifier({ mobile });
    if (!user || user.deletedAt) return ACCEPTED;
    const organizationId = await this.repository.withTransaction((transaction) => this.repository.findOrganizationIdForUser(user.id, transaction));
    await this.verificationEngine.resendVerification({ userId: user.id, organizationId: organizationId ?? null, channel: VerificationChannel.SMS, purpose: VerificationPurpose.SMS_OTP, correlationId });
    return ACCEPTED;
  }

  async confirm(token: string, correlationId?: string): Promise<GenericAcceptedDto> {
    const parsed = this.parse(token); if (!parsed) return ACCEPTED;
    await this.verificationEngine.verify({
      ...parsed, expectedPurpose: VerificationPurpose.SMS_OTP, correlationId,
      afterVerified: async (verification, transaction) => {
        if (!verification.userId) throw new Error('SMS verification requires a user subject');
        await this.repository.createAuditEvent({ subjectUserId: verification.userId, action: 'identity.sms_verification.verified', metadata: { verificationId: verification.id, subjectType: verification.subjectType, subjectReferenceId: verification.subjectReferenceId, correlationId: correlationId ?? null } }, transaction);
        await this.repository.createOutboxEvent({ eventType: 'SmsVerified', aggregateType: 'Verification', aggregateId: verification.id, payload: { verificationId: verification.id, organizationId: null, userId: verification.userId, correlationId: correlationId ?? null } }, transaction);
      },
    });
    return ACCEPTED;
  }

  private parse(token: string): { verificationId: string; secret: string } | undefined { const dot = token.indexOf('.'); if (dot < 1 || dot === token.length - 1) return undefined; const verificationId = token.slice(0, dot); const secret = token.slice(dot + 1); return /^[0-9a-f-]{36}$/i.test(verificationId) && /^\d{6}$/.test(secret) ? { verificationId, secret } : undefined; }
}
