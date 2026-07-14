import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Prisma, VerificationChannel as PrismaVerificationChannel, VerificationPurpose, VerificationStatus, VerificationSubjectType } from '@prisma/client';
import * as argon2 from 'argon2';
import type { Environment } from '../../config/environment';
import { IdentityEventType } from '../events/identity-events';
import { IdentityRepository } from '../repositories/identity.repository';
import { VerificationEnvelopeService } from '../verification/verification-envelope.service';
import { EmailChannel, SmsChannel, WhatsAppChannel, type VerificationChannel } from './verification-channel';

type VerificationSubjectInput = {
  /** Optional solely for non-user subjects. Existing callers remain user based. */
  userId?: string;
  subjectType?: VerificationSubjectType;
  subjectReferenceId?: string;
};

type CreateInput = VerificationSubjectInput & {
  /** Allows a parent aggregate to establish a referentially-safe verification ID in one transaction. */
  verificationId?: string;
  organizationId: string | null;
  purpose: VerificationPurpose;
  channel: PrismaVerificationChannel;
  correlationId?: string;
  resendCount?: number;
  transaction?: Prisma.TransactionClient;
};

type VerifiedRecord = {
  id: string;
  userId: string | null;
  purpose: VerificationPurpose;
  subjectType: VerificationSubjectType;
  subjectReferenceId: string;
  user: { status: string; emailVerifiedAt: Date | null; deletedAt: Date | null } | null;
};

type VerifyInput = {
  verificationId: string;
  secret: string;
  correlationId?: string;
  expectedPurpose?: VerificationPurpose;
  afterVerified?: (verification: VerifiedRecord, transaction: Prisma.TransactionClient) => Promise<void>;
};

@Injectable()
export class VerificationEngine {
  private readonly email = new EmailChannel();
  private readonly sms = new SmsChannel();
  private readonly whatsapp = new WhatsAppChannel();

  constructor(
    private readonly repository: IdentityRepository,
    private readonly config: ConfigService<Environment, true>,
    private readonly envelopes: VerificationEnvelopeService,
  ) {}

  async createVerification(input: CreateInput) {
    if (input.transaction) return this.create(input, input.transaction);
    return this.repository.withTransaction((transaction) => this.create(input, transaction));
  }

  async resendVerification(input: Omit<CreateInput, 'resendCount' | 'transaction'>) {
    return this.repository.withTransaction(async (transaction) => {
      const subject = this.subject(input);
      const channel = this.channel(input.channel);
      await this.repository.expirePendingVerificationsBySubject(subject.subjectType, subject.subjectReferenceId, input.channel, input.purpose, transaction);
      await this.repository.expireVerificationDeliveryEnvelopesBySubject(subject.subjectType, subject.subjectReferenceId, transaction);
      const active = await this.repository.findActiveVerificationBySubject(subject.subjectType, subject.subjectReferenceId, input.channel, input.purpose, transaction);
      if (active) {
        const cooldown = this.settings.cooldownSeconds * 1000;
        if (active.createdAt.getTime() + cooldown > Date.now() || active.resendCount >= this.settings.maximumResends) return undefined;
        await this.repository.revokeVerification(active.id, transaction);
        await this.repository.destroyVerificationDeliveryEnvelope(active.id, transaction);
        channel.destroy();
        await this.audit(active.userId ?? undefined, 'identity.verification.revoked', this.metadata(active, input.correlationId), transaction);
        await this.event(IdentityEventType.VerificationRevoked, active.id, input.organizationId, this.outboxPayload(active.id, input.organizationId, active.userId, input.correlationId), transaction);
        return this.create({ ...input, ...subject, resendCount: active.resendCount + 1 }, transaction, IdentityEventType.VerificationResent);
      }
      return this.create({ ...input, ...subject }, transaction);
    });
  }

  async verify(input: VerifyInput) {
    return this.repository.withTransaction(async (transaction) => {
      const verification = await this.repository.findEmailVerification(input.verificationId, transaction);
      if (!verification || (input.expectedPurpose && verification.purpose !== input.expectedPurpose)) return undefined;
      const channel = this.channel(verification.channel);
      const metadata = this.metadata(verification, input.correlationId);
      if (verification.status !== VerificationStatus.PENDING) {
        await this.audit(verification.userId ?? undefined, 'identity.verification.replay', metadata, transaction);
        return undefined;
      }
      if (verification.expiresAt <= new Date()) {
        await this.repository.expirePendingVerificationsBySubject(verification.subjectType, verification.subjectReferenceId, verification.channel, verification.purpose, transaction);
        await this.repository.destroyVerificationDeliveryEnvelope(verification.id, transaction);
        channel.expire();
        await this.audit(verification.userId ?? undefined, 'identity.verification.expired', metadata, transaction);
        await this.event(IdentityEventType.VerificationExpired, verification.id, null, this.outboxPayload(verification.id, null, verification.userId, input.correlationId), transaction);
        return undefined;
      }
      if (!channel.validate(input.secret) || !(await argon2.verify(verification.secretHash, input.secret))) {
        await this.repository.recordVerificationFailure(verification.id, verification.maxAttempts, transaction);
        const current = await this.repository.findEmailVerification(verification.id, transaction);
        if (current && current.attempts >= current.maxAttempts) {
          await transaction.verification.update({ where: { id: current.id }, data: { status: VerificationStatus.ATTEMPTS_EXCEEDED, revokedAt: new Date() } });
          await this.repository.destroyVerificationDeliveryEnvelope(current.id, transaction);
          await this.audit(current.userId ?? undefined, 'identity.verification.failure', this.metadata(current, input.correlationId), transaction);
          await this.event(IdentityEventType.VerificationAttemptsExceeded, current.id, null, this.outboxPayload(current.id, null, current.userId, input.correlationId), transaction);
        }
        return undefined;
      }
      const consumed = await this.repository.verifyVerification(verification.id, transaction);
      if (consumed.count !== 1) {
        await this.audit(verification.userId ?? undefined, 'identity.verification.replay', metadata, transaction);
        return undefined;
      }
      await this.repository.destroyVerificationDeliveryEnvelope(verification.id, transaction);
      await this.audit(verification.userId ?? undefined, 'identity.verification.verified', metadata, transaction);
      await this.event(IdentityEventType.VerificationVerified, verification.id, null, this.outboxPayload(verification.id, null, verification.userId, input.correlationId), transaction);
      if (input.afterVerified) await input.afterVerified(verification, transaction);
      return verification;
    });
  }

  async revoke(verificationId: string, transaction?: Prisma.TransactionClient) {
    if (transaction) return this.revokeInTransaction(verificationId, transaction);
    return this.repository.withTransaction((client) => this.revokeInTransaction(verificationId, client));
  }

  async expire(subjectInput: VerificationSubjectInput, channel: PrismaVerificationChannel, purpose: VerificationPurpose) {
    return this.repository.withTransaction(async (transaction) => {
      const subject = this.subject(subjectInput);
      const expired = await this.repository.findExpiredPendingVerificationsBySubject(subject.subjectType, subject.subjectReferenceId, channel, purpose, transaction);
      if (!expired.length) return 0;
      await this.repository.expirePendingVerificationsBySubject(subject.subjectType, subject.subjectReferenceId, channel, purpose, transaction);
      for (const verification of expired) {
        await this.repository.destroyVerificationDeliveryEnvelope(verification.id, transaction);
        const metadata = this.metadata(verification, undefined);
        await this.audit(verification.userId ?? undefined, 'identity.verification.expired', metadata, transaction);
        await this.event(IdentityEventType.VerificationExpired, verification.id, null, this.outboxPayload(verification.id, null, verification.userId), transaction);
      }
      return expired.length;
    });
  }

  async cleanup(subjectInput: VerificationSubjectInput) {
    return this.repository.withTransaction(async (transaction) => {
      const subject = this.subject(subjectInput);
      const changed = await this.repository.expireVerificationDeliveryEnvelopesBySubject(subject.subjectType, subject.subjectReferenceId, transaction);
      return changed.count;
    });
  }

  private async create(input: CreateInput, transaction: Prisma.TransactionClient, eventType: IdentityEventType = IdentityEventType.VerificationCreated) {
    const subject = this.subject(input);
    const channel = this.channel(input.channel);
    const secret = channel.generate();
    const expiresAt = new Date(Date.now() + this.settings.expirySeconds * 1000);
    const verification = await this.repository.createVerification({
      id: input.verificationId,
      userId: input.userId,
      ...subject,
      channel: input.channel,
      purpose: input.purpose,
      secretHash: await argon2.hash(secret),
      expiresAt,
      maxAttempts: this.settings.maximumAttempts,
      resendCount: input.resendCount ?? 0,
    }, transaction);
    const prepared = channel.prepareDelivery(verification.id, secret);
    const envelope = this.envelopes.encrypt(prepared.token, {
      verificationId: verification.id,
      organizationId: input.organizationId,
      userId: input.userId ?? null,
      ...subject,
      correlationId: input.correlationId ?? null,
    });
    await this.repository.createVerificationDeliveryEnvelope({ ...envelope, verificationId: verification.id, expiresAt }, transaction);
    const payload = this.outboxPayload(verification.id, input.organizationId, input.userId ?? null, input.correlationId);
    await this.audit(input.userId, 'identity.verification.requested', { ...payload, ...subject }, transaction);
    await this.audit(input.userId, 'identity.verification_envelope.created', { ...payload, ...subject }, transaction);
    await this.event(eventType, verification.id, input.organizationId, payload, transaction);
    return verification;
  }

  private async revokeInTransaction(verificationId: string, transaction: Prisma.TransactionClient) {
    await this.repository.revokeVerification(verificationId, transaction);
    return this.repository.destroyVerificationDeliveryEnvelope(verificationId, transaction);
  }

  private subject(input: VerificationSubjectInput): { subjectType: VerificationSubjectType; subjectReferenceId: string } {
    const subjectType = input.subjectType ?? VerificationSubjectType.USER;
    const subjectReferenceId = input.subjectReferenceId ?? input.userId;
    if (!subjectReferenceId) throw new Error('Verification subject reference is required');
    if (subjectType === VerificationSubjectType.USER && !input.userId) throw new Error('User verification requires userId');
    return { subjectType, subjectReferenceId };
  }

  private metadata(verification: { id: string; userId: string | null; subjectType: VerificationSubjectType; subjectReferenceId: string }, correlationId?: string): Prisma.InputJsonValue {
    return { verificationId: verification.id, subjectType: verification.subjectType, subjectReferenceId: verification.subjectReferenceId, correlationId: correlationId ?? null };
  }

  private outboxPayload(verificationId: string, organizationId: string | null, userId: string | null, correlationId?: string): Prisma.InputJsonObject {
    // Contract remains ID-only; subject attributes remain in the verification aggregate and audit record.
    return { verificationId, organizationId, userId, correlationId: correlationId ?? null };
  }

  private get settings() { return this.config.getOrThrow('verification').email; }

  private channel(channel: PrismaVerificationChannel): VerificationChannel {
    if (channel === PrismaVerificationChannel.EMAIL) return this.email;
    if (channel === PrismaVerificationChannel.SMS) return this.sms;
    if (channel === PrismaVerificationChannel.WHATSAPP) return this.whatsapp;
    throw new Error(`Verification channel ${channel} is not implemented`);
  }

  private audit(userId: string | undefined, action: string, metadata: Prisma.InputJsonValue, transaction: Prisma.TransactionClient) {
    return this.repository.createAuditEvent({ subjectUserId: userId, action, metadata }, transaction);
  }

  private event(eventType: IdentityEventType, aggregateId: string, organizationId: string | null, payload: Prisma.InputJsonValue, transaction: Prisma.TransactionClient) {
    return this.repository.createOutboxEvent({ eventType, aggregateType: 'Verification', aggregateId, organizationId: organizationId ?? undefined, payload }, transaction);
  }
}
