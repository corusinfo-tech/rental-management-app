import { PrismaClient } from '@prisma/client';
import { randomUUID } from 'node:crypto';
import type { OutboxEventHandler, OutboxRecord, WorkerMetrics } from './types';

export type OutboxWorkerConfig = { pollIntervalMs: number; leaseTimeoutMs: number; maximumAttempts: number; retryBaseDelayMs: number; batchSize: number };

/** PostgreSQL-backed transactional outbox processor. Handlers must provide external idempotency using event.id. */
export class OutboxWorker {
  readonly workerId = randomUUID();
  readonly metrics: WorkerMetrics = { processed: 0, failed: 0, retries: 0, deadLetters: 0, totalLatencyMs: 0, totalProcessingMs: 0 };
  private readonly handlers = new Map<string, OutboxEventHandler>();
  constructor(private readonly prisma: PrismaClient, private readonly config: OutboxWorkerConfig, handlers: OutboxEventHandler[], requiredEventTypes: readonly string[] = []) {
    handlers.forEach((handler) => {
      if (this.handlers.has(handler.eventType)) throw new Error(`Duplicate outbox handler registration: ${handler.eventType}`);
      this.handlers.set(handler.eventType, handler);
    });
    this.assertHandlerCoverage(requiredEventTypes);
  }

  /** Startup gate: every event producer must declare a concrete or terminal policy. */
  assertHandlerCoverage(requiredEventTypes: readonly string[]): void {
    const missing = requiredEventTypes.filter((eventType) => !this.handlers.has(eventType));
    if (missing.length) throw new Error(`Missing outbox handler policy: ${missing.join(', ')}`);
  }

  async pollOnce(): Promise<number> { const events = await this.claim(); for (const event of events) await this.process(event); return events.length; }

  async claim(): Promise<OutboxRecord[]> {
    const leaseUntil = new Date(Date.now() + this.config.leaseTimeoutMs);
    return this.prisma.$queryRaw<OutboxRecord[]>`
      UPDATE "OutboxEvent" AS event SET "status" = 'PROCESSING', "leaseOwner" = ${this.workerId}, "leaseExpiresAt" = ${leaseUntil}, "attempts" = event."attempts" + 1
      FROM (SELECT "id" FROM "OutboxEvent" WHERE ("status" = 'PENDING' AND "availableAt" <= NOW()) OR ("status" = 'PROCESSING' AND "leaseExpiresAt" <= NOW()) ORDER BY "createdAt" FOR UPDATE SKIP LOCKED LIMIT ${this.config.batchSize}) AS claim
      WHERE event."id" = claim."id"
      RETURNING event."id", event."eventType", event."aggregateType", event."aggregateId", event."organizationId", event."payload", event."attempts", event."createdAt"`;
  }

  private async process(event: OutboxRecord): Promise<void> {
    const startedAt = Date.now(); const handler = this.handlers.get(event.eventType);
    try {
      if (!handler) throw new Error(`No registered outbox handler for ${event.eventType}`);
      await handler.handle(event);
      const updated = await this.prisma.outboxEvent.updateMany({ where: { id: event.id, status: 'PROCESSING', leaseOwner: this.workerId }, data: { status: 'PROCESSED', processedAt: new Date(), leaseOwner: null, leaseExpiresAt: null, lastError: null } });
      if (updated.count !== 1) return;
      await this.prisma.identityAuditEvent.create({ data: { action: 'outbox.event.processed', metadata: { eventId: event.id, eventType: event.eventType, workerId: this.workerId } } });
      this.metrics.processed++; this.metrics.totalLatencyMs += Date.now() - event.createdAt.getTime();
    } catch (error) {
      const message = error instanceof Error ? error.message.slice(0, 512) : 'outbox handler failed';
      const deadLetter = event.attempts >= this.config.maximumAttempts;
      const delay = this.config.retryBaseDelayMs * 2 ** Math.max(0, event.attempts - 1);
      await this.prisma.outboxEvent.updateMany({ where: { id: event.id, status: 'PROCESSING', leaseOwner: this.workerId }, data: deadLetter ? { status: 'DEAD_LETTER', leaseOwner: null, leaseExpiresAt: null, lastError: message } : { status: 'PENDING', availableAt: new Date(Date.now() + delay), leaseOwner: null, leaseExpiresAt: null, lastError: message } });
      this.metrics.failed++; if (deadLetter) this.metrics.deadLetters++; else this.metrics.retries++;
    } finally { this.metrics.totalProcessingMs += Date.now() - startedAt; }
  }
}
