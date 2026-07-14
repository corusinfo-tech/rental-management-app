import { createServer, type Server } from 'node:http';
import { PrismaClient } from '@prisma/client';
import Redis from 'ioredis';
import { createOrganizationOutboxWorker } from './outbox/organization-outbox-worker';
import type { OutboxWorker } from './outbox/outbox-worker';
import type { WorkerRuntimeConfig } from './runtime-config';

type QueueSnapshot = { pending: number; deadLetters: number; lagMs: number };
type Probe = { healthy: boolean; latencyMs: number; error?: string };
type OutboxPort = Pick<OutboxWorker, 'workerId' | 'metrics' | 'pollOnce'>;
export type WorkerRuntimeDependencies = { prisma: PrismaClient; redis: Redis; outbox: OutboxPort };

export class WorkerRuntime {
  private readonly prisma: PrismaClient;
  private readonly redis: Redis;
  private readonly outbox: OutboxPort;
  private server?: Server;
  private pollTimer?: NodeJS.Timeout;
  private polling = false;
  private running = false;
  private startedAt?: Date;
  private lastPollStartedAt?: Date;
  private lastPollCompletedAt?: Date;
  private lastPollError?: string;
  private lastDatabaseProbe?: Probe;
  private lastRedisProbe?: Probe;

  constructor(private readonly config: WorkerRuntimeConfig, dependencies?: WorkerRuntimeDependencies) {
    this.prisma = dependencies?.prisma ?? new PrismaClient({ datasources: { db: { url: config.databaseUrl } } });
    this.redis = dependencies?.redis ?? new Redis(config.redisUrl, { lazyConnect: true, maxRetriesPerRequest: 1 });
    this.outbox = dependencies?.outbox ?? createOrganizationOutboxWorker(this.prisma, config);
  }

  async start(): Promise<void> {
    await this.assertDependencies();
    await this.startHealthServer();
    this.running = true;
    this.startedAt = new Date();
    await this.poll();
    this.pollTimer = setInterval(() => void this.poll(), this.config.pollIntervalMs);
  }

  async stop(): Promise<void> {
    this.running = false;
    if (this.pollTimer) clearInterval(this.pollTimer);
    await Promise.allSettled([
      this.server ? new Promise<void>((resolve) => this.server!.close(() => resolve())) : Promise.resolve(),
      this.redis.quit(),
      this.prisma.$disconnect(),
    ]);
  }

  async readiness(): Promise<{ ready: boolean; database: Probe; redis: Probe; worker: Record<string, unknown>; queue: QueueSnapshot }> {
    const [database, redis, queue] = await Promise.all([this.databaseProbe(), this.redisProbe(), this.queueSnapshot()]);
    return {
      ready: database.healthy && redis.healthy && this.running,
      database,
      redis,
      worker: this.workerState(),
      queue,
    };
  }

  metrics(): Record<string, unknown> {
    return {
      worker_started: this.running ? 1 : 0,
      outbox_events_processed_total: this.outbox.metrics.processed,
      outbox_events_failed_total: this.outbox.metrics.failed,
      outbox_retries_total: this.outbox.metrics.retries,
      outbox_dead_letters_total: this.outbox.metrics.deadLetters,
      outbox_processing_duration_ms_total: this.outbox.metrics.totalProcessingMs,
      outbox_queue_latency_ms_total: this.outbox.metrics.totalLatencyMs,
      database_latency_ms: this.lastDatabaseProbe?.latencyMs ?? null,
      redis_latency_ms: this.lastRedisProbe?.latencyMs ?? null,
      ...this.workerState(),
    };
  }

  healthPort(): number | undefined {
    const address = this.server?.address();
    return address && typeof address !== 'string' ? address.port : undefined;
  }

  private async assertDependencies(): Promise<void> {
    const database = await this.databaseProbe();
    if (!database.healthy) throw new Error(`PostgreSQL startup probe failed: ${database.error}`);
    const redis = await this.redisProbe();
    if (!redis.healthy) throw new Error(`Redis startup probe failed: ${redis.error}`);
  }

  private async poll(): Promise<void> {
    if (!this.running || this.polling) return;
    this.polling = true;
    this.lastPollStartedAt = new Date();
    try {
      await this.outbox.pollOnce();
      this.lastPollCompletedAt = new Date();
      this.lastPollError = undefined;
    } catch (error) {
      this.lastPollError = error instanceof Error ? error.message.slice(0, 512) : 'outbox poll failed';
    } finally {
      this.polling = false;
    }
  }

  private async databaseProbe(): Promise<Probe> {
    const started = performance.now();
    try {
      await this.prisma.$connect();
      await this.prisma.$queryRaw`SELECT 1`;
      const probe = { healthy: true, latencyMs: Math.round(performance.now() - started) };
      this.lastDatabaseProbe = probe;
      return probe;
    } catch (error) {
      const probe = { healthy: false, latencyMs: Math.round(performance.now() - started), error: error instanceof Error ? error.message : 'database unavailable' };
      this.lastDatabaseProbe = probe;
      return probe;
    }
  }

  private async redisProbe(): Promise<Probe> {
    const started = performance.now();
    try {
      if (this.redis.status === 'wait') await this.redis.connect();
      await this.redis.ping();
      const probe = { healthy: true, latencyMs: Math.round(performance.now() - started) };
      this.lastRedisProbe = probe;
      return probe;
    } catch (error) {
      const probe = { healthy: false, latencyMs: Math.round(performance.now() - started), error: error instanceof Error ? error.message : 'redis unavailable' };
      this.lastRedisProbe = probe;
      return probe;
    }
  }

  private async queueSnapshot(): Promise<QueueSnapshot> {
    const [pending, deadLetters, oldest] = await Promise.all([
      this.prisma.outboxEvent.count({ where: { status: 'PENDING' } }),
      this.prisma.outboxEvent.count({ where: { status: 'DEAD_LETTER' } }),
      this.prisma.outboxEvent.findFirst({ where: { status: 'PENDING' }, orderBy: { createdAt: 'asc' }, select: { createdAt: true } }),
    ]);
    return { pending, deadLetters, lagMs: oldest ? Math.max(0, Date.now() - oldest.createdAt.getTime()) : 0 };
  }

  private workerState(): Record<string, unknown> {
    return {
      worker_id: this.outbox.workerId,
      worker_running: this.running,
      worker_polling: this.polling,
      worker_started_at: this.startedAt?.toISOString() ?? null,
      worker_last_poll_started_at: this.lastPollStartedAt?.toISOString() ?? null,
      worker_last_poll_completed_at: this.lastPollCompletedAt?.toISOString() ?? null,
      worker_last_poll_error: this.lastPollError ?? null,
    };
  }

  private async startHealthServer(): Promise<void> {
    this.server = createServer(async (request, response) => {
      const send = (status: number, body: unknown) => {
        response.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' });
        response.end(JSON.stringify(body));
      };
      if (request.url === '/health/live') return send(this.running ? 200 : 503, { status: this.running ? 'ok' : 'starting' });
      if (request.url === '/health/ready') {
        try { const readiness = await this.readiness(); return send(readiness.ready ? 200 : 503, readiness); }
        catch (error) { return send(503, { ready: false, error: error instanceof Error ? error.message : 'health probe failed' }); }
      }
      if (request.url === '/metrics') {
        try { return send(200, { metrics: this.metrics(), queue: await this.queueSnapshot() }); }
        catch (error) { return send(503, { error: error instanceof Error ? error.message : 'metrics unavailable' }); }
      }
      return send(404, { error: 'not found' });
    });
    await new Promise<void>((resolve, reject) => {
      this.server!.once('error', reject);
      this.server!.listen(this.config.healthPort, this.config.host, () => { this.server!.off('error', reject); resolve(); });
    });
  }
}
