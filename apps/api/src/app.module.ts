import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { validateEnvironment } from './config/environment';
import { DatabaseModule } from './database/database.module';
import { HealthModule } from './health/health.module';
import { LoggerModule } from './core/logger/logger.module';
import { CorrelationIdMiddleware } from './core/request/correlation-id.middleware';
import { RequestIdMiddleware } from './core/request/request-id.middleware';
import { IdentityModule } from './identity/identity.module';
import { OrganizationModule } from './organization/organization.module';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      cache: true,
      expandVariables: true,
      validate: validateEnvironment,
    }),
    DatabaseModule,
    LoggerModule,
    HealthModule,
    IdentityModule,
    OrganizationModule,
  ],
  providers: [RequestIdMiddleware, CorrelationIdMiddleware],
})
export class AppModule {}
