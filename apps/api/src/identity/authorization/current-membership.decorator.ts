import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import type { IdentityRequest, MembershipContext } from './request-context';

export const CurrentMembership = createParamDecorator(
  (_: unknown, context: ExecutionContext): MembershipContext | undefined =>
    context.switchToHttp().getRequest<IdentityRequest>().membership,
);
