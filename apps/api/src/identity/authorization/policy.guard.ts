import { CanActivate, ExecutionContext, ForbiddenException, Injectable } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { CurrentMembershipResolver } from './current-membership.resolver';
import { REQUIRED_POLICIES, type PolicyHandler } from './require-policies.decorator';
import type { IdentityRequest } from './request-context';

@Injectable()
export class PolicyGuard implements CanActivate {
  constructor(
    private readonly reflector: Reflector,
    private readonly memberships: CurrentMembershipResolver,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const policies = this.reflector.getAllAndOverride<PolicyHandler[]>(REQUIRED_POLICIES, [
      context.getHandler(),
      context.getClass(),
    ]) ?? [];
    if (policies.length === 0) {
      return true;
    }

    const membership = await this.memberships.resolve(context.switchToHttp().getRequest<IdentityRequest>());
    if (!(await Promise.all(policies.map((policy) => policy(membership)))).every(Boolean)) {
      throw new ForbiddenException('Policy requirements are not met');
    }
    return true;
  }
}
