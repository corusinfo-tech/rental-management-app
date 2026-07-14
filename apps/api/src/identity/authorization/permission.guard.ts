import { CanActivate, ExecutionContext, ForbiddenException, Injectable } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { CurrentMembershipResolver } from './current-membership.resolver';
import { REQUIRED_PERMISSIONS } from './require-permissions.decorator';
import type { IdentityRequest } from './request-context';

@Injectable()
export class PermissionGuard implements CanActivate {
  constructor(
    private readonly reflector: Reflector,
    private readonly memberships: CurrentMembershipResolver,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const required = this.reflector.getAllAndOverride<string[]>(REQUIRED_PERMISSIONS, [
      context.getHandler(),
      context.getClass(),
    ]) ?? [];
    if (required.length === 0) {
      return true;
    }

    const membership = await this.memberships.resolve(context.switchToHttp().getRequest<IdentityRequest>());
    if (!required.every((permission) => membership.permissionCodes.includes(permission))) {
      throw new ForbiddenException('Required permission is missing');
    }
    return true;
  }
}
