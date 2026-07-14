import { ForbiddenException, Injectable, UnauthorizedException } from '@nestjs/common';
import { IdentityRepository } from '../repositories/identity.repository';
import { OrganizationResolver } from './organization.resolver';
import type { IdentityRequest, MembershipContext } from './request-context';

@Injectable()
export class CurrentMembershipResolver {
  constructor(
    private readonly repository: IdentityRepository,
    private readonly organizations: OrganizationResolver,
  ) {}

  async resolve(request: IdentityRequest): Promise<MembershipContext> {
    const userId = request.identity?.sub;
    if (!userId) {
      throw new UnauthorizedException('Access token is required');
    }

    const organizationId = this.organizations.resolve(request);
    if (!organizationId) {
      throw new ForbiddenException('Organization context is required');
    }

    const membership = await this.repository.findActiveMembershipForUser(userId, organizationId);
    if (!membership) {
      throw new ForbiddenException('Active organization membership is required');
    }

    const context = {
      id: membership.id,
      organizationId: membership.organizationId,
      permissionCodes: membership.roles.flatMap((membershipRole) =>
        membershipRole.role.permissions.map((rolePermission) => rolePermission.permission.code),
      ),
    };
    request.membership = context;
    return context;
  }
}
