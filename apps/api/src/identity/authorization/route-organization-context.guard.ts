import { BadRequestException, CanActivate, ExecutionContext, Injectable } from '@nestjs/common';
import type { IdentityRequest } from './request-context';

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

/** Binds authorization context to the resource route, never to a caller-selected header. */
@Injectable()
export class RouteOrganizationContextGuard implements CanActivate {
  canActivate(context: ExecutionContext): boolean {
    const request = context.switchToHttp().getRequest<IdentityRequest>();
    const organizationId = request.params?.id;
    if (!organizationId || !UUID_PATTERN.test(organizationId)) throw new BadRequestException('Organization route parameter must be a UUID');
    const supplied = request.header('x-organization-id');
    if (supplied && supplied !== organizationId) throw new BadRequestException('x-organization-id does not match the organization route parameter');
    request.organizationId = organizationId;
    return true;
  }
}
