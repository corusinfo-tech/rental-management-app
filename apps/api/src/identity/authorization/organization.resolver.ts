import { BadRequestException, Injectable } from '@nestjs/common';
import type { IdentityRequest } from './request-context';

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

@Injectable()
export class OrganizationResolver {
  resolve(request: IdentityRequest): string | undefined {
    if (request.organizationId) return request.organizationId;
    const header = request.header('x-organization-id');
    if (!header) {
      return undefined;
    }
    if (!UUID_PATTERN.test(header)) {
      throw new BadRequestException('x-organization-id must be a UUID');
    }
    request.organizationId = header;
    return header;
  }
}
