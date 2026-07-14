import type { Request } from 'express';

export type AccessTokenClaims = { sub: string; sid: string };

export type MembershipContext = {
  id: string;
  organizationId: string;
  permissionCodes: string[];
};

export type IdentityRequest = Request & {
  identity?: AccessTokenClaims;
  organizationId?: string;
  membership?: MembershipContext;
};
