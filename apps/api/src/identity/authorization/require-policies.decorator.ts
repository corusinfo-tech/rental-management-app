import { SetMetadata } from '@nestjs/common';
import type { MembershipContext } from './request-context';

export type PolicyHandler = (context: MembershipContext) => boolean | Promise<boolean>;

export const REQUIRED_POLICIES = 'identity:required-policies';
export const RequirePolicies = (...policies: PolicyHandler[]) => SetMetadata(REQUIRED_POLICIES, policies);
