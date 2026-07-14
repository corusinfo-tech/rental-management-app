import { ConflictException, ForbiddenException, NotFoundException, BadRequestException, Injectable } from '@nestjs/common';
import { randomUUID } from 'node:crypto';
import { Prisma } from '@prisma/client';
import { AssignOrganizationRoleDto, CreateOrganizationRoleDto, OrganizationRoleResponseDto, SetRolePermissionsDto, UpdateOrganizationRoleDto } from './dto/role.dto';
import { OrganizationRoleRepository } from './role.repository';
import { OrganizationEvent } from './organization-events';

@Injectable()
export class OrganizationRoleService {
  constructor(private readonly repository: OrganizationRoleRepository) {}

  async create(actorUserId: string, organizationId: string, input: CreateOrganizationRoleDto): Promise<OrganizationRoleResponseDto> {
    try {
      return await this.repository.transaction(async (transaction) => {
        await this.assertOwner(actorUserId, organizationId, transaction);
        if (await this.repository.findCustomByName(input.name, organizationId, transaction)) throw new ConflictException('Role name already exists');
        if (input.isDefault) await this.repository.clearDefault(organizationId, undefined, transaction);
        const role = await this.repository.create({ organizationId, code: this.code(input.name), name: input.name, description: input.description, isDefault: input.isDefault ?? false }, transaction);
        const payload = { organizationId, roleId: role.id, actorUserId };
        await this.repository.audit(actorUserId, 'organization.role.created', payload, transaction);
        await this.repository.outbox(OrganizationEvent.RoleCreated, 'Role', role.id, organizationId, payload, transaction);
        return this.response(role, []);
      });
    } catch (error) {
      if (this.isUnique(error)) throw new ConflictException('Role name or code already exists');
      throw error;
    }
  }

  async list(actorUserId: string, organizationId: string): Promise<OrganizationRoleResponseDto[]> {
    await this.repository.transaction((transaction) => this.assertOwner(actorUserId, organizationId, transaction));
    return (await this.repository.list(organizationId)).map((role) => this.response(role, role.permissions.filter((entry) => !entry.permission.deletedAt).map((entry) => entry.permission.code)));
  }

  async update(actorUserId: string, organizationId: string, roleId: string, input: UpdateOrganizationRoleDto): Promise<OrganizationRoleResponseDto> {
    return this.repository.transaction(async (transaction) => {
      await this.assertOwner(actorUserId, organizationId, transaction);
      const role = await this.requireCustom(roleId, organizationId, transaction);
      if (input.name && input.name.toLowerCase() !== role.name.toLowerCase() && await this.repository.findCustomByName(input.name, organizationId, transaction)) throw new ConflictException('Role name already exists');
      if (input.isDefault) await this.repository.clearDefault(organizationId, roleId, transaction);
      const updated = await this.repository.update(role.id, { name: input.name, description: input.description, isDefault: input.isDefault }, transaction);
      await this.repository.audit(actorUserId, 'organization.role.updated', { organizationId, roleId, actorUserId }, transaction);
      return this.response(updated, role.permissions.filter((entry) => !entry.permission.deletedAt).map((entry) => entry.permission.code));
    });
  }

  async delete(actorUserId: string, organizationId: string, roleId: string) {
    return this.repository.transaction(async (transaction) => {
      await this.assertOwner(actorUserId, organizationId, transaction);
      const role = await this.requireCustom(roleId, organizationId, transaction);
      await this.repository.softDelete(role.id, transaction);
      await this.repository.audit(actorUserId, 'organization.role.deleted', { organizationId, roleId, actorUserId }, transaction);
      return { accepted: true };
    });
  }

  async setPermissions(actorUserId: string, organizationId: string, roleId: string, input: SetRolePermissionsDto) {
    return this.repository.transaction(async (transaction) => {
      await this.assertOwner(actorUserId, organizationId, transaction);
      await this.requireCustom(roleId, organizationId, transaction);
      const permissions = await this.repository.findPermissions(input.permissionIds, transaction);
      if (permissions.length !== input.permissionIds.length) throw new BadRequestException('One or more permissions are unavailable');
      const current = new Set((await this.repository.rolePermissionIds(roleId, transaction)).map((entry) => entry.permissionId));
      const requested = new Set(input.permissionIds);
      const granted = input.permissionIds.filter((id) => !current.has(id));
      const revoked = input.replace ? [...current].filter((id) => !requested.has(id)) : [];
      if (granted.length) await this.repository.grantPermissions(roleId, granted, transaction);
      if (revoked.length) await this.repository.revokePermissions(roleId, revoked, transaction);
      const base = { organizationId, roleId, actorUserId };
      for (const permissionId of granted) await this.repository.audit(actorUserId, 'organization.permission.granted', { ...base, permissionId }, transaction);
      for (const permissionId of revoked) await this.repository.audit(actorUserId, 'organization.permission.revoked', { ...base, permissionId }, transaction);
      if (granted.length) await this.repository.outbox(OrganizationEvent.PermissionGranted, 'Role', roleId, organizationId, { ...base, permissionIds: granted }, transaction);
      return { accepted: true };
    });
  }

  async assign(actorUserId: string, organizationId: string, membershipId: string, input: AssignOrganizationRoleDto) {
    return this.repository.transaction(async (transaction) => {
      await this.assertOwner(actorUserId, organizationId, transaction);
      const membership = await this.repository.findMembership(membershipId, organizationId, transaction);
      if (!membership) throw new NotFoundException('Membership not found');
      const role = await this.repository.findAssignable(input.roleId, organizationId, transaction);
      if (!role) throw new NotFoundException('Role not found');
      const payload = { organizationId, membershipId, roleId: role.id, assignedBy: actorUserId };
      if (input.remove) {
        const removed = await this.repository.remove(membershipId, role.id, transaction);
        if (removed.count) await this.repository.audit(actorUserId, 'organization.role.removed', payload, transaction);
        return { accepted: true };
      }
      await this.repository.assign(membershipId, role.id, actorUserId, transaction);
      await this.repository.audit(actorUserId, 'organization.role.assigned', payload, transaction);
      await this.repository.outbox(OrganizationEvent.RoleAssigned, 'OrganizationMembership', membershipId, organizationId, payload, transaction);
      return { accepted: true };
    });
  }

  private async assertOwner(userId: string, organizationId: string, transaction: Prisma.TransactionClient) {
    if (!(await this.repository.ownerMembership(userId, organizationId, transaction))) throw new ForbiddenException('Only organization owners may manage roles');
  }

  private async requireCustom(roleId: string, organizationId: string, transaction: Prisma.TransactionClient) {
    const role = await this.repository.findCustom(roleId, organizationId, transaction);
    if (!role) throw new NotFoundException('Custom organization role not found');
    return role;
  }

  private code(name: string) { return `org-${name.trim().toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 40) || 'role'}-${randomUUID().slice(0, 8)}`; }
  private response(role: { id: string; organizationId: string | null; code: string; name: string; description: string | null; isSystem: boolean; isDefault: boolean; createdAt: Date; updatedAt: Date }, permissionCodes: string[]): OrganizationRoleResponseDto { return { id: role.id, organizationId: role.organizationId, code: role.code, name: role.name, description: role.description, isSystem: role.isSystem, isDefault: role.isDefault, permissionCodes, createdAt: role.createdAt, updatedAt: role.updatedAt }; }
  private isUnique(error: unknown) { return typeof error === 'object' && error !== null && 'code' in error && error.code === 'P2002'; }
}
