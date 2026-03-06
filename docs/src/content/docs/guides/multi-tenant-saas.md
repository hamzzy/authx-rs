---
title: Implement Multi-tenant SaaS with Organizations and Roles
description: Model tenants, memberships, role permissions, and request-time organization context with authx-rs.
---

This guide shows the recommended authx-rs shape for a B2B SaaS product where users can belong to one or more organizations.

## 1. Treat organizations as tenants

Each customer workspace should map to an authx `Organization`. Keep tenant-specific roles, memberships, and invitations under that organization instead of creating duplicate user accounts.

## 2. Create an owner-led organization

When the first user creates a workspace, call `OrgService::create`. This creates:

- the organization record
- a built-in `owner` role
- an owner membership for the creator

## 3. Model application roles explicitly

Create roles that mirror real permissions, not page names:

- `owner`
- `billing_admin`
- `editor`
- `viewer`

Permissions stay organization-scoped, so the same user can be an owner in one org and a viewer in another.

## 4. Invite users instead of creating shadow accounts

Use `invite_member` to issue a token and deliver it through your own email flow. After acceptance, the new membership is linked to the existing user identity.

## 5. Switch active organization per session

When a user chooses another workspace in the UI, call `switch_org` so the session carries the current tenant context. Handlers and policies can then enforce organization-local access without guessing which workspace the user meant.

## 6. Combine roles with policies

Recommended baseline:

- roles grant the business capability
- `OrgBoundaryPolicy` prevents cross-tenant access
- additional policies add contextual controls such as verified email, IP restrictions, or MFA

## 7. Persist tenant context in your app

Good request patterns:

- derive current org from the authx session
- include organization IDs in resource paths or resource strings
- reject requests where path org and active org disagree

## Example flow

1. Alice creates organization `acme`.
2. Alice receives `owner` membership in `acme`.
3. Alice creates a custom `billing_admin` role.
4. Alice invites Bob into `acme` with that role.
5. Bob signs in and switches his active org to `acme`.
6. Policies enforce that Bob can act only inside `acme`.

## Related docs

- [Organizations & Roles](/concepts/organizations-and-roles/)
- [Organizations](/authz/organizations/)
- [Multi-tenant example](/examples/multi-tenant/)
