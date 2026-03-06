---
title: Organizations & Roles
description: How authx-rs models multi-tenant organizations, memberships, and role-based access.
---

authx-rs models multi-tenancy around four core entities:

- `Organization`: the tenant or workspace.
- `Role`: a named set of permissions within one organization.
- `Membership`: the link between a user and a role in an organization.
- Session `org_id`: the user's active organization context for the current request.

## Mental model

```text
User
 ├─ Membership(org = acme, role = owner)
 └─ Membership(org = beta, role = viewer)

Session
 └─ active org = acme
```

The same person can belong to multiple organizations at once, but each request evaluates against one active organization at a time.

## What the organization layer gives you

- Tenant isolation without creating duplicate user accounts.
- Role-based permissions scoped to one organization.
- Invitation flows for onboarding users into a tenant.
- Session-level organization switching for SaaS apps with multiple workspaces.

## Core workflow

### 1. Create the tenant

`OrgService::create` creates the organization and an initial built-in `owner` role, then attaches the creator as the first member.

### 2. Define roles

Custom roles store a list of permission strings such as `billing.read`, `reports.export`, or `project.write`.

### 3. Invite users

Invites are token-based. authx-rs issues the raw token; your application delivers it by email or another channel.

### 4. Switch context per request

When a user belongs to multiple organizations, `switch_org` updates the session's active organization. Downstream authorization uses that active org when enforcing policies.

## Role evaluation

Roles are the RBAC half of the model. They are usually combined with policies for stronger guardrails:

- RBAC answers "does this membership have the named permission?"
- Policies answer "is this request allowed under the current context?"

That combination is what makes multi-tenant SaaS enforcement practical. A user may have `reports.read`, but a policy can still deny access if the request crosses organization boundaries or fails another attribute check.

## Related docs

- [Organizations](/authz/organizations/)
- [RBAC](/authz/rbac/)
- [Policies](/concepts/policies/)
- [Multi-tenant SaaS guide](/guides/multi-tenant-saas/)
