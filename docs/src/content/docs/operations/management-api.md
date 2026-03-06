---
title: Management API Plan
description: Proposed control-plane API for multi-cluster and multi-region authx deployments.
---

This page outlines a future management API for operators running authx in multiple clusters or regions.

## Problem it solves

The current crates focus on embedding auth into one application. Larger deployments need an operator-facing control plane for:

- key distribution and rotation visibility
- region health and replication state
- cluster registration
- auditability of platform actions

## Likely scope

### Cluster registration

- register cluster identity
- advertise region, version, and capabilities
- expose liveness / readiness / degradation state

### Key management

- inspect active and next signing keys
- distribute new public key material
- coordinate rollout windows
- audit rotations and revocations

### Replication visibility

- show token/session replication lag where relevant
- show last successful sync time
- surface partial-region degradation cleanly

## Security model

This API must not reuse normal end-user sessions.

Recommended model:

- dedicated operator principals
- strong RBAC for platform operations
- separate scopes for read-only versus mutating control-plane actions
- audit logs for every management action

## Candidate endpoint groups

- `/management/clusters`
- `/management/regions`
- `/management/keys`
- `/management/replication`
- `/management/audit`

## Non-goals

At least initially, this should not become:

- a full hosted SaaS control plane
- a generic infrastructure orchestration system
- a replacement for normal application-domain admin APIs

## Rollout recommendation

1. define operator auth and RBAC model
2. ship read-only health/status endpoints first
3. add key lifecycle operations next
4. add replication and multi-region coordination features after real deployment feedback
