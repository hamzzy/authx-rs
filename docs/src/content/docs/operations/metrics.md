---
title: Metrics & Tracing Plan
description: Proposed Prometheus and OpenTelemetry integration model for authx events and request flows.
---

This page describes the intended shape of optional metrics integration for authx-rs.

## Design principle

Instrumentation should be additive and opt-in. Core auth behavior must not require a metrics backend.

## EventBus subscriber model

The cleanest attachment point is an `EventBus` subscriber that translates `AuthEvent` values into counters and rates.

Candidate counters:

- `authx_sign_in_total`
- `authx_sign_in_failure_total`
- `authx_sign_out_total`
- `authx_user_created_total`
- `authx_session_revoked_total`
- `authx_oidc_federation_begin_total`
- `authx_oidc_federation_callback_total`
- `authx_oidc_provider_token_exchange_total`

## Histograms and timers

Some useful latency histograms are not event-only. They should be measured around service methods or HTTP endpoints:

- password sign-in latency
- OIDC token exchange latency
- userinfo fetch latency
- storage-heavy operations such as listing sessions or revoking tokens

## OpenTelemetry spans

Recommended span boundaries:

- auth flow entry points (`sign_up`, `sign_in`, `sign_out`)
- OIDC provider authorization-code exchange
- refresh token flow
- federation begin / callback
- storage repository calls that are operationally significant

Example span names:

- `authx.auth.sign_in`
- `authx.oidc.exchange_code`
- `authx.federation.callback`
- `authx.storage.session.find_by_token_hash`

## Label privacy rules

Do not emit raw user identifiers, emails, session tokens, or provider access tokens as labels.

Safe labels are typically:

- outcome (`success`, `failure`)
- flow (`email_password`, `oidc_federation`, `device_code`)
- provider name when it is configuration-level metadata
- status class (`2xx`, `4xx`, `5xx`)

## Prometheus integration shape

The likely implementation path is a small optional crate or module that:

- subscribes to `EventBus`
- owns counters/histograms
- exposes a scrape endpoint through the host framework

## Rollout recommendation

1. define stable metric names
2. implement EventBus-based counters first
3. add spans around OIDC and federation flows
4. document privacy guarantees before calling the feature production-ready
