// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

import cloudflare from '@astrojs/cloudflare';

export default defineConfig({
  integrations: [
    starlight({
      title: 'authx-rs',
      description: 'Production-grade authentication & authorization framework for Rust',
      logo: {
        light: './src/assets/logo-light.svg',
        dark:  './src/assets/logo-dark.svg',
        replacesTitle: false,
      },
      social: [
        { icon: 'github', label: 'GitHub', href: 'https://github.com/authx/authx-rs' },
      ],
      editLink: {
        baseUrl: 'https://github.com/authx/authx-rs/edit/main/docs/',
      },
      customCss: ['./src/styles/custom.css'],
      sidebar: [
        {
          label: 'Getting Started',
          items: [
            { label: 'Introduction',     slug: 'getting-started/introduction' },
            { label: 'Quick Start',      slug: 'getting-started/quick-start' },
            { label: 'Architecture',     slug: 'getting-started/architecture' },
            { label: 'Configuration',    slug: 'getting-started/configuration' },
          ],
        },
        {
          label: 'Core Concepts',
          items: [
            { label: 'Plugins',          slug: 'concepts/plugins' },
            { label: 'Storage Adapters', slug: 'concepts/storage' },
            { label: 'Sessions',         slug: 'concepts/sessions' },
            { label: 'Identity',         slug: 'concepts/identity' },
            { label: 'Events & Audit',   slug: 'concepts/events' },
          ],
        },
        {
          label: 'Authentication',
          items: [
            { label: 'Email + Password', slug: 'auth/email-password' },
            { label: 'Magic Link',       slug: 'auth/magic-link' },
            { label: 'Email OTP',        slug: 'auth/email-otp' },
            { label: 'Username Login',   slug: 'auth/username' },
            { label: 'Anonymous / Guest',slug: 'auth/anonymous' },
            { label: 'OAuth (Social)',   slug: 'auth/oauth' },
            { label: 'API Keys',         slug: 'auth/api-keys' },
          ],
        },
        {
          label: 'Multi-Factor Auth',
          items: [
            { label: 'TOTP Setup',       slug: 'mfa/totp' },
            { label: 'Backup Codes',     slug: 'mfa/backup-codes' },
            { label: 'Email OTP (MFA)',  slug: 'mfa/email-otp' },
          ],
        },
        {
          label: 'Authorization',
          items: [
            { label: 'RBAC',             slug: 'authz/rbac' },
            { label: 'ABAC Policies',    slug: 'authz/abac' },
            { label: 'Organizations',    slug: 'authz/organizations' },
          ],
        },
        {
          label: 'Security',
          items: [
            { label: 'Passwords & Crypto',slug: 'security/crypto' },
            { label: 'Rate Limiting',    slug: 'security/rate-limiting' },
            { label: 'Brute Force',      slug: 'security/brute-force' },
            { label: 'CSRF Protection',  slug: 'security/csrf' },
            { label: 'Key Rotation',     slug: 'security/key-rotation' },
          ],
        },
        {
          label: 'Storage',
          items: [
            { label: 'Memory Store',     slug: 'storage/memory' },
            { label: 'PostgreSQL',       slug: 'storage/postgres' },
            { label: 'Custom Adapter',   slug: 'storage/custom' },
          ],
        },
        {
          label: 'HTTP / Axum',
          items: [
            { label: 'Axum Integration', slug: 'http/axum' },
            { label: 'Middleware',       slug: 'http/middleware' },
            { label: 'Route Handlers',   slug: 'http/handlers' },
            { label: 'Admin Dashboard',  slug: 'http/dashboard' },
          ],
        },
        {
          label: 'CLI',
          items: [
            { label: 'authx CLI',        slug: 'cli/overview' },
          ],
        },
        {
          label: 'Examples',
          items: [
            { label: 'Axum App',         slug: 'examples/axum-app' },
            { label: 'Multi-Tenant SaaS',slug: 'examples/multi-tenant' },
          ],
        },
        {
          label: 'Reference',
          autogenerate: { directory: 'reference' },
        },
      ],
    }),
  ],

  adapter: cloudflare(),
});