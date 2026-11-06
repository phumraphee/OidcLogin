# Changelog

## 1.2.0 — 2026-11-06

First public release.

- Log in with an OpenID Connect provider (authorization code flow with PKCE, state and nonce;
  tokens fetched on the server with the client secret) **next to** the normal password log-in,
  which is never removed.
- People link their own provider account from their account page, or a global admin types each
  person's provider username on **Log-in accounts** (`/admin/oidc-login`), with
  suggestions from the provider's user list (Pocket ID API key) or a pasted list.
- Optional, off by default: accounts from provider groups — a group mapped to an Omeka role
  creates or links the user on first log-in and keeps the role in step.
- Logout ends the provider's log-in too (its end-session page), so a shared computer keeps
  neither.
- Account name and button text in English, with a second text for browsers that ask for Thai
  first. Without a Thai text the button says "Log in with" and the account name.
- The client id and secret are read only from `config/local.config.php` (`'oidclogin'`), never
  from the database or a form.
