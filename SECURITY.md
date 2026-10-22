# Security policy

## Supported versions

Only the latest 0.x release receives security fixes.

## Reporting a vulnerability

Report vulnerabilities privately through GitHub's private vulnerability
reporting: open this repository's **Security** tab and select **Report a
vulnerability**. Do not report them in public issues, pull requests or
discussions.

Include the plugin and Traefik versions, the relevant static and dynamic
configuration, and the requests or steps that reproduce the problem.

## What to expect

The maintainers reply in the private advisory and coordinate the fix and its
disclosure with you there. A confirmed vulnerability is fixed in a new release,
and the advisory is published once that release is available.

## Scope

In scope is the plugin in this repository: for example, a request that gets an
untrusted client IP restored, or that reaches a protected host without a
pinned certificate or a `directAccessCIDRs` source address.

Out of scope:

- Traefik and Cloudflare. Report vulnerabilities in them to their maintainers.
- [`aopctl`](https://github.com/krystal/aopctl), which has its own repository.
- Deployments that do not meet the README's
  [deployment preconditions](README.md#deployment-preconditions), unless the
  README itself is wrong.
