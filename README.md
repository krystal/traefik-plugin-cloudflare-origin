# traefik-plugin-cloudflare-origin

A Traefik v3 middleware plugin for origins behind Cloudflare's proxy. For
requests that present a pinned Cloudflare Authenticated Origin Pulls (AOP)
client certificate, it restores the client IP from `Cf-Connecting-Ip`. It can
also restrict hosts to those requests plus an allowlist of source CIDRs.

It targets Traefik v3, which runs plugins through the Yaegi interpreter, and
uses only the Go standard library. The test suite runs against the Traefik
release locked in [`mise.lock`](mise.lock).

To put one service behind Cloudflare with this plugin:

1. Read the [security model](#security-model) and the
   [deployment preconditions](#deployment-preconditions).
2. [Set up Cloudflare](#set-up-cloudflare) with your own AOP certificate.
3. [Install the plugin](#install-the-plugin) in Traefik.
4. Apply [example 1](#1-gate-one-service), following the
   [rollout order](#roll-out).

## The problem

When a hostname moves behind Cloudflare, the TCP peer Traefik sees is a
Cloudflare edge server. Applications that read `X-Forwarded-For` from the right
and trust only the pod network then log and rate-limit the edge IP instead of
the client.

Traefik's `forwardedHeaders.trustedIPs` does not fix this. It keeps
Cloudflare's `X-Forwarded-For` and appends the edge IP, so the rightmost entry
is still the edge. Applications would then need to trust Cloudflare's ranges,
which the [security model](#security-model) explains is unsafe. Remove
Cloudflare's ranges from `trustedIPs` when you adopt this plugin.

This plugin makes the request look as if Cloudflare were not there. On a
request it trusts, it rewrites the request's remote address to the client IP.
Traefik's proxy then builds `X-Forwarded-For` from that address, the plugin
sets `X-Real-Ip` to match, and applications need no changes.

## Security model

**Cloudflare's IP ranges do not prove a request came through your zone.** Every
Cloudflare customer's traffic, including Workers, leaves from the same ranges,
and any Cloudflare account can send requests to your origin. A source IP check
cannot tell your zone's traffic from someone else's, so it cannot tell whether
Cloudflare set `Cf-Connecting-Ip` for one of your visitors.

**Cloudflare's global AOP certificate does not prove it either.** Cloudflare
presents the same global certificate for every zone that enables zone-level
AOP without uploading its own certificate. An origin that trusts that
certificate accepts requests proxied for any Cloudflare customer.

**Per-zone or per-hostname AOP with your own CA does.** You create a CA, issue
a client certificate from it, and upload that certificate to Cloudflare for
your zone or hostname. Traefik verifies the client certificate against your
CA, and the plugin then checks that the verified chain contains a certificate
you pinned by SHA-256 fingerprint. Only Cloudflare's connections for your
hostnames carry that certificate.

The pin matters because Traefik chooses TLS options per hostname, from the SNI.
An entrypoint-wide plugin instance also sees requests whose TLS option trusts
some other client CA, such as another team's mTLS setup. Without the pin, any
verified certificate would allow the client IP rewrite.

**Same-zone Workers are inside the trust boundary.** A Worker running in your
own zone sends its subrequests through your zone, so they carry your AOP
certificate. Cloudflare documents that such a Worker can set the
`CF-Connecting-IP` value through `x-real-ip`. That value can be any address,
including one in your pod network that applications treat as internal. Only
give Worker access to people you would trust to set the client IP.

## How it works

Two pieces of Traefik configuration work together:

- A **TLSOption** with `clientAuth` makes Traefik ask for and verify client
  certificates. Traefik picks the TLSOption per hostname, from the SNI in the
  TLS handshake.
- The plugin's **Middleware** inspects the verified certificate. You attach it
  to an IngressRoute (router level) or to an entrypoint (every router on it).

For each request, the plugin:

1. Records the original remote address, `Cf-Connecting-Ip` and `X-Real-Ip`
   values the first time it runs in a middleware chain. Later instances in the
   same chain make their decisions from these original values.
2. Treats the request as verified when a verified certificate chain contains a
   certificate whose SHA-256 fingerprint is in `clientCertFingerprints`.
   Unverified peer certificates do not count.
3. Deletes `True-Client-Ip`, `Cf-Connecting-Ipv6`, `Cf-Pseudo-Ipv4`, and
   underscore variants of these and `Cf-Connecting-Ip`, on every request.
4. On a verified request with exactly one valid `Cf-Connecting-Ip` value, sets
   the remote address to that IP (keeping the original port) and sets
   `X-Real-Ip` and `Cf-Connecting-Ip` to it. Otherwise it restores the
   original remote address and the `X-Real-Ip` value Traefik set, and deletes
   `Cf-Connecting-Ip`.
5. Returns `403 Forbidden` when the request is protected, not verified, and
   its original peer IP is not in `directAccessCIDRs`. A request is protected
   when its host is in `protectedHosts`, or always when `protectAllHosts` is
   set.

A verified request without a usable `Cf-Connecting-Ip` passes through with the
edge IP as the client. When `allowMissingClientIP` is `false`, it gets a 403
instead, on every host the instance sees.

Requests allowed through `directAccessCIDRs` are unverified, so their
`Cf-Connecting-Ip` is never read and the backend sees their TCP source IP.

When an entrypoint instance and a router instance both run, the router
instance runs last and decides the final client IP. A router instance with a
narrower pin can therefore undo the entrypoint instance's rewrite, and it
gates on the original peer IP rather than the rewritten one.

## Configuration

- `clientCertFingerprints` (list, required): SHA-256 fingerprints of a
  certificate's DER encoding, in hex. Colons and case are ignored. At least one
  is required. Pin your AOP CA so leaf rotation needs no config change.
- `protectedHosts` (list, default empty): exact hostnames to protect. Matching
  is case-insensitive and ignores the port and trailing dots. Wildcards are not
  supported. Leave it empty to only restore client IPs.
- `directAccessCIDRs` (list, default empty): CIDRs or single IPs allowed to
  reach protected hosts without a certificate, matched against the TCP peer.
  IPv4-mapped IPv6 ranges such as `::ffff:0:0/96` are rejected; use the IPv4
  form.
- `protectAllHosts` (bool, default `false`): protect every request this
  instance sees. Use it on a router-level instance so the protection follows
  the router's match.
- `allowMissingClientIP` (bool, default `true`): let a verified request without
  a single valid `Cf-Connecting-Ip` value through, with the edge IP as the
  client. Set it to `false` to reject such requests with a 403 on every host
  this instance sees.

Traefik matches these keys case-insensitively and silently ignores unknown
keys, so check spelling against this list.

Traefik refuses to create an instance when a fingerprint is not 64 hex
characters, a CIDR does not parse or is an IPv4-mapped IPv6 range, or a host
is empty or contains `*`, `:`, `/`, whitespace or non-ASCII characters. It
then skips every router that uses that instance. For an entrypoint instance,
that is every router on the entrypoint.

## Set up Cloudflare

1. Create a CA and issue a client certificate from it. Keep the CA key
   offline, and use the CA only for AOP: the plugin trusts every certificate
   it signs.
2. Upload the client certificate and key to Cloudflare as a
   [per-hostname](https://developers.cloudflare.com/ssl/origin-configuration/authenticated-origin-pull/set-up/per-hostname/)
   or zone-level
   [Authenticated Origin Pulls](https://developers.cloudflare.com/ssl/origin-configuration/authenticated-origin-pull/)
   certificate, and enable it for the hostnames that should use it.
3. Set the zone's SSL/TLS mode to Full (strict).
4. Do not set Pseudo IPv4 to "Overwrite Headers". It replaces
   `CF-Connecting-IP` with a Class E address.
5. Compute the pin from your CA certificate:

   ```sh
   openssl x509 -in aop-ca.crt -noout -fingerprint -sha256
   ```

   Use the value after `Fingerprint=`. Colons are fine.

### Rotate the CA

1. Trust both CAs in Traefik. Add a Secret for the new CA to the TLSOption's
   `clientAuth.secretNames` next to the old one (or add it to `caFiles` with
   the file provider). Without this, Traefik rejects the new certificate during
   the TLS handshake, before the plugin can check it.
2. List both the old and new fingerprints in `clientCertFingerprints`.
3. Roll out the new client certificate in Cloudflare.
4. Remove the old fingerprint and the old CA from Traefik.

Rotating only the leaf certificate under an unchanged CA needs none of this
when you pin the CA.

## Install the plugin

Traefik loads this plugin as a local plugin: Traefik must find the three plugin
files, `.traefik.yml`, `go.mod` and `cloudflare_origin.go`, in
`/plugins-local/src/github.com/krystal/traefik-plugin-cloudflare-origin`. With
the Traefik Helm chart 41.1.1 you can provide them in two ways:

- **Inline source** (`inlinePlugin`): the files live in your Helm values, and
  the chart mounts them from a ConfigMap. Upgrades are a reviewable diff in
  your values, and Traefik needs no network access to load the plugin. Use this
  unless the values size or copy step is a problem.
- **Fetched at startup** (`localPath`): an init container clones a pinned
  release into a volume. Your values stay small, but every new Traefik pod
  needs to reach GitHub, and a failed fetch keeps the pod from starting.

The chart mounts the ConfigMap flat, which is why the plugin's files sit at the
root of this repository.

Set `experimental.abortOnPluginFailure: true` either way. If the plugin then
fails to load, Traefik refuses to start instead of starting without the plugin
and skipping every router that uses it.

The middleware examples below refer to the plugin by the name used here,
`cloudflare-origin`.

### Inline source in Helm values

Copy the three files from a tagged release into your values, unmodified:
replace each placeholder comment below with the full contents of that file.
This works with any Helm-based deployment, including Argo CD and Flux.

```yaml
experimental:
  abortOnPluginFailure: true
  localPlugins:
    cloudflare-origin:
      moduleName: github.com/krystal/traefik-plugin-cloudflare-origin
      mountPath: /plugins-local/src/github.com/krystal/traefik-plugin-cloudflare-origin
      type: inlinePlugin
      source:
        .traefik.yml: |
          # Contents of .traefik.yml
        go.mod: |
          module github.com/krystal/traefik-plugin-cloudflare-origin

          go 1.22
        cloudflare_origin.go: |
          // Contents of cloudflare_origin.go
```

To upgrade, replace the three files with those from the new release.

When you run Helm directly, `--set-file` reads the files from a checkout of
this repository instead. Keep the rest of the block above in `values.yaml`,
without `source`:

```sh
helm upgrade --install traefik traefik/traefik --version 41.1.1 \
  --namespace traefik --values values.yaml \
  --set-file 'experimental.localPlugins.cloudflare-origin.source.\.traefik\.yml=.traefik.yml' \
  --set-file 'experimental.localPlugins.cloudflare-origin.source.go\.mod=go.mod' \
  --set-file 'experimental.localPlugins.cloudflare-origin.source.cloudflare_origin\.go=cloudflare_origin.go'
```

### Fetched at startup

An init container clones the release tag and checks that it points at the
commit you expect, so a moved tag fails the pod instead of loading different
code. Replace `<tag>` and `<commit SHA>` with a release and its full commit
SHA, and pin the `alpine/git` image to a tag and digest you trust.

```yaml
deployment:
  initContainers:
    - name: fetch-cloudflare-origin
      image: alpine/git:<tag>@sha256:<digest>
      env:
        - name: HOME
          value: /tmp
        - name: PLUGIN_TAG
          value: <tag>
        - name: PLUGIN_COMMIT
          value: <commit SHA>
      command: [sh, -euc]
      args:
        - |
          git -c advice.detachedHead=false clone --quiet --depth 1 --branch "$PLUGIN_TAG" \
            https://github.com/krystal/traefik-plugin-cloudflare-origin.git /tmp/src
          cd /tmp/src
          test "$(git rev-parse HEAD)" = "$PLUGIN_COMMIT"
          cp .traefik.yml go.mod cloudflare_origin.go /plugin/
      securityContext:
        allowPrivilegeEscalation: false
        capabilities:
          drop: [ALL]
        readOnlyRootFilesystem: true
      volumeMounts:
        - name: cloudflare-origin
          mountPath: /plugin
        - name: cloudflare-origin-tmp
          mountPath: /tmp
  additionalVolumes:
    - name: cloudflare-origin
      emptyDir: {}
    - name: cloudflare-origin-tmp
      emptyDir: {}

experimental:
  abortOnPluginFailure: true
  localPlugins:
    cloudflare-origin:
      moduleName: github.com/krystal/traefik-plugin-cloudflare-origin
      mountPath: /plugins-local/src/github.com/krystal/traefik-plugin-cloudflare-origin
      type: localPath
      volumeName: cloudflare-origin
```

The init container runs as the chart's non-root pod user, so its writable
paths are the two `emptyDir` volumes. `HOME` points at one of them because Git
writes there.

## Deployment preconditions

Check these before you deploy. The plugin cannot detect most of them.

- In entrypoint mode, attach the plugin to every entrypoint that routes to a
  protected service, and list it first so later middlewares see the restored
  client IP.
- Protected routers should use exact `Host()` rules. For `HostRegexp` or
  wildcard routers, use a router-level instance with `protectAllHosts`.
- Keep Traefik's `cnameFlattening` off. It lets a CNAME alias match a protected
  `Host()` rule under a name that `protectedHosts` does not list.
- Do not list Cloudflare's ranges in `forwardedHeaders.trustedIPs`, and do not
  set `forwardedHeaders.insecure`, on an entrypoint that uses the plugin.
  Traefik keeps the forwarding headers that trusted peers send, and the plugin
  passes them through on requests it does not rewrite. With Cloudflare trusted,
  a request from another Cloudflare account would reach the backend with an
  `X-Forwarded-For` and `X-Real-Ip` of its choosing. List only proxies you
  control.
- Keep `forwardedHeaders.notAppendXForwardedFor` off, or Traefik will not add
  the restored client IP to `X-Forwarded-For`.
- Keep HTTP/3 off. It is untested with this plugin.
- TCP routers with `HostSNI` rules bypass HTTP middlewares, including this one.
- `directAccessCIDRs` must not overlap node or load balancer SNAT ranges, or
  every request arriving through SNAT counts as direct access. Use
  `externalTrafficPolicy: Local` or the PROXY protocol so Traefik sees real
  source IPs.
- Set Cloudflare's SSL/TLS mode to Full (strict), and do not set Pseudo IPv4 to
  "Overwrite Headers".
- HTTP-01 ACME challenges get a 403 if the plugin is on that entrypoint and the
  host is protected, because Let's Encrypt's validation servers are neither
  Cloudflare nor in `directAccessCIDRs`.
- Router `ClientIP()` rules match before middlewares run, so they see the edge
  IP. `ipAllowList` middlewares placed after the plugin see the restored IP.

## Kubernetes examples

The examples use the `traefik.io/v1alpha1` CRDs and the plugin name
`cloudflare-origin` from [Install the plugin](#install-the-plugin). Replace
`AB:CD:...:EF` with your CA's fingerprint, and the hostnames and CIDRs with
your own.

### 1. Gate one service

This is the recommended setup. One IngressRoute accepts requests from
Cloudflare that carry your AOP certificate, and direct requests from your own
networks. Everything else gets a 403. Only requests from Cloudflare have their
client IP restored.

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: cloudflare-aop-ca
  namespace: app
type: Opaque
stringData:
  ca.crt: |
    -----BEGIN CERTIFICATE-----
    ...your AOP CA certificate...
    -----END CERTIFICATE-----
---
apiVersion: traefik.io/v1alpha1
kind: TLSOption
metadata:
  name: cloudflare-aop
  namespace: app
spec:
  clientAuth:
    secretNames:
      - cloudflare-aop-ca
    # Direct-access clients connect without a certificate, so the plugin,
    # not the handshake, enforces access.
    clientAuthType: VerifyClientCertIfGiven
---
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: cloudflare-origin
  namespace: app
spec:
  plugin:
    cloudflare-origin:
      clientCertFingerprints:
        - "AB:CD:...:EF" # SHA-256 of your AOP CA certificate
      protectAllHosts: true
      directAccessCIDRs:
        - 198.51.100.0/24
        - 2001:db8:100::/56
---
apiVersion: traefik.io/v1alpha1
kind: IngressRoute
metadata:
  name: app
  namespace: app
spec:
  entryPoints:
    - websecure
  routes:
    - match: Host(`app.example.com`)
      kind: Rule
      middlewares:
        - name: cloudflare-origin
      services:
        - name: app
          port: 80
  tls:
    secretName: app-example-com-tls
    options:
      name: cloudflare-aop
```

Every IngressRoute that serves `app.example.com` must use the same TLSOption.
Traefik selects the TLSOption from the hostname, and conflicting options for
one hostname fall back to the default TLSOption, which does not request client
certificates.

Direct-access clients must reach the ingress directly, not through Cloudflare.
Use split DNS so `app.example.com` resolves to the ingress inside your
networks, or add an internal hostname to the same route so it shares the
middleware:

```yaml
    - match: Host(`app.example.com`) || Host(`app.internal.example.com`)
```

To gate more hostnames, give each one's IngressRoute the same TLSOption and
Middleware references, with the Secret, TLSOption and Middleware in that
IngressRoute's namespace.

### 2. Cloudflare-proxied but open

To restore client IPs without restricting access, leave out
`protectAllHosts`. The host still needs a TLSOption that requests client
certificates, because the plugin only trusts `Cf-Connecting-Ip` on verified
requests. Create the same Secret and TLSOption as in example 1 in the `www`
namespace, then:

```yaml
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: cloudflare-origin
  namespace: www
spec:
  plugin:
    cloudflare-origin:
      clientCertFingerprints:
        - "AB:CD:...:EF"
---
apiVersion: traefik.io/v1alpha1
kind: IngressRoute
metadata:
  name: www
  namespace: www
spec:
  entryPoints:
    - websecure
  routes:
    - match: Host(`www.example.com`)
      kind: Rule
      middlewares:
        - name: cloudflare-origin
      services:
        - name: www
          port: 80
  tls:
    secretName: www-example-com-tls
    options:
      name: cloudflare-aop
```

### 3. Advanced: entrypoint-wide restoration with per-service gates

An instance attached to the entrypoint restores client IPs for every
Cloudflare-proxied host without per-route changes. Protection then comes from
either `protectedHosts` on that instance, as below, or router-level instances
as in example 1, which can be combined with it.

This has a larger blast radius. The entrypoint instance runs for every router
on the entrypoint, and if it fails to start, or the Middleware is missing,
Traefik skips every router on that entrypoint.

Create the Middleware first, in the Traefik namespace:

```yaml
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: cloudflare-origin
  namespace: traefik
spec:
  plugin:
    cloudflare-origin:
      clientCertFingerprints:
        - "AB:CD:...:EF"
      protectedHosts:
        - app.example.com
        - admin.example.com
      directAccessCIDRs:
        - 198.51.100.0/24
```

Then reference it from the chart values as `<namespace>-<name>@kubernetescrd`:

```yaml
ports:
  websecure:
    http:
      middlewares:
        - traefik-cloudflare-origin@kubernetescrd
```

Each Cloudflare-proxied hostname still needs a TLSOption that requests and
verifies client certificates against your AOP CA, as in example 1. To cover
every hostname that has no TLSOption of its own, name the TLSOption `default`.
Only one TLSOption named `default` may exist across all namespaces. Traefik
then asks every client of those hostnames for a certificate, including
visitors who connect directly. Browsers that hold client certificates may show
a certificate prompt, so prefer per-hostname TLSOptions when direct visitors
use them.

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: cloudflare-aop-ca
  namespace: traefik
type: Opaque
stringData:
  ca.crt: |
    -----BEGIN CERTIFICATE-----
    ...your AOP CA certificate...
    -----END CERTIFICATE-----
---
apiVersion: traefik.io/v1alpha1
kind: TLSOption
metadata:
  name: default
  namespace: traefik
spec:
  clientAuth:
    secretNames:
      - cloudflare-aop-ca
    clientAuthType: VerifyClientCertIfGiven
```

## Roll out

Traefik only receives Cloudflare's client certificate once the host's
TLSOption requests it, so you can introduce each piece without breaking
traffic. For example 1:

1. Install the plugin in Traefik, and confirm Traefik starts and logs no
   plugin errors.
2. Create the Secret, the TLSOption, and the Middleware without
   `protectAllHosts`. Then reference the TLSOption and Middleware from the
   IngressRoute. The host now restores client IPs for Cloudflare requests but
   blocks nothing.
3. Enable AOP for the hostname in Cloudflare and proxy its DNS record through
   Cloudflare.
4. Confirm that requests through Cloudflare reach the backend with the client
   IP, for example in the [access log](#access-logs) or the application's own
   logs, and that direct-access clients still connect.
5. Add `protectAllHosts: true` to the Middleware.

Each Middleware must exist before an IngressRoute or entrypoint references it.
Otherwise Traefik skips the routers that reference it until it appears.

## File provider

The same configuration works with the file provider. Traefik loads local
plugins from `plugins-local/src/<moduleName>` under its working directory, so
copy the three plugin files into
`plugins-local/src/github.com/krystal/traefik-plugin-cloudflare-origin`.

```yaml
# Static configuration
experimental:
  abortOnPluginFailure: true
  localPlugins:
    cloudflare-origin:
      moduleName: github.com/krystal/traefik-plugin-cloudflare-origin
```

```yaml
# Dynamic configuration
http:
  middlewares:
    cloudflare-origin:
      plugin:
        cloudflare-origin:
          clientCertFingerprints: ["AB:CD:...:EF"]
          protectAllHosts: true
          directAccessCIDRs: ["198.51.100.0/24"]
  routers:
    app:
      rule: Host(`app.example.com`)
      service: app
      middlewares: [cloudflare-origin]
      tls:
        options: cloudflare-aop
  services:
    app:
      loadBalancer:
        servers:
          - url: http://127.0.0.1:8080
tls:
  options:
    cloudflare-aop:
      clientAuth:
        caFiles: [/etc/traefik/aop-ca.crt]
        clientAuthType: VerifyClientCertIfGiven
```

## Access logs

Traefik's `ClientHost` and `ClientAddr` access log fields record the TCP peer,
which stays the Cloudflare edge IP. Keep the request headers the plugin sets to
record the client IP:

```yaml
accessLog:
  fields:
    headers:
      names:
        Cf-Connecting-Ip: keep
        X-Real-Ip: keep
```

## Hardening

Set `ports.websecure.http.underscoreHeadersStrategy: delete` (Traefik v3.7.6+,
chart 41.1.1) to drop every header with an underscore in its name before
routing. The plugin already removes underscore variants of the headers it
manages; this covers all other headers too.

## Development

Tools and tasks are managed with [mise](https://mise.jdx.dev). `mise.toml` pins
each tool to a major version, and `mise.lock` pins the exact version and
checksum for linux-x64, linux-arm64 and macos-arm64. mise skips tool releases
younger than three days.

| Task                    | What it does                                                                |
| ----------------------- | --------------------------------------------------------------------------- |
| `mise run setup`        | Install tools and the lefthook pre-commit hook                              |
| `mise run check`        | `format:check`, `lint`, `test` and `test:yaegi`; run it before pushing     |
| `mise run format`       | Format Go code                                                              |
| `mise run format:check` | Check Go formatting without changing files                                  |
| `mise run lint`         | golangci-lint (including the e2e suite), actionlint, zizmor and pinact      |
| `mise run test`         | Unit tests with the Go toolchain                                            |
| `mise run test:yaegi`   | The same unit tests under the Yaegi CLI                                     |
| `mise run e2e`          | End-to-end tests against the locked Traefik binary, standard and fast proxy |
| `mise run pin:actions`  | Pin GitHub Actions to full commit SHAs                                      |

CI runs `lint`, `format:check`, `test`, `test:yaegi` and `e2e` as separate
jobs.

The pre-commit hook (`lefthook.yml`) checks staged files offline: Go
formatting, golangci-lint when Go or lint config changes, and actionlint,
pinact and zizmor when workflow or `.github` YAML changes. It reads the working
tree, so CI stays authoritative. pinact's release-age check needs the GitHub
API and runs only in CI.

The plugin must stay compatible with the Yaegi version Traefik embeds (v0.16.1
in Traefik v3.7) and its Go 1.22 standard library: no generics, no `slices`,
`maps` or `cmp` packages, no range over integers or functions, no `min`, `max`
or `clear` builtins, and no goroutines. `test:yaegi` is only meaningful while
the Yaegi CLI matches Traefik's interpreter, so the e2e suite fails if the
locked Yaegi CLI differs from the Yaegi version built into the locked Traefik.

### Dependency updates

Dependabot updates GitHub Actions weekly with a three-day cooldown, and
`lint:pinact` rejects action pins younger than three days. To update tools,
run `mise upgrade` (which respects the cooldown), then
`mise lock --platform linux-x64,linux-arm64,macos-arm64`. When Traefik moves
to a new Yaegi version, update `aqua:traefik/yaegi` in the same change.

For an urgent security fix inside the cooldown window, override it for that
one change, for example `MISE_MINIMUM_RELEASE_AGE=0 mise upgrade <tool>`, and
say so in the pull request.

### Releases

[release-please](https://github.com/googleapis/release-please) maintains a
release pull request from the [Conventional Commits](https://www.conventionalcommits.org)
on `main`, configured in `.github/release-please-config.json`. Merging it tags
the release (`vX.Y.Z`), creates the GitHub release and updates `CHANGELOG.md`.
The first release is `v0.1.0`. Before 1.0.0, breaking changes bump the minor
version, and `feat` and `fix` commits bump the patch version.

The release-please job runs last in CI, only after every other job passes on a
push to `main` or a `release-X.Y.x` maintenance branch. It runs in the
`release` environment and authenticates as a GitHub App, so its release pull
requests trigger CI. The environment must have:

- a deployment branch policy that allows only `main` and `release-*.x`;
- the App's client ID in the `RELEASE_PLEASE_GITHUB_CLIENT_ID` variable; and
- the App's private key in the `RELEASE_PLEASE_GITHUB_APP_PRIVATE_KEY` secret.

## License

[MIT](LICENSE)
