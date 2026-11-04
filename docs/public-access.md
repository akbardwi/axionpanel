# Public access behind a local TLS proxy

AxionPanel is pre-alpha. Use for limited testing, not production. The safer
alternative is the SSH-tunnel configuration in [deployment.md](deployment.md).
This guide describes an optional, manually configured deployment, not an installer.

## Panel configuration

Keep the non-root panel on loopback and the privileged agent on its Unix socket.
Use the systemd preparation and ownership rules from deployment.md, replacing
only the panel's origin/development flags:

```text
-addr 127.0.0.1:7800
-origin https://panel.example.com
-trusted-proxy 127.0.0.1/32,::1/128
```

Do not pass `-insecure-loopback`: an HTTPS origin keeps session cookies Secure.
Setting an origin does not enable TLS in the Go listener. Nginx terminates TLS.
Never publish port 7800 or the agent socket. Keep database, encryption key and
bootstrap-password output outside the repository with owner-only permissions.

## Client-IP trust boundary

Without `-trusted-proxy`, forwarding headers are ignored. The flag accepts
comma-separated CIDRs of immediate proxies. Trust only peers you control; a
trusted peer can assert any client address. On a multi-user host, loopback trust
also trusts local processes that can reach the panel.

The panel prefers a single valid `CF-Connecting-IP`, otherwise resolves
`X-Forwarded-For` from right to left past configured trusted hops. Duplicate XFF
headers or malformed hops encountered before the first untrusted address fall
back to the direct peer. This identity is used consistently for login/MFA
throttles and stored sessions. Nginx must
**overwrite**, not append or pass through, both headers:

```nginx
location / {
    proxy_pass http://127.0.0.1:7800;
    proxy_set_header Host $host;
    proxy_set_header CF-Connecting-IP $remote_addr;
    proxy_set_header X-Forwarded-For $remote_addr;
    proxy_set_header X-Forwarded-Proto https;
    proxy_connect_timeout 5s;
    proxy_read_timeout 30s;
}
```

When using Cloudflare, configure nginx `set_real_ip_from` using the official
[IPv4](https://www.cloudflare.com/ips-v4) and
[IPv6](https://www.cloudflare.com/ips-v6) lists, with
`real_ip_header CF-Connecting-IP`. Scope these directives inside this domain's
`server` blocks so unrelated sites are unaffected. Refresh the lists as needed.
Do not trust the incoming CF header from arbitrary internet peers. Use Cloudflare
Full (strict) TLS mode with a valid origin certificate. The application cannot
inspect or enforce the CDN account's TLS setting.

## TLS and verification

Use a certificate valid for the exact domain and TLS 1.2/1.3 at nginx. A manual
vhost example is in [deploy/nginx/axionpanel.conf.example](../deploy/nginx/axionpanel.conf.example).
Test nginx configuration before reloading; do not overwrite other vhosts. For HTTP-01, serve
`/.well-known/acme-challenge/` from a separate webroot over HTTP and HTTPS. A CDN
redirect can require the challenge to remain reachable at HTTPS. Configure
certificate renewal plus a deploy hook that tests/reloads the actual nginx
binary. A timer being enabled is not proof renewal succeeds: run a staging
renewal dry run and inspect failures.

Before sharing access, verify through the public domain:

- UI and assets return 200; unauthenticated protected APIs return 401.
- Real login succeeds; session cookie has Secure and HttpOnly.
- Incorrect Origin on an authentication POST returns 403.
- Authenticated host information and statistics come from the real agent.
- Session IP matches the client, not 127.0.0.1 or a CDN edge.
- The Go listener is loopback-only; agent remains Unix-only.

The rest of the UI still includes explicitly labelled sample screens. Public
access does not implement site/database/firewall management.
