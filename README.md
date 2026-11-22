# kdcd

A Kerberos KDC daemon for one realm, built on the library
[go-authn/kdc](https://github.com/go-authn/kdc). It answers AS and TGS requests
over UDP and TCP and, optionally, **mints a TGT** for a person who proved
themselves elsewhere (a passkey login at
[go-authn/bridge](https://github.com/go-authn/bridge)), over mutual TLS. The
library holds the protocol; this program holds the sockets, the configuration,
and the rules for the secrets.

```
kdcd check --config /etc/kdcd/kdcd.hcl
kdcd       --config /etc/kdcd/kdcd.hcl
```

Install (the binary is `kdcd`: MIT's KDC is `krb5kdc`, Heimdal's is `kdc`):

```
go install github.com/go-authn/kdcd/cmd/kdcd@latest
```

Pure Go, `CGO_ENABLED=0`; releases carry a `SHA256SUMS` manifest and a build
provenance attestation per binary. As a service: `packaging/systemd/` (unit and
sysusers file; see "Running it").

## No passwords

**There is no password path in `kdcd`, and none can be turned on** (removed in
v0.2.0; v0.1.0 had `password_file`). A person has no long-term key here, so an
**AS-REQ** for a person is answered `KDC_ERR_NULL_KEY` by design, whatever the
client sends. A person gets a TGT only through the **mint listener**, from a
caller that authenticated them with a passkey (go-authn/bridge).

- A directory says **who exists, and their groups**. Nothing a source carries
  reaches the KDC but the name: every identity is rebuilt name-only before the
  library sees it (`nameOnly`), so even a password a source did publish derives
  no key. The load-time refusals below are there to say why, not to be the only
  guard.
- Services and `krbtgt/REALM` keep their keys in the keytab: **random keys**,
  never derived from a password (generate them, for example, with 32 bytes from
  `/dev/urandom` through your keytab tool).
- `password_file`, a `users` query or attribute naming a password or NT-hash
  column, a `bind_password_file`, a `bind_dn` (a simple bind is a password), or a
  DSN holding a password: refused at load, naming the removal and the version.
- An `ldap` source is read **anonymously**. A service bind by client certificate
  or SASL EXTERNAL is not available yet because `go-authn/directory`'s
  `hcldir.Block` has no field for it; until it has, `bind_dn` is refused.

## Configuration

One HCL file. Nothing in it is a secret; every secret is a file or a
secretsource reference.

```hcl
realm       = "POC.TEST"                 # a DNS name in capitals
keytab_file = "/etc/kdcd/kdc.keytab"     # krbtgt/POC.TEST + the services below
services    = ["cifs/fs.poc.test"]       # optional: refuse to start without these keys
lifetime    = "10h"                      # optional, 1m to 24h (default 10h)
max_skew    = "5m"                       # optional, 1s to 15m (default 5m)

listen {
  address = "127.0.0.1:88"               # IP:port, UDP and TCP; the default
  # allow_wildcard = true                # needed for 0.0.0.0 or [::]
}

mint {                                    # optional: absent, there is no second listener
  address        = "127.0.0.1:8443"      # an interface, never the wildcard
  cert_file      = "/etc/kdcd/mint.pem"  # this listener's certificate
  key_file       = "/etc/kdcd/mint.key"
  client_ca_file = "/etc/kdcd/callers-ca.pem"
  callers        = ["https://login.poc.test"]   # URI subjectAltNames, matched exactly
}

kkdcp {                                   # optional: Kerberos over HTTPS (MS-KKDCP), behind a TLS proxy
  listen = "127.0.0.1:8088"              # PLAIN HTTP on an interface, never the wildcard
  # path = "/KdcProxy"                   # the default; the only path served
}

# The directory: who exists. Any number of these, in any mix.
user "alice@poc.test" {}                  # a name; a TGT only through mint

users "sql" {                             # go-authn/directory hcldir blocks
  driver   = "postgres"                   # sqlite, postgres or mysql
  dsn_file = "/etc/kdcd/dsn"              # no password in it: a client certificate or a socket
  users    = "select login as name from staff"
}
users "ldap" {                            # read anonymously
  url      = "ldaps://ldap.example.org"
  base_dn  = "ou=people,dc=example,dc=org"
}
```

The `users` blocks are [go-authn/directory/hcldir](https://github.com/go-authn/directory)'s;
kdcd refuses the parts of them that carry a password (see above).

### Where the keytab and the mint key come from

kdcd has exactly two secrets: the keytab (it holds the `krbtgt` key, which signs
every ticket) and the mint listener's TLS key. It takes **no password, no DSN
password and no token**: a DSN or a password is refused (see below), so there is
nothing of that kind to move out of the configuration.

Each of the two is named one of two ways, and naming both is an error:

| Configuration | Reads |
| --- | --- |
| `keytab_file = "/etc/kdcd/kdc.keytab"`, `key_file = "..."` (in `mint`) | a file, opened once, checked on the open file (regular, mode 0600, owner root or the daemon's), read byte for byte, up to 1 MiB |
| `keytab_from = "systemd-creds:kdc-keytab"`, `key_from = "systemd-creds:mint-key"` | a [go-authn/secretsource](https://github.com/go-authn/secretsource) reference (v0.8.0): the exact bytes of a systemd credential, 4096 bytes at most |

`keytab_file` and `key_file` stay, and are **not** deprecated: key material is
binary, and secretsource's `file:` strips one trailing newline, which would
change a keytab whose last byte is 0x0a. So `file:` is refused in `*_from`
(write the path as `*_file`), and a reference with no scheme is refused too.
A keytab larger than 4096 bytes does not fit a credential: keep it in
`keytab_file`.

With a systemd unit, seal the keytab to the machine and let systemd place it
(`kdcd check` prints the reference, never the bytes):

```
systemd-creds encrypt --with-key=host+tpm2 --name=kdc-keytab kdc.keytab /etc/credstore.encrypted/kdc-keytab.cred
```

```ini
[Service]
LoadCredentialEncrypted=kdc-keytab:/etc/credstore.encrypted/kdc-keytab.cred
LoadCredentialEncrypted=mint-key:/etc/credstore.encrypted/mint-key.cred
```

```hcl
keytab_from = "systemd-creds:kdc-keytab"
mint { key_from = "systemd-creds:mint-key" ... }
```

`--with-key=host+tpm2` with no `--tpm2-pcrs` survives a firmware or Secure Boot
update; never seal with a bare `--tpm2-pcrs=7`. **Recovery**: the credential is
lost with the TPM2 chip or `/var/lib/systemd/credential.secret`. Keep the
keytab (and the mint key) in an offline copy; when the service fails with
"may need re-sealing" (after a firmware, PCR or host-key change), run
`systemd-creds encrypt` again from that copy and `systemctl restart kdcd`.

`kdcd check --config FILE` reads and builds everything the daemon would, opens
the directory, listens on nothing, and prints what it serves: the realm,
addresses, the keytab's principals (name, kvno, etype; never a key), how many
people the directory holds, the mint callers. Exit status 0 and a last line
`ok`, or the first refusal.

### What it refuses to start with

| Refused | Why |
| --- | --- |
| a keytab, mint key or DSN file that **group or others can read or write**, or that belongs to a uid other than root or the daemon's | a copy another account can read forges tickets for every person of the realm |
| **any password path**: `password_file` (even empty), `bind_password_file`, `bind_dn`, a `users`/`groups` query or attribute naming `password`, `passwd`, `nt_hash`, `userPassword`..., a DSN carrying a password | removed in v0.2.0: no person has a key here; the message says so. The query and DSN checks are best effort; `nameOnly` holds whatever they miss |
| a secret written inline (`password = "..."` is not an argument) | secrets live in files, never in the configuration, a backup of it, or a log |
| a configuration file that group or others can write | whoever writes it chooses the mint callers |
| a keytab with no `krbtgt/REALM` key, or lacking a listed service, **in aes256-cts-hmac-sha1-96** (the one type the library issues) | it would start and fail at the first `kinit` |
| a wildcard or a host name in `listen` (an IP literal is required), and **any** wildcard for `mint` | the KDC and the mint listener are on the interfaces somebody chose |
| a `mint` block with no callers, no certificate, or an expired one | the library reads no callers as "minting off"; this says so instead of silently minting nothing |
| `ldap://` to another machine without `start_tls` | every password would cross the network as typed |

Secret files are opened **once** and the open file is checked (regular file,
mode, owner), so a check cannot be about one file and the read about another
(the model is go-fileshare's `readKeytab`). `dsn_file` is read by `hcldir` by
name, after being checked the same way.

## Kerberos over HTTPS: the kkdcp block

With `kkdcp { listen = "127.0.0.1:8088" }` kdcd also serves
[MS-KKDCP](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kkdcp/5bcebb8d-b747-4ee5-9453-428aec1c5c38)
(go-authn/kdc's `KKDCPHandler`) on that address, plain HTTP, at `/KdcProxy`
(or `path`). Put a TLS-terminating reverse proxy in front: Windows requires
HTTPS, and a certificate is renewed there, not here. With Caddy:

```
kdc.example.org {
	handle /KdcProxy {
		reverse_proxy 127.0.0.1:8088
	}
}
```

Clients then reach the realm through port 443 and **port 88 need not be open to
the internet**: MIT krb5 with `kdc = https://kdc.example.org/KdcProxy` in its
realm, Windows with the `KdcProxy` policy (`authn-kinit setup --kdc-proxy`).
The proxy answers what port 88 answers, so a person with no key is still
`KDC_ERR_NULL_KEY` through it; it refuses non-POST (405), junk (400), another
realm (403). `kdcd check` prints the block (`kkdcp  off` without it).

## The mint trust model

`POST https://<mint address>/mint` with `{"principal": "alice", "lifetime_seconds": 36000}`
returns a KRB-CRED (RFC 4120 5.8) holding a TGT for `alice`, for the caller to
hand to the person's machine ([go-authn/kinit](https://github.com/go-authn/kinit)
loads it into a Windows logon session). What bounds it:

- **The caller is the TLS client certificate**, verified against `client_ca_file`
  by the listener (TLS 1.3, `RequireAndVerifyClientCert`): a connection with no
  certificate, or one the CA did not sign, fails the handshake before any HTTP
  is read. A verified certificate is then matched, by a **URI subjectAltName**,
  against `callers`, exactly; a certificate that verifies but is not listed is
  `403`. Nothing in a header or a body names the caller.
- **Whoever is on `callers` can obtain a TGT for any principal in the directory**
  (never a service, never a name the directory lacks), without that person's key.
  The caller's own authentication of the person is what the realm trusts, so a
  caller is as trusted as the KDC's keytab is. List one per identity provider,
  give each its own certificate, and keep `client_ca_file` a CA that signs
  nothing else.
- The ticket is `INITIAL | PRE-AUTHENT`, never renewable, forwardable or
  proxiable; its lifetime is the least of the request, `lifetime` and ten hours.
- The session key is made from `crypto/rand`, leaves the process once, in the
  reply, and is never logged. The reply is `Cache-Control: no-store`. The
  KRB-CRED carries the key in the clear, so **the TLS channel is the
  encryption**: put the listener on an internal interface.
- Only `/mint` is served, with timeouts and a header limit. Every mint, and
  every refusal, is logged with the caller's URI and the principal asked for.

The full threat model is that of the library's pull request,
[go-authn/kdc#38](https://github.com/go-authn/kdc/pull/38), with the
[minting section](https://github.com/go-authn/kdc#a-tgt-for-a-person-with-no-key-minting)
and the [audit notes](https://github.com/go-authn/kdc#what-an-unauthenticated-peer-can-and-cannot-do-v045-audit)
of the library's README; none of it is repeated or weakened here.
[go-authn/bridge](https://github.com/go-authn/bridge)'s `kerberos` block is the
caller's side: its `kdc_url` is `https://<mint address>/mint`, its `ca_file`
signs `cert_file` above, and its client certificate's URI name is a `callers`
entry.

## Running it

`packaging/systemd/kdcd.service` runs it as the system user of
`packaging/sysusers.d/kdcd.conf`, with the hardening of
[authn-bridge](https://github.com/go-authn/bridge)'s unit. Port 88 is
privileged, so the unit grants exactly `CAP_NET_BIND_SERVICE` and nothing else.

```
install -d -m 0750 -o root -g kdcd /etc/kdcd
install -m 0640 -o root -g kdcd kdcd.hcl /etc/kdcd/       # no secret in it
install -m 0600 -o kdcd -g kdcd kdc.keytab mint.key /etc/kdcd/
systemctl enable --now kdcd
```

Secrets belong to `kdcd` (or to root) at mode 0600; 0640 with group `kdcd` is
refused on purpose. A change to the configuration is `systemctl restart kdcd`
(the daemon does not reload; a client retries a refused connection).

On Windows the mode bits mean nothing and are not checked: put the files where
only the account that runs the service can read them.

## Not here

Cross-realm, PKINIT, FAST, renewable or postdated tickets, a kadmin protocol,
and any encryption type but aes256-cts-hmac-sha1-96 are the library's own
limits ([go-authn/kdc](https://github.com/go-authn/kdc#readme)). `kdcd` has no
reload and no metrics endpoint yet.
