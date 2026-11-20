# Changelog

## v0.2.0 (breaking)

- Removed: every password path. A `user` block takes no `password_file`; an
  AS-REQ for a person is answered `KDC_ERR_NULL_KEY` by design, and a person
  gets a TGT only through the mint listener. Directories (`users "sql"`,
  `users "ldap"`, `user`) say who exists and their groups, nothing else: the
  KDC is handed name-only identities, so nothing a source carries can derive a
  key.
- Refused at load, naming the removal and the version: `password_file`,
  `bind_password_file`, `bind_dn` (a simple bind is a password), a `users` or
  `groups` query or attribute naming a password or NT-hash column, and a DSN
  that carries a password.
- Migration: delete those lines; give services and krbtgt random keytab keys.
  An `ldap` source is read anonymously until go-authn/directory's `hcldir`
  offers a client-certificate or SASL EXTERNAL bind.

## v0.1.0

- Added: `kdcd`, a KDC daemon for one realm on go-authn/kdc v0.8.0: UDP and TCP
  listeners (default `127.0.0.1:88`), an HCL configuration, keys from a keytab
  file, the directory from `user` and go-authn/directory `users "sql"|"ldap"`
  blocks, and an optional mint listener (mutual TLS 1.3, callers by URI
  subjectAltName).
- Added: `kdcd check --config`, which builds everything but the sockets and
  prints what the configuration serves.
- Added: refusal to start on a secret file that group or others can access or
  that another uid owns, a configuration file others can write, a wildcard or
  named listen address, a keytab missing the realm's krbtgt or a listed
  service, and a mint block with no callers.
- Added: `packaging/systemd/kdcd.service` and a sysusers file.
