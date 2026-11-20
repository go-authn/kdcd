# Changelog

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
