# Security policy

`kdcd` issues Kerberos tickets and, with a `mint` block, a ticket for any person
in its directory to an allowlisted caller. A flaw here can forge identities.

## Reporting a vulnerability

Do not put an exploit, a key or a ticket in a public issue or pull request.
Open an issue that says only that you have a security report, naming no detail,
and a maintainer will arrange a private channel; or write to the maintainer
whose address is on their GitHub profile. GitHub's private vulnerability
reporting is not enabled on this repository yet.

We aim to acknowledge a report within three working days and to fix a confirmed
flaw in a patch release, crediting the reporter if they wish.

## Supported versions

The latest release. Below v1, a breaking change is a MINOR release, and security
fixes land on the latest MINOR only.

## What is in scope

The program in `cmd/kdcd`: its configuration and secret-file rules, its
listeners (UDP and TCP KDC, the mutual-TLS mint listener) and its shutdown.
Protocol flaws in the library are reported to
[go-authn/kdc](https://github.com/go-authn/kdc), whose threat model covers the
KDC's own surface; this repository's is in the README ("The mint trust model").
