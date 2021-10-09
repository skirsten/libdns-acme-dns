# [`acme-dns`](https://github.com/joohoi/acme-dns) for [`libdns`](https://github.com/libdns/libdns)

[![Go Reference](https://pkg.go.dev/badge/test.svg)](https://pkg.go.dev/github.com/skirsten/libdns-acme-dns)

This package implements the [libdns interfaces](https://github.com/libdns/libdns) for [acme-dns](https://github.com/joohoi/acme-dns), allowing you to manage DNS records.

- As acme-dns is not a fully featured DNS server, this package has many limitations. This makes it only usable for performing ACME challenges.
- Currently does not take into consideration the zone. To manage multiple zones, multiple instances of the provider must be created.
