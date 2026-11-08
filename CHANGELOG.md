# Changelog

## v0.1.0 (2026-11-08)

First public release.

- SPF builder with terms in evaluation order (edit, move, remove), several values added at once with ip4, ip6 or include detected for each, and presets for Microsoft 365, Google Workspace, Barracuda Email Gateway Defense (US), Mailgun and SendGrid.
- SPF checks: syntax of every mechanism and modifier, qualifiers, terms after `all`, `+all` and `?all`, the 10 DNS lookup limit, ranges with host bits, ranges a broader one already covers, record size, and two strings joined without a space.
- DKIM: reads a TXT record, a zone-file or opendkim line (and takes the selector from it), a PEM public key or a bare base64 key. Reports the key type and length against RFC 8301, converts PKCS#1 RSA keys and SPKI-wrapped Ed25519 keys to the published form, and refuses private keys (they are never saved).
- DMARC builder and checker with a plain-English explanation of the policy, following RFC 7489 and noting where RFC 9989 (May 2026) differs: `t=`, `psd=` and `np=` are recognized, and `pct=`, `rf=` and `ri=` are marked as removed.
- Inspect DNS: looks up what is published through Cloudflare or Google DNS-over-HTTPS, follows the whole SPF include tree to count lookups and void lookups, checks that outside DMARC report addresses have authorized your reports, and checks DKIM selectors, including ones published as a CNAME.
- DNS output as one TXT record (split into 255-byte strings where needed) for a zone file, Cloudflare, the Route 53 console and CLI, or any web panel, with Copy and Check published.
- Proposed repairs, each change labeled (format, no effect, merge, fix, by hand). Nothing changes until it is applied, and a broken record never loads into the builder silently.
- Light, dark and system themes; keyboard tab navigation; works at phone width; your work is saved in this browser only.
