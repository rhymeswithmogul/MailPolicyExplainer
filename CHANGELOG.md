# MailPolicyExplainer Change Log

## Since the last release:
- **NEW**: MX records and MTA-STS policy servers are now tested to make sure they can be reached over both IPv4 and IPv6.
- **FIX**: DKIM keys without a version defined were reported as invalid.  Per the RFC, "v=DKIM1" is supposed to be the default if a key type is not declared.  Now, keys missing a "v=" tag will be reported as valid.
- **FIX**: DKIM keys without a key type defined were reported as invalid.  Per the RFC, "k=rsa" is supposed to be the default if a key type is not declared.  Now, keys missing a "k=" tag will be reported as valid.

## Version 1.0.0 (Saturday, October 14, 2023)
First public release.
