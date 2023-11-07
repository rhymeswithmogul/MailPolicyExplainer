# MailPolicyExplainer Change Log

## Version 1.3.0 (coming soon)
- **NEW** SPF records are now tracked so that they count the number of DNS lookups performed.
- **NEW** SPF "include:" tokens are now parsed recursively, unless the new `-NoRecursion` parameter is specified.
- **FIX** Fixed grammar in some `Test-SpfRecord` messages.

## Version 1.2.0 (Thursday, October 19, 2023)
~~The SPF tester now follows the `redirect=` modifier.  Previously, it would only display the value of the modifier (and not do it correctly, either, only showing a null value).~~ (This behavior was changed by version 1.3.0.)

## Version 1.1.0 (Thursday, October 19, 2023)
- **NEW**: MX records and MTA-STS policy servers are now tested to make sure they can be reached over both IPv4 and IPv6.
- **FIX**: DKIM keys without a version defined were reported as invalid.  Per the RFC, `v=DKIM1` is supposed to be the default if a key type is not declared.  Now, keys missing a `v=` tag will be reported as valid.
- **FIX**: DKIM keys without a key type defined were reported as invalid.  Per the RFC, `k=rsa` is supposed to be the default if a key type is not declared.  Now, keys missing a `k=` tag will be reported as valid.
- **NEW**: DKIM RSA keys larger than 4096 bits will now be reported as bad practice. While they were not required to be verifiable in RFC 6376, they are required to be supported as of RFC 8301.
- **FIX**: The PowerShell Gallery `IconUri` has been corrected.

## Version 1.0.0 (Saturday, October 14, 2023)
First public release.
