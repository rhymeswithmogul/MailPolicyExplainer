# MailPolicyExplainer News

## Version 1.3.0
This was released on Tuesdsay, November 7, 2023.

The SPF test now supports a new parameter, `-CountDnsLookups`, to test an SPF record recursively to ensure that no more than ten additional DNS lookups are required to evaluate SPF for a domain.  This can be invoked by either `Test-SpfRecord -CountDnsLookups` or `Test-MailPolicy -CountSpfDnsLookups`.  (`-Recurse` is an easy-to-remember alias for both cmdlets).

In addition, a few bugs have also been squished -- namely, one that prevented conceptual help from being made available.

## Version 1.2.0
This was also released on Thursday, October 19, 2023.

The SPF test now follows the `redirect=` modifier's value.  For example, if domainA.com has `v=spf1 redirect=domainB.com`, the module will analyze domainB.com's SPF record.  (Previously, the `redirect=` test was non-functional.)  Note that this behavior was reversed in version 1.3.0.

## Version 1.1.0
This was released on Thursday, October 19, 2023.

### New features
MX records and MTA-STS policy servers are now checked to make sure they are reachable over both IPv4 and IPv6.  This will ensure that all Internet users, including those who only have one protocol, can still access your server.

### Bug Fixes
- DKIM records may safely omit the `v=DKIM1` and `k=rsa` tokens.  This module, however, did not recognize those as valid.  These default values are now allowed to be missing, and substituted with appropriate defaults, per the RFC.
- DKIM RSA keys larger than 4,096 bits now generate a warning, as they are not required to be supported by all validators.

## Version 1.0.0
This module was first released to the world on Saturday, October 14, 2023.
