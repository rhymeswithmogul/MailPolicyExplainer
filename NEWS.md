# MailPolicyExplainer News

## Version 1.2.0
This was also released on Thursday, October 19, 2023.

The SPF test now follows the `redirect=` modifier's value.  For example, if domainA.com has `v=spf1 redirect=domainB.com`, the module will analyze domainB.com's SPF record.  (Previously, the `redirect=` test was non-functional.)

## Version 1.1.0
This was released on Thursday, October 19, 2023.

### New features
MX records and MTA-STS policy servers are now checked to make sure they are reachable over both IPv4 and IPv6.  This will ensure that all Internet users, including those who only have one protocol, can still access your server.

### Bug Fixes
- DKIM records may safely omit the `v=DKIM1` and `k=rsa` tokens.  This module, however, did not recognize those as valid.  These default values are now allowed to be missing, and substituted with appropriate defaults, per the RFC.
- DKIM RSA keys larger than 4,096 bits now generate a warning, as they are not required to be supported by all validators.

## Version 1.0.0
This module was first released to the world on Saturday, October 14, 2023.
