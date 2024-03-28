# MailPolicyExplainer News

## Version 1.4.0
This will be released soon.

One new feaure.  `Test-DkimRecord` will print the full DKIM TXT record to the verbose stream (i.e., the one that's visible when using `-Verbose` or setting the appropriate `$VerbosePreference` value).  Thanks to [Jason Berry](https://github.com/skyblaster) for writing [the pull request](https://github.com/rhymeswithmogul/MailPolicyExplainer/pull/1)!

One bug was fixed.  The SPF parser would sometimes show IPv4 addresses with a character prepended;  for example, "Accept mail from the IPv4 address +192.0.2.1" or "Reject mail from the IPv4 address -192.0.2.2".  This has been corrected by fixing the parser.

## Version 1.3.4
This was released on Wednesday, January 24, 2024.

This is a bugfix release.  Due to a tiny syntax error, this module was not loading on Windows PowerShell 5.1.  This has been corrected.  PowerShell 7 was not affected.  Thank you to Aslan Grealis for pointing this out.

## Version 1.3.3
This was released on Thursday, January 17, 2024.

This is a bugfix release.  When no DANE records are present for a domain with a single MX host, `Test-DaneRecords` would erroneously report the domain name when it should have reported the MX server name.  For example, "DANE records are not present for contoso.com" instead of "DANE records are not present for mail.contoso.com".  The non-existence of DANE records was reported correctly, though the error message was confusing.

## Version 1.3.2
This was released on Friday, December 8, 2023.

This is a bugfix release.  Now, `Test-MtaStsPolicy` no longer misidentifies `mta-sts.txt` files with the correct CRLF line endings as malformed.  This was caused by a regression in version 1.3.1.

## Version 1.3.1
This was released on Wednesday, December 6, 2023.

The output of `Test-IPVersions` is now indented when run from `Test-MxRecord` or `Test-MailPolicy`.  This ought to make things a little easier to read.

More importantly, almost a dozen bugs have been squashed!

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
