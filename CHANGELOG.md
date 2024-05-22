# MailPolicyExplainer Change Log

## Version 1.4.1 (Wednesday, May 22, 2024)
**FIX** DMARC `pct` tokens are now properly explained.  Thanks to [Jason Berry](https://github.com/skyblaster) for finding the bug and writing [the pull request](https://github.com/rhymeswithmogul/MailPolicyExplainer/pull/3)!

## Version 1.4.0 (Thursday, April 4, 2024)
- **NEW** Most cmdlets now have a switch, `-DisableDnssecValidation`, that does just that.
- **NEW** `Test-DkimRecord` will print the full DKIM TXT record to the verbose stream.  Thanks to [Jason Berry](https://github.com/skyblaster) for writing [the pull request](https://github.com/rhymeswithmogul/MailPolicyExplainer/pull/1)!
- **FIX** DNSSEC results are shown even when records are not found, to show proof of non-existence (unless DNSSEC validation is disabled).
- **FIX** The SPF qualifier is no longer prepended to IPv4 addresses.
- **FIX** A bug caused Windows PowerShell 5.1 not to parse MTA-STS policy file line endings properly.  Thanks to [Jason Berry](https://github.com/skyblaster) for reporting this and writing [another pull request](https://github.com/rhymeswithmogul/MailPolicyExplainer/pull/2)!

## Version 1.3.4 (Wednesday, January 24, 2024)
**FIX** Some previous versions of this module failed to load on Windows PowerShell 5.1 due to a missing backtick.  PowerShell 7 considered this to be valid syntax.  Thanks to Aslan Grealis for finding this bug.

## Version 1.3.3 (Thursday, January 18, 2024)
**FIX** When no DANE records are present for a domain with a single MX host, `Test-DaneRecords` would erroneously report the domain name when it should have reported the MX server name.

## Version 1.3.2 (Friday, December 8, 2023)
**FIX** `Test-MtaStsPolicy` no longer misidentifies `mta-sts.txt` files with the correct CRLF line endings as malformed.  This was caused by a regression in version 1.3.1.

## Version 1.3.1 (Wednesday, December 6, 2023)
- **FIX** Implied MX records are now displayed correctly.
- **NEW** The IP version checks are now displayed with an indentation when run as a part of `Test-MailPolicy`.
- **FIX** The IP version checks now work with implied MX records.
- **FIX** `Test-DaneRecords` now correctly checks DANE records for domains without MX records.
- **FIX** The DMARC `fo` token is now parsed correctly when multiple values are present.
- **FIX** The DMARC `rf` token is now parsed correctly.
- **FIX** The MTA-STS policy file test returns a better error message when the file does not have the correct CRLF line endings.
- **FIX** The SMTP TLS reporting policy test now checks to make sure exactly one `v` tag is present with the value `TLSRPTv1`.
- **FIX** The SMTP TLS reporting policy test now fails gracefully when invalid text is present.
- **FIX** The SPF `exists` and `mx` token parsers no longer generate a spurious error when *not* counting DNS lookups.
- **FIX** IntelliSense's handling of `Test-SpfRecord` has been improved by hiding some internal-use-only parameters.
- **FIX** Online help is fixed for `Test-SmtpTlsReportingPolicy`, `Test-MtaStsPolicy`, and `Test-SpfRecord`.
- **FIX** Cleaned up `Test-DaneRecords`' output.
- **FIX** Miscellaneous code cleanup to improve future maintenance.

## Version 1.3.0 (Tuesday, November 7, 2023)
- **NEW** `Test-SpfRecord` can now recursively evaluate SPF records to count how many DNS lookups are performed when evaluating `redirect=` modifiers and `include:` tokens.  Use either `Test-SpfRecord -CountDnsLookups`, `Test-SpfRecord -Recurse`, or `Test-MailPolicy -CountSpfDnsLookups` to use this new mode.  Note that this overrides the new behavior introduced in version 1.2.0.
- **FIX** Fixed grammar in some `Test-SpfRecord` messages.
- **FIX** RFC documents were supposed to be made available as conceptual help, but were not.  This has been corrected.

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
