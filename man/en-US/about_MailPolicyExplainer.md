# MailPolicyExplainer
## about_MailPolicyExplainer

![Unofficial logo: email with an info icon](https://github.com/rhymeswithmogul/MailPolicyExplainer/blob/main/icon/icon.svg)

# SHORT DESCRIPTION
A PowerShell module to fetch and analyze a domain's mail-related DNS records.

# LONG DESCRIPTION
MailPolicyExplainer is just that: a PowerShell module that will retrieve all of a domain's email-related DNS records, and show them to the user. However, unlike a simple call to `Resolve-DnsName`, this module will actually analyze them and show you what they mean, rather than just what they are.

This module supports MX, SPF, DKIM ADSP, DMARC, DANE, MTA-STS, and SMTP TLS Reporting; as well as evaluating whether or not records are signed with DNSSEC. In addition, if you provide names of selectors, DKIM and BIMI selector records are also evaluated.

# EXAMPLES
Most people using this module will want to use the `Test-MailPolicy` cmdlet, which runs every single test in order.  Though it may not be obvious which DKIM and BIMI selector names exist (save for email services like Exchange Online who use well-known DKIM selector names -- selector1 and selector2), the `-DkimSelectorsToCheck` and `-BimiSelectorsToCheck` can be used to test known selectors.

In its simplest form, `Test-MailPolicy` will review almost every DNS record available.
```powershell
PS C:\>  Test-MailPolicy contoso.com
```

Exchange Online always uses DKIM selectors "selector1" and "selector2".  If a domain doesn't use any other email sending platforms (such as Constant Contact), you can test any Office 365 customer with this command:
```powershell
PS C:\>  Test-MailPolicy fabrikam.com -DkimSelectorsToCheck "selector1","selector2"
```

But what if they *do* use something like Constant Contact?  Assuming the DKIM selector name is known:
```powershell
PS C:\>  Test-MailPolicy woodgrovebank.com -DkimSelectorsToCheck "selector1","selector2","constantcontact"
```

Note that sometimes emails can come from subdomains, and those subdomains will have their own DNS records.  You will need to run this cmdlet once per domain.
```powershell
PS C:\>  Test-MailPolicy tailspintoys.com -DkimSelectorsToCheck "selector1","selector2"
PS C:\>  Test-MailPolicy shop.tailspintoys.com -DkimSelectorsToCheck "shopify"
```

Or, if you only want to test one aspect of email, you can test items individually.  For example, if yu're working on MTA-STS, you can skip all the other checks.
```powershell
PS C:\>  Test-MtaStsPolicy adatum.com
```

SPF records can also be tested recursively, to see how many DNS lookups are required to evaluate them.  If more than ten additional DNS lookups are required, parsers may choose to terminate processing and return a PermError.  There are two ways to do this:

```powershell
PS C:\>  Test-MailPolicy lucernepublishing.com -CountSpfDnsLookups
PS C:\>  Test-SpfRecord  lucernepublishing.com -CountDnsLookups
```

PROTIP: You can use the alias `-Recurse` instead.

# NOTE
No command output is sent to the pipeline.  All output is sent to the output stream, where it can be read by humans.  However, the output stream can be redirected to a text file.

# TROUBLESHOOTING NOTE
## Help
All cmdlets provide detailed help, available using the PowerShell `Get-Help` command.  In addition, several relevant RFCs are available as conceptual help topics in case you'd like to learn more about the standards that are being tested.

## Limitations
While this module does its best to test the correctness of DNS records, it cannot ensure the complete validity of everything.  For example:
 - This module can test MX records, but not whether or not A/AAAA records are in place for those names.
 - This module can test SPF records, but it does not know if you're missing an `include:` for some third-party service.
 - This module can test DKIM selectors, but it cannot test whether outgoing messages are being signed.
 - This module can test DANE records, but not whether or not the records are correct for an MX lookup.
 - This module can test BIMI records, but not whether the linked SVG image is valid, whether or not the client trusts the assertion, nor if outgoing emails have the appropriate BIMI headers.
 - This module cannot test internal DNS zones (i.e., ones that are not resolvable over the public Internet).
 - This module can look up DMARC or TLSRPT reporting addresses, but cannot check to see if reports can be successfully submitted.

Some of these limitations (such as testing DANE records) may be addressed in future versions of the module.

## Privacy
As the built-in `Resolve-DnsName` cmdlet doesn't do everything that we need it to do (and because it's conspicuously absent on non-Windows versions of PowerShell), these cmdlets need to rely on an outside DNS resolving service.  After testing some options, the only reliable cross-platform option was to use [Google's Public DNS API](https://developers.google.com/speed/public-dns/docs/doh/json).  MailPolicyExplainer uses the PowerShell runtime to make queries in a similar fashion to DNS-over-HTTPS (DoH).  DNSSEC is always attempted, but left for the resolver to verify.

Some people may have privacy concerns about sending random DNS queries to Google.  Until Microsoft ports their DnsClient module to other platforms, and ensures that it can look up any type of DNS record, we are stuck using a third-party resource.  However, future versions of this module may introduce support for using other public DNS APIs, or switching to proper DNS-over-HTTPS so that user-provided servers can be used.

To troubleshoot DNS lookups, a cmdlet `Invoke-GooglePublicDnsApi` is made available.  However, it is not intended for public use, and is subject to change or removal at any time.

While the domain owner has no way to know which DNS lookups you and this module are doing, note that the MTA-STS does connect to the company's web server in order to retrieve the MTA-STS policy file.  A single HTTP GET request will be made from your current IP address to the well-known location https://mta-sts.contoso.com/.well-known/mta-sts.txt (assuming you're testing against contoso.com).

## Bug Reporting and Feature Requests
As this module relies on parsing DNS records that are supposed to follow a strict set of rules, it is unlikely that you will run into any issues.  Should you encounter problems, though, you are encouraged to file issues on GitHub.

# SEE ALSO
- [Test-MailPolicy](https://github.com/rhymeswithmogul/MailPolicyExplainer/blob/main/man/en-US/Test-MailPolicy.md)
- [Test-MXRecord](https://github.com/rhymeswithmogul/MailPolicyExplainer/blob/main/man/en-US/Test-MXRecord.md)
- [about_SMTP](https://github.com/rhymeswithmogul/MailPolicyExplainer/blob/main/man/en-US/about_SMTP.md)
- [about_MXRecords](https://github.com/rhymeswithmogul/MailPolicyExplainer/blob/main/man/en-US/about_MXRecords.md)
- [about_NullMXRecords](https://github.com/rhymeswithmogul/MailPolicyExplainer/blob/main/man/en-US/about_NullMXRecords.md)
- [about_IDNEmailAuthentication](https://github.com/rhymeswithmogul/MailPolicyExplainer/blob/main/man/en-US/about_IDNEmailAuthentication.md)

- [Test-BimiSelector](https://github.com/rhymeswithmogul/MailPolicyExplainer/blob/main/man/en-US/Test-BimiSelector.md)
- [about_BIMI](https://github.com/rhymeswithmogul/MailPolicyExplainer/blob/main/man/en-US/about_BIMI.md)

- [Test-DaneRecord](https://github.com/rhymeswithmogul/MailPolicyExplainer/blob/main/man/en-US/Test-DaneRecord.md)
- [about_DANERecords](https://github.com/rhymeswithmogul/MailPolicyExplainer/blob/main/man/en-US/about_DANERecords.md)
- [about_DANERecordsAcronyms](https://github.com/rhymeswithmogul/MailPolicyExplainer/blob/main/man/en-US/about_DANERecordsAcronyms.md)
- [about_DANERecordsUsage](https://github.com/rhymeswithmogul/MailPolicyExplainer/blob/main/man/en-US/about_DANERecordsUsage.md)

- [Test-DkimSelector](https://github.com/rhymeswithmogul/MailPolicyExplainer/blob/main/man/en-US/Test-DkimSelector.md)
- [Test-AdspRecord](https://github.com/rhymeswithmogul/MailPolicyExplainer/blob/main/man/en-US/Test-AdspRecord.md)
- [about_DKIM](https://github.com/rhymeswithmogul/MailPolicyExplainer/blob/main/man/en-US/about_DKIM.md)
- [about_DKIMADSP](https://github.com/rhymeswithmogul/MailPolicyExplainer/blob/main/man/en-US/about_DKIMADSP.md)
- [about_DKIMRSAKeyUpdates](https://github.com/rhymeswithmogul/MailPolicyExplainer/blob/main/man/en-US/about_DKIMRSAKeyUpdates.md)
- [about_DKIMEd25519](https://github.com/rhymeswithmogul/MailPolicyExplainer/blob/main/man/en-US/about_DKIMEd25519.md)

- [Test-DmarcRecord](https://github.com/rhymeswithmogul/MailPolicyExplainer/blob/main/man/en-US/Test-DmarcRecord.md)
- [about_DMARC](https://github.com/rhymeswithmogul/MailPolicyExplainer/blob/main/man/en-US/about_DMARC.md)

- [Test-MtaStsPolicy](https://github.com/rhymeswithmogul/MailPolicyExplainer/blob/main/man/en-US/Test-MtaStsPolicy.md)
- [about_MTA-STS](https://github.com/rhymeswithmogul/MailPolicyExplainer/blob/main/man/en-US/about_MTA-STS.md)

- [Test-SmtpTlsReportingPolicy](https://github.com/rhymeswithmogul/MailPolicyExplainer/blob/main/man/en-US/Test-SmtpTlsReportingPolicy.md)
- [about_SMTPTLSReporting](https://github.com/rhymeswithmogul/MailPolicyExplainer/blob/main/man/en-US/about_SMTPTLSReporting.md)

- [Test-SpfRecord](https://github.com/rhymeswithmogul/MailPolicyExplainer/blob/main/man/en-US/Test-SpfRecord.md)
- [about_SPF](https://github.com/rhymeswithmogul/MailPolicyExplainer/blob/main/man/en-US/about_SPF.md)

# KEYWORDS
SMTP, MX, SPF, DKIM, ADSP, DMARC, BIMI, DNS, DNSSEC, DANE, TLSA, TXT, IDN, MTA-STS, mail, email, Exchange Online, Google Workspace, Office 365.
