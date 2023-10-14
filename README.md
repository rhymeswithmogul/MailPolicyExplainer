# MailPolicyExplainer
![Unofficial logo: email with an info icon](https://github.com/rhymeswithmogul/MailPolicyExplainer/blob/main/icon/icon.svg)

A PowerShell module to fetch and analyze a domain's mail-related DNS records.

# SHORT EXAMPLE
```powershell
PS C:\>  Test-MailPolicy contoso.com
```

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

## Further Help
For more help, why not start with [the conceptual help](https://github.com/rhymeswithmogul/MailPolicyExplainer/blob/main/man/en-US/about_MailPolicyExplainer.md)?