---
external help file: MailPolicyExplainer-help.xml
Module Name: MailPolicyExplainer
online version: online version: https://github.com/rhymeswithmogul/MailPolicyExplainer/blob/main/man/en-US/Test-MtaStsPolicy.md
schema: 2.0.0
---

# Test-MtaStsPolicy

## SYNOPSIS
Fetches and checks a domain's MTA-STS record and policy.

## SYNTAX

```
Test-MtaStsPolicy [-DomainName] <String> [<CommonParameters>]
```

## DESCRIPTION
This cmdlet will test a domain's MTA-STS policy record, attempt to download the MTA-STS policy file, and test that, too.

Mail Transport Agent Strict Transport Security is a method for mail server operators to advertise that their mail servers support STARTTLS in a way that is immune to downgrade or man-in-the-middle attacks.  This requires a DNS record, and a text file in a specific spot on a web server.

When MTA-STS is enabled, the policy file must be available via HTTPS on a web server that supports TLS 1.2 or newer.  When MTA-STS checks pass, the sending mail server must use STARTTLS (with TLS 1.2 or higher) and see a matching and otherwise-valid certificate offered by the email server.  If anything goes wrong, delivery must be delayed (assuming the MTA-STS policy is set to "enforce") and an SMTP TLS failure report must be sent.

MTA-STS was invented as a substitute for the much-simpler DANE, as DANE requires DNSSEC while MTA-STS does not.  However, both can coexist.

There is a companion technology, SMTP TLS Reporting.  While it is not a requirement to use MTA-STS, its use is highly encouraged so that you can receive MTA-STS and STARTTLS failure reports.

## EXAMPLES

### Example 1
```powershell
PS C:\> Test-MtaStsPolicy contoso.com
```

This will evaluate the MTA-STS policy for contoso.com.  It will look up the DNS TXT record "_mta-sts.contoso.com."  It will then try to download the file "https://mta-sts.contoso.com/.well-known/mta-sts.txt" using TLS 1.2 or higher, and parse the file.

## PARAMETERS

### -DomainName
The domain name to test.  Be sure to include any applicable subdomains (i.e., "contoso.com" and "newsletters.contoso.com" are two different domains).

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: 0
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### None
This cmdlet does not accept pipeline input.

## OUTPUTS

### System.Void
This cmdlet does not generate pipeline output.

## NOTES
MTA-STS is defined in RFC 8461.

## RELATED LINKS

[Test-SmtpTlsReportingPolicy]()
[about_MTA-STS]()
[about_SMTPTLSReporting]()
