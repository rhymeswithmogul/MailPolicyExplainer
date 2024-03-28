---
external help file: MailPolicyExplainer-help.xml
Module Name: MailPolicyExplainer
online version: https://github.com/rhymeswithmogul/MailPolicyExplainer/blob/main/man/en-US/Test-SmtpTlsReportingPolicy.md
schema: 2.0.0
---

# Test-SmtpTlsReportingPolicy

## SYNOPSIS
Tests a domain's SMTP TLS reporting policy.

## SYNTAX

```
Test-SmtpTlsReportingPolicy [-DomainName] <String> [-DisableDnssecVerification] [<CommonParameters>]
```

## DESCRIPTION
This cmdlet will test a domain's SMTP TLS reporting policy.  This is a mechanism by which server operators can receive alerts should inbound connections fail, whetner due to a failure of DANE or MTA-STS, or any other issue with STARTTLS.

SMTP TLS reporting is not a requirement to use DANE or MTA-STS, but it is highly recommended to be implemented.

## EXAMPLES

### Example 1
```powershell
PS C:\> Test-SmtpTlsreportingPolicy contoso.com
```

Tests the SMTP TLS reporting policy for contoso.com.  This resolves the DNS TXT reocrd "_smtp._tls.contoso.com."

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

### -DisableDnssecVerification
Disable DNSSEC validation.  This cmdlet will not request authenticated data from the resolver;  thus, DNSSEC validation of resource records will not occur, nor will the user be informed about unauthenticated denial of existence of DNS records.  Using this switch is NOT RECOMMENDED for production use and should only be used for diagnostic and troubleshooting purposes only!

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases: CD, DnssecCD, NoDnssec, DisableDnssec

Required: False
Position: Named
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
SMTP TLS Reporting is defined in RFC 8460.

## RELATED LINKS

[Test-MtaStsPolicy]()
[Test-DaneRecord]()
[about_SMTPTLSReporting]()