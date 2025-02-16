---
external help file: MailPolicyExplainer-help.xml
Module Name: MailPolicyExplainer
online version: https://github.com/rhymeswithmogul/MailPolicyExplainer/blob/main/man/en-US/Test-DmarcRecord.md
schema: 2.0.0
---

# Test-DmarcRecord

## SYNOPSIS
Tests a domain's DMARC record.

## SYNTAX

```
Test-DmarcRecord [-DomainName] <String> [-DisableDnssecVerification] [<CommonParameters>]
```

## DESCRIPTION
This cmdlet will test a domain's DMARC record for correctness.

DMARC (Domain-based Message Authentication, Reporting, and Conformance) is a DNS TXT record that allows domain owners to set policies and preferences for email validation and reporting.

DMARC relies on both SPF and DKIM to determine if a message is legitimate ("aligned").  The DMARC policy can also instruct other mail servers to quarantine or reject emails that fail SPF and DKIM.  It can also instruct recipients' mail servers to respond with delivery information that can be used to generate reports for mail server operators to analyze email flow and deliverability.

A strict DMARC policy is also a requirement for BIMI.

## EXAMPLES

### Example 1
```powershell
PS C:\> Test-DmarcRecord contoso.com
```

Tests the DMARC record for contoso.com.  The DNS TXT record to be resolved is "_dmarc.contoso.com."

## PARAMETERS

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
If a subdomain does not have a DMARC policy, it will inherit the DMARC policy from its parent domain.

DMARC is defined in RFC 7489.

## RELATED LINKS

[Test-SpfRecord]()
[Test-DkimSelector]()
[Test-BimiSelector]() 
[about_DMARC]()
