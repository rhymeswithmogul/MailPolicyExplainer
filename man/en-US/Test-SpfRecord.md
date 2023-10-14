---
external help file: MailPolicyExplainer-help.xml
Module Name: MailPolicyExplainer
online version: online version: https://github.com/rhymeswithmogul/MailPolicyExplainer/blob/main/man/en-US/Test-SpfRecord.md
schema: 2.0.0
---

# Test-SpfRecord

## SYNOPSIS
Tests and explains a domain's SPF record.

## SYNTAX

```
Test-SpfRecord [-DomainName] <String> [<CommonParameters>]
```

## DESCRIPTION
This cmdlet tests and evaluates a domain's SPF record.

Sender Policy Framework (RFC 7208) is a DNS TXT record at the root of a DNS zone that lets a domain define its legitimate sources of email.  It can contain IP addresses, domain names, or even other SPF records.

SPF provides a complementary authentication to DKIM, and is a requirement for implementing DMARC.

In the past, SPF records had their own DNS resource record type, also called "SPF".  SPF records of type SPF are now historic, and the DNS TXT record should be used.

In addition, Microsoft briefly tried to create Sender ID, a very similar DNS record that started with "spf2.0".  That is also historic and no longer in use.

## EXAMPLES

### Example 1
```powershell
PS C:\> {{ Add example code here }}
```

Tests the SPF record for contoso.com.  This resolves the DNS TXT reocrd "contoso.com."

## PARAMETERS

### -DomainName
The domain name to test.  Be sure to include any applicable subdomains (i.e., "contoso.com" and "newsletters.contoso.com" are two different domains).

```yaml
Type: String
Parameter Sets: (All)
Aliases: Name

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
SPF record evaluation must not result in more than ten DNS lookups.  Otherwise, the SPF result is "PermError".  This cmdlet does not count how many DNS lookups are done.

## RELATED LINKS

[Test-DkimSelector]()
[Test-DmarcRecord]()
[about_SPF]()
[about_IDNEmailAuthentication]()