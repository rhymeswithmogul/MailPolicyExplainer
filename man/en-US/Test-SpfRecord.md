---
external help file: MailPolicyExplainer-help.xml
Module Name: MailPolicyExplainer
online version: https://github.com/rhymeswithmogul/MailPolicyExplainer/blob/main/man/en-US/Test-SpfRecord.md
schema: 2.0.0
---

# Test-SpfRecord

## SYNOPSIS
Tests and explains a domain's SPF record.

## SYNTAX

```
Test-SpfRecord [-DomainName] <String> [-CountDnsLookups] [-DisableDnssecVerification]
 [-Recursions <PSReference>] [-DnsLookups <PSReference>] [<CommonParameters>]
```

## DESCRIPTION
This cmdlet tests and evaluates a domain's SPF record.  When `-CountDnsLookups` is used, the SPF record will be evaluated recursively, counting how many additional DNS lookups are required to evaluate SPF.

Sender Policy Framework (RFC 7208) is a DNS TXT record at the root of a DNS zone that lets a domain define its legitimate sources of email.  It can contain IP addresses, domain names, or even other SPF records.

SPF provides a complementary authentication to DKIM, and is a requirement for implementing DMARC.

In the past, SPF records had their own DNS resource record type, also called "SPF".  SPF records of type SPF are now historic, and the DNS TXT record should be used.

In addition, Microsoft briefly tried to create Sender ID, a very similar DNS record that started with "spf2.0".  That is historic and no longer in use.

## EXAMPLES

### Example 1
```powershell
PS C:\>  Test-SpfRecord contoso.com
```

Tests the SPF record for contoso.com.  This resolves the DNS TXT record "contoso.com."

### Example 2
```powershell
PS C:\>  Test-SpfRecord lucernepublishing.com -CountDnsLookups
```

Tests the SPF record for lucernepublishing.com, evaluating it recursively and counting how many additional DNS lookups are performed.  This resolves the DNS TXT record "lucernepublishing.com" and any other SPF records referenced by any "redirect" modifiers or "include" tokens.

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

### -CountDnsLookups
Specify this parameter to count how many DNS lookups are required to evaluate this SPF record, to make sure it isn't over the limit of ten additional lookups, after which point, SPF evaluators may choose to stop processing and return a PermError.  This switch will cause this cmdlet to operate recursively, and evaluate any SPF records found via the "redirect" modifier and the "include" token.

PROTIP: -Recurse is an alias for this switch.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases: Recurse, CountSpfDnsLookups

Required: False
Position: Named
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

## RELATED LINKS

[Test-DkimSelector]()
[Test-DmarcRecord]()
[about_SPF]()
[about_IDNEmailAuthentication]()