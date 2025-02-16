---
external help file: MailPolicyExplainer-help.xml
Module Name: MailPolicyExplainer
online version: https://github.com/rhymeswithmogul/MailPolicyExplainer/blob/main/man/en-US/Test-MailPolicy.md
schema: 2.0.0
---

# Test-MailPolicy

## SYNOPSIS
Tests all email-related DNS records for a domain.

## SYNTAX

```
Test-MailPolicy [-DomainName] <String> [-CountSpfDnsLookups] [-DkimSelectorsToCheck <String[]>]
 [-ExchangeOnlineDkim] [-BimiSelectorsToCheck <String[]>] [-DisableDnssecVerification]
 [<CommonParameters>]
```

## DESCRIPTION
This cmdlet will check all of a domain's email-related DNS records, including MX, DANE, SPF, DMARC, MTA-STS, and SMTP TLS reporting policies.  It can also check DKIM and BIMI selectors, if specified.

## EXAMPLES

### Example 1
```powershell
PS C:\> Test-MailPolicy contoso.com
```

Checks the MX records and their associated DANE records, SPF record, DMARC record, MTA-STS record and policy file, and SMTP TLS reporting policy.

### Example 2
```powershell
PS C:\> Test-MailPolicy fabrikam.com -DkimSelectorsToCheck "selector1","selector2"
```

This will do everything the previous example does, but also check the DKIM selectors named "selector1" and "selector2".  (These are the names of the two Exhcange Online selectors.)

### Example 3
```powershell
PS C:\> Test-MailPolicy tailspintoys.com -DkimSelectorsToCheck "marketing" -BimiSelectorsToCheck "default"
```

This will do everything the first example does, but also check the DKIM selector "marketing" and the BIMI selector "default".

### Example 4
```powershell
PS C:\> Test-MailPolicy lucernepublishing.com -CountSpfDnsLookups
```

This will do everything the first example does, and test the SPF record recursively to make sure that no more than ten additional DNS lookups are required to evaluate the entire record.

## PARAMETERS

### -BimiSelectorsToCheck
The names of one or more DKIM selectors.  If omitted, no DKIM checks will be done.

```yaml
Type: String[]
Parameter Sets: (All)
Aliases: bimi

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -CountSpfDnsLookups
Specify this switch to count how many additional DNS lookups are required to evaluate SPF.  The SPF test will run recursively to check all `redirect=` modifiers and `include:` tokens.  If more than ten additional DNS lookups are required, SPF parsers may choose to terminate and return a PermError.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases: Recurse

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

### -DkimSelectorsToCheck
The names of one or more BIMI selectors.  If omitted, no BIMI checks will be done.

```yaml
Type: String[]
Parameter Sets: (All)
Aliases: dkim

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

### -ExchangeOnlineDkim
Check the DKIM selectors "selector1" and "selector2".  These are the two (and only two) used by Exchange Online.  You may also use the `-DkimSelectorsToCheck` parameter to check additional selectors.

This is functionally equivalent to `-DkimSelectorsToCheck "selector1","selector2"`.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases: ExchangeOnline, Microsoft365, Microsoft365Dkim, Office365, Office365Dkim

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
This cmdlet (and the others in this module) will test for DNSSEC.  While it is not a requirement (except for DANE), its use is strongly recommended.

If you do not want to run all of these tests, there are cmdlets for each individual test, too.

## RELATED LINKS

[Test-AdspRecord]()
[Test-BimiSelector]()
[Test-DaneRecord]()
[Test-DkimSelector]()
[Test-DmarcRecord]()
[Test-MtaStsPolicy]()
[Test-MXRecord]()
[Test-SmtpTlsReportingPolicy.md]()
[Test-SpfRecord]()
[about_MailPolicyExplainer]()
[about_SMTP]()
