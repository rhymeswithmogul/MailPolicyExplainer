---
external help file: MailPolicyExplainer-help.xml
Module Name: MailPolicyExplainer
online version: https://github.com/rhymeswithmogul/MailPolicyExplainer/blob/main/man/en-US/Test-BimiSelector.md
schema: 2.0.0
---

# Test-BimiSelector

## SYNOPSIS
Tests a domain's BIMI selector for correctness.

## SYNTAX

```
Test-BimiSelector [-DomainName] <String> [[-Name] <String>] [-DisableDnssecVerification] [<CommonParameters>]
```

## DESCRIPTION
This cmdlet wlil look up one of a domain's BIMI selectors and test it for correctness.

Brand Indicators for Message Identification (BIMI) is a draft standard used to allow mail user agents (MUAs) to display company logos and other brands next to properly-identified emails.

There are three requirements for BIMI to function, even if the DNS record for the BIMI selector is syntactically correct:
1. The email must be properly signed with DKIM.
2. The email must be DMARC-aligned.
3. The domain's DMARC policy must be "quarantine" or "reject".
4. The BIMI record must link to a valid SVG file accessible over HTTPS.

Additionally, the BIMI record should contain a link to an assertion that's signed by a trusted certificate authority.  This is not a requirement by the BIMI specification, but many MUAs will not show the image unless it is verifiable.

BIMI records contain two tags, "l" linking to a valid SVG image, and "a" linking to an assertion file.  Alternatively, "l" and "a" may have null values to indicate that a domain has opted out of BIMI.

## EXAMPLES

### Example 1
```powershell
PS C:\> Test-BimiSelector "contoso.com"
```

Tests the BIMI selector named "default" present for contoso.com.  The DNS TXT record to be looked up is "default._bimi.contoso.com".

As "default" is the default value, the output of this cmdlet would not change if `-Name "default"` were added.

### Example 2
```powershell
PS C:\> Test-BimiSelector "contoso.com" -Name "tailspintoys"
```

Tests the BIMI selector named "tailspintoys" present for contoso.com.  The DNS TXT record to be looked up is "tailspintoys._bimi.contoso.com".

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
The domain name whose BIMI selector you wish to test.  Be sure to include any applicable subdomains (i.e., "contoso.com" and "newsletters.contoso.com" are two different domains).

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

### -Name
The BIMI selector to analyze.  If not specified, the default of "default" will be used.

```yaml
Type: String
Parameter Sets: (All)
Aliases: Selector, SelectorName

Required: False
Position: 1
Default value: "default"
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
MailPolicyExplainer can only check DKIM, DMARC, and BIMI DNS records for correctness.  There are many other requirements that this module cannot check, such as:
 - If outgoing emails are properly signed.
 - If outgoing emails contain the appropriate BIMI headers.
 - If the SVG file can be downloaded.
 - If the SVG file is valid.
 - If the assertion can be downloaded.
 - If the assertion is trusted by the recipient's MUA.

Note that while BIMI is in use, the specification is still under development, and has not yet been finalized and approved by the IETF.  This cmdlet complies with draft-brand-indicators-for-message-identification-04.

## RELATED LINKS

[about_BIMI]()
[Test-DkimSelector]()
[Test-DmarcRecord]()
[BIMI Working Group](https://datatracker.ietf.org/doc/draft-brand-indicators-for-message-identification/)
