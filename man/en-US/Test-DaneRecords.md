---
external help file: MailPolicyExplainer-help.xml
Module Name: MailPolicyExplainer
online version: https://github.com/rhymeswithmogul/MailPolicyExplainer/blob/main/man/en-US/Test-DaneRecords.md
schema: 2.0.0
---

# Test-DaneRecords

## SYNOPSIS
This cmdlet tests DANE records for correctness.

## SYNTAX

```
Test-DaneRecords [-DomainName] <String> [<CommonParameters>]
```

## DESCRIPTION
This cmdlet will test the DANE records of a domain's MX servers for correctness.

DNS-based Authentication of Named Entities (DANE) is a method used to verify the identity of a remote server.  By publishing the server's TLS certificate information in DNS, clients connecting to the remote server can use those TLS authentication (TLSA) records to confirm they have connected to the correct server, making downgrade and man-in-the-middle attacks impossible.  This can replace the traditional TLS certificate validation procedures, or work in tandem with them.

As DNS lookups are not encrypted, DANE will not function unless the DNS zone is signed with DNSSEC.

This cmdlet will verify that a remote server's TLSA records are of the acceptable types for SMTP, either DANE-TX (2) or DANE-EE (3).  It will also verify that the zone is signed with DNSSEC.

Note that this cmdlet can only check for the existence, security, and correctness of DNS TLSA records.  It does not connect to the servers to verify that the TLSA records are actually valid.

DANE was defined in RFC 6698 and updated by RFC 7218, RFC 7671, and RFC 8749.

## EXAMPLES

### Example 1
```powershell
PS C:\> Test-DaneRecords contoso.com
```

This will look up the DANE records for each of contoso.com's MX servers.

For example, if contoso.com has MX records for "mail.contoso.com" and "email.fabrikam.com", then the DNS TLSA records for "_25._tcp.mail.contoso.com" and "_25._tcp.email.fabrikam.com" will be tested.

### Example 1
```powershell
PS C:\> Test-DaneRecords woodgrovebank.com
```

This will look up the DANE records for each of woodgrovebank.com's MX servers.

For example, if woodgrovebank.com uses Exchange Online, this cmdlet may look up and test a TLSA record called "_25._tcp.woodgrovebank-com.1a2b.mx.microsoft".

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
This cmdlet does not attempt to connect to the server and test that the DANE records are valid.  It only tests them for correctness.

## RELATED LINKS

[Test-MxRecords]()
[about_DANERecords]()
[about_DANERecordsAcronyms]()
[about_DANERecordsUsage]()
