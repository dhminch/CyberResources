# Resources

## Reconnaissance

- recon-ng - (Comes with Kali) Framework for performing recon on targets

### Host Discovery

- [Certificate transparency logs](https://crt.sh/) - Logs of all certificates issued for a domain. There are multiple other logs providers too.
- [Shodan](https://shodan.io) - Like Google but for service headers. Paid account is much better and not too expensive, plus huge discount multiple times a year.
- [Censys](https://censys.io/ipv4) - Search IPs, hosts, and certificates for domain.
- [DNS Dumpster](https://dnsdumpster.com) - Search domain to find other DNS records
- [EyeWitness](https://github.com/FortyNorthSecurity/EyeWitness) - Takes screenshots of services to make it easier to tell what targets are most fruitful.

### External Host Enumeration

- [Hacker Target](https://hackertarget.com/ip-tools/) - Tools for non-directly getting information about a target device.

### Threat Discovery

- [Threat Crowd](https://threatcrowd.org/) - Search domain, IP, email to see if it's a threat.
- [AbuseIPDB](https://www.abuseipdb.com/) - IP abuse database.
- [VirusTotal](https://virustotal.com) - Search if file is malicious.

### Cloud Discovery

- [ip2provider](https://github.com/oldrho/ip2provider) - Tool to convert list of IPs to list of backing cloud providers.

### Metadata Discovery

- [PowerMeta](https://github.com/dafthack/PowerMeta) - Framework for searching and extracting metadata from documents on a domain.
- [FOCA](https://www.elevenpaths.com/labstools/foca/index.html) - Tool for extracting metadata from documents.
- [GitLeaks](https://github.com/zricethezav/gitleaks) - Tool to look for secrets in git repos. Particularly useful for internal-only repos.
- [GitRob](https://github.com/michenriksen/gitrob) - Another tool to look for secrets in git repos.

### Person Discovery

- [peasant](https://github.com/arch4ngel/peasant) - LinkedIn recon tool.

### Allowed Outbound Ports Discovery

These are domains with all ports open. This is useful for determining what ports are allowed outbound with a `nmap -sS -p- <TEST_DOMAIN>`.

- [AllPortsExposed](http://allports.exposed/)
- [LetMeOutOfYourNet](http://letmeoutofyour.net/)
- [PortQuiz](http://portquiz.net/)


## Escape

- [GTFO Bins](https://gtfobins.github.io/) - If a program runs with higher privileges (e.g., less, journalctl), check if there's a breakout.

## Cracking

- [Firefox Decrypt](https://github.com/unode/firefox_decrypt) - tool to extract passwords from profiles of Mozilla Firefox, Thunderbird, SeaMonkey. May also work on software derived from these.

## Privesc 

- [PEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) - Modern privilege escalation recon tool.

## Exploitation

### Cloud Exploitation

- [pacu](https://github.com/rhinosecuritylabs/pacu) - Framework for attacking cloud-hosted resources.

### Deserialization

- [Deserialization attacks on .NET (and general .NET debugging resources)](https://www.youtube.com/watch?v=--6PiuvBGAU)

### Supply Chain

- [Programming language and OS supply chain](https://www.youtube.com/watch?v=aEeXv5clL7c) - Exploiting targets through weak trust relationships in programming language package repositories and OS repositories.

## Packet Capture / Network Monitoring

- [Brim]{https://www.brimsecurity.com/) - Tool that processes large PCAPs with Zeek and then presents connection information in GUI format.

## Reverse Engineering

- [Ghidra](https://ghidra-sre.org/) - Free reverse engineering tool on par with IDA Pro ($$$).

## Infrastructure

- [Fireprox](https://github.com/ustayready/fireprox) - Proxy that sends each connection over a new EC2 instance (with new IP).

## Other

- [HackTricks](https://book.hacktricks.xyz/) - Detailed book on penetration testing techniques, by the author of the PEAS privesc tool.

