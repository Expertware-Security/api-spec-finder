# Internal API Auth Recon

Two scripts that together check which HTTP APIs on an internal network actually
require authentication. The first one discovers hosts, the second one probes
them. You can run them as a pipeline or use either on its own.

  1. `recon_hosts.py` builds the target list. It has three modes so two people
     can split the work: an `ldap` mode that pulls computers and HTTP service
     principals out of Active Directory, a `subnet` mode that sweeps local
     interface ranges and any CIDRs you give it, and a `merge` mode that combines
     both operators' output into one `hosts.txt`.

  2. `api_auth_recon.py` takes that host list, finds the live web services, looks
     for Swagger/OpenAPI specs, pulls the GET endpoints out of those specs, and
     hits each one without any credentials to see whether it comes back open or
     asks for a token.

Both were built for authorized internal security assessments. Only run them
against hosts and ranges you have written permission to test.

Typical flow when two people share the job:

```
pip install -r requirements.txt

# person A, Active Directory
python recon_hosts.py ldap --user 'CONTOSO\jdoe' --password 'secret' -o recon_out

# person B, network ranges (can reuse the AD subnet list A produced)
python recon_hosts.py subnet --interfaces --cidr-file recon_out/ad_subnets.txt -o recon_out

# combine both, then scan
python recon_hosts.py merge -o recon_out
python api_auth_recon.py -i recon_out/hosts.txt -o api_recon.jsonl
```

Working solo, just run both discovery modes yourself and merge. The rest of this
file documents `api_auth_recon.py`. The discovery script is covered in its own
section near the end.

## What the scanner does

For every host you feed it, the scanner runs through four steps:

1. Probes a set of common HTTP and HTTPS ports and records the ones that answer.
2. Tries the usual Swagger and OpenAPI paths on each live service.
3. Parses any spec it finds and pulls out the operations that expose a GET.
4. Sends an unauthenticated GET to each of those endpoints and classifies the
   response.

The output is an Excel workbook with three sheets: the web services it found,
the Swagger specs it found, and the endpoint results. In the endpoints sheet the
rows that answered without asking for auth are highlighted in red, since those
are the ones worth a closer look.

## Requirements

Python 3.8 or newer, plus the packages in `requirements.txt`. Install them with:

```
pip install -r requirements.txt
```

The tools it depends on are `requests`, `openpyxl` for the Excel file, and `rich`
for the live console output.

## Usage

The input file is one host per line. A line can be a bare hostname or IP, or a
`host:port` pair if you already know which port to hit. Blank lines and lines
starting with `#` are ignored. You can also put several entries on one line
separated by spaces or commas. This works well with the hostname list you get
out of an LDAP dump.

Basic run:

```
python api_auth_recon.py -i hosts.txt -o api_recon.jsonl
```

That produces `api_recon.jsonl` (the crash-safe journal) and `api_recon.xlsx`
(the report). The Excel file is the thing you actually read.

While it runs you get live output: green lines for a live web service, cyan for a
Swagger spec, and a red `[UNAUTH]` line each time an endpoint answers without
auth. That way you can see it is doing something rather than staring at a frozen
terminal.

## If it gets interrupted

Every finding is written to the JSONL journal and flushed to disk the moment it
happens, so even a hard kill leaves everything you have collected so far on disk.
On top of that, the Excel file is rebuilt from the journal every so often, when
you press Ctrl-C, and when the script exits normally.

If the process was killed hard and the Excel file looks stale, you can rebuild it
from the journal without rescanning anything:

```
python api_auth_recon.py -o api_recon.jsonl --rebuild
```

Re-running the same command also resumes. Any host that already finished is
skipped, so you can stop and restart a long scan without losing progress or
repeating work.

## Options

- `-i, --input` the hosts file (required unless you use `--rebuild`)
- `-o, --out` journal path, the Excel report is written next to it with the same
  name and an `.xlsx` extension (default `api_recon.jsonl`)
- `-w, --workers` how many hosts to scan at once (default 20)
- `-t, --timeout` per-request timeout in seconds (default 7)
- `--ports` comma-separated list of ports to override the defaults
- `--per-api` cap on how many GET endpoints to test per spec, 0 means all
  (default 0). Set this to something like 3 if you only want a quick
  does-it-ask-for-a-token check rather than full coverage.
- `--delay` seconds to wait between requests, for rate limiting
- `--retries` request retries (default 0)
- `--ua` the User-Agent string, set by default to something that identifies the
  traffic as an authorized assessment
- `--snapshot-every` rebuild the Excel file every N finished hosts (default 20)
- `--rebuild` skip scanning, just rebuild the Excel file from an existing journal

## How results are classified

Each endpoint lands in one of these buckets in the report:

- `UNAUTHENTICATED` came back 200 with a normal-looking body and no sign of an
  auth check. This is the finding. These rows are red.
- `200-AUTH-BODY` came back 200 but the body reads like an auth error, for
  example an "unauthorized" or "please log in" message. Worth a manual check.
- `PROTECTED` returned 401 or 403, or sent back a `WWW-Authenticate` header. The
  header value tells you the scheme, so you can tell Bearer apart from Negotiate,
  NTLM, or Basic.
- `REDIRECT-SSO` a redirect pointing at a login, SSO, ADFS, or OAuth URL, which
  usually means the app is protected.
- `REDIRECT` some other redirect.
- `OTHER` any other status code.
- `ERROR` the request failed to connect.

## A few things worth knowing

The script only ever sends GET requests, and it skips paths whose names suggest
they might change state even on a GET, for example anything with delete, reset,
export, or shutdown in the path. That skip list is a safety net, not a
guarantee, so glance over the specs for anything sensitive before you run it
against production.

If you run this from a domain-joined Windows machine, note that the `requests`
library does not automatically send your Kerberos or NTLM credentials the way a
browser or WinHTTP would. That is actually what you want here, because it means
the results reflect genuine anonymous access rather than your own logged-in
session. An API using Integrated Windows Auth will show up as PROTECTED with a
Negotiate or NTLM value in the `www_authenticate` column, not as open.

Keep the authorization paperwork handy for whatever ranges you put in the hosts
file. The default User-Agent is set to flag the traffic as an authorized
assessment so it is easy to spot in their logs.

# Building the host list with recon_hosts.py

This is the discovery stage, and it has three modes so two people can divide the
work. Its dependencies live in the shared `requirements.txt`. Each mode writes
its own files into the output directory so two operators on two machines never
overwrite each other:

- `ldap` writes `hosts_ldap.txt`, `inventory_ldap.csv`, and `ad_subnets.txt`
- `subnet` writes `hosts_subnet.txt` and `inventory_subnet.csv`
- `merge` writes the combined `hosts.txt`

Point both operators at the same output directory (a share, or just copy the
files together at the end) and `merge` will pick up every `hosts_*.txt` it finds.

## The ldap mode

This queries a domain controller, which any normal domain user can read. It pulls
computer objects for their DNS names and operating system, and it reads the HTTP
service principals, which point straight at web services and sometimes carry a
port. Those port-carrying entries come out as `host:port` lines, which the
scanner understands directly. It also reads the subnet list from AD Sites and
writes it to `ad_subnets.txt`, which is the natural handoff to whoever is running
the subnet mode.

The user format decides the bind method, and picking the wrong one is the usual
cause of a bind failure. There are two forms:

- `DOMAIN\user`, the NetBIOS domain and a backslash, does an NTLM bind. This is
  the reliable default. In PowerShell quote it so the backslash survives:
  `--user 'CONTOSO\jdoe'`.
- `user@domain.tld`, a UPN, does a simple bind instead. A simple bind sends the
  password in cleartext over plain LDAP, so add `--ssl` to run it over LDAPS.

```
python recon_hosts.py ldap --user 'CONTOSO\jdoe' --password 'secret' -o recon_out
```

The script picks the method automatically from the user string. A bare username
with neither a backslash nor an `@` cannot be used and it will tell you so up
front rather than failing at the bind. You can override the choice with
`--auth ntlm` or `--auth simple` if you need to.

If you got `bind failed: NTLM needs domain/username and a password`, it means the
user reached the NTLM path without a `DOMAIN\` prefix. Either add the domain and
backslash, or use the UPN form with `--ssl`.

If you would rather use the Kerberos ticket you already have on a domain-joined
box, use `--kerberos` instead of a password, though that needs a working GSSAPI
or SSPI setup. If you leave off `--dc` and `--domain`, the script tries to work
them out from the environment and from DNS SRV records, which usually just works
on a domain-joined machine.

ldap mode options: `--dc`, `--domain`, `--user`, `--password`, `--auth`
(auto, ntlm, simple), `--kerberos`, `--ssl` (LDAPS on 636), `--page-size`
(default 500).

## The subnet mode

This finds hosts by reachability rather than by AD membership, so it catches
appliances and Linux boxes that are not domain-joined. Give it any mix of local
interfaces and explicit ranges. It works out each subnet, runs a quick TCP
connect check on a handful of common ports, and keeps only the addresses that
answer, so dead space does not clog the list.

```
# sweep the ranges your own NICs sit on
python recon_hosts.py subnet --interfaces -o recon_out

# sweep the AD subnet map the ldap operator produced
python recon_hosts.py subnet --cidr-file recon_out/ad_subnets.txt -o recon_out

# or a specific range or two
python recon_hosts.py subnet --cidr 10.20.0.0/24 --cidr 10.20.1.0/24 -o recon_out
```

`--cidr-file` accepts a plain list of CIDRs and also the tab-separated
`ad_subnets.txt` format, so the handoff is a straight copy. You can combine
`--interfaces`, `--cidr`, and `--cidr-file` in one run.

subnet mode options: `--interfaces`, `--cidr` (repeatable), `--cidr-file`,
`--ports` (default 80, 443, 445, 3389, 22, 8080, 8443), `--timeout` (default
1.0s), `--workers` (default 200), `--max-hosts` (skip any subnet bigger than this
many hosts, default 4096), `--include-public` (also sweep non-private interface
subnets, which you usually do not want).

## The merge mode

```
python recon_hosts.py merge -o recon_out
```

With no file arguments it combines every `hosts_*.txt` in the output directory.
You can also name files explicitly, which is handy if the two of you kept
separate directories:

```
python recon_hosts.py merge personA/hosts_ldap.txt personB/hosts_subnet.txt -o recon_out
```

The result is a deduplicated `hosts.txt` ready for the scanner.

## Notes

The 445 and 3389 ports are in the default sweep list on purpose. They are good
signals that a Windows host is alive even when it has no web service, which keeps
the host list complete. The scanner re-probes real web ports itself later, so the
sweep here is only about pruning dead addresses, not about finding web apps.

Output is written and flushed as it goes and re-dumped if you press Ctrl-C, so an
interrupted run still leaves you a usable host list. Large subnets are skipped by
default rather than swept blindly, so check `ad_subnets.txt` afterwards if you
want to reach into a range the sweep left out.

As with the scanner, `ldap3` does not silently reuse your Windows login. You give
it a credential or a Kerberos ticket explicitly, so it is clear what account the
enumeration ran as.
