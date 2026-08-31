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

# person A, Active Directory (binds as the current logged-in Windows user)
python recon_hosts.py ldap -o recon_out

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

By default the ldap mode binds as the **current logged-in Windows user** over
SSPI / Kerberos. On a domain-joined machine that means there is nothing to type:
no username, no password, no credential for the shell to mangle. Just run it.

```
python recon_hosts.py ldap -o recon_out
```

This uses the same integrated authentication a browser or WinHTTP would, taking
the Kerberos ticket from your current logon session. It needs the `winkerberos`
package (pulled in by `requirements.txt` on Windows) and a domain controller
reachable by hostname — Kerberos builds its service ticket from the DC's name, so
if you pass `--dc` give it a hostname or FQDN, not an IP. Leave `--dc` and
`--domain` off and the script discovers them from your environment and DNS, which
usually just works.

If you need to run the enumeration as a **different account**, pass `--user` and
the script switches to an explicit credential. The user format decides the bind
method:

- `DOMAIN\user`, the NetBIOS domain and a backslash, does an NTLM bind. In
  PowerShell quote it so the backslash survives: `--user 'CONTOSO\jdoe'`.
- `user@domain.tld`, a UPN, does a simple bind instead. A simple bind sends the
  password in cleartext over plain LDAP, so add `--ssl` to run it over LDAPS.

```
python recon_hosts.py ldap --user 'CONTOSO\jdoe' --password 'secret' -o recon_out
```

The script picks the method automatically from the user string. A bare username
with neither a backslash nor an `@` cannot be used and it will tell you so up
front rather than failing at the bind. You can override the choice with
`--auth ntlm` or `--auth simple` if you need to. `--current-user` (an alias for
`--kerberos`) forces the current-user path back on even when a `--user` is
present.

If you got `bind failed: NTLM needs domain/username and a password`, it means the
user reached the NTLM path without a `DOMAIN\` prefix. Either add the domain and
backslash, or use the UPN form with `--ssl`.

If you got `unsupported hash type MD4`, that is OpenSSL 3 dropping MD4 from its
default provider, which NTLM needs for the NT hash. The script carries its own
pure-Python MD4 and switches to it automatically when the system one is missing,
so this is handled for you with no extra install and no config changes. You will
see a one-line note that it fell back to the built-in MD4. If you would rather
avoid NTLM entirely, the UPN plus `--ssl` simple bind or `--kerberos` both skip
MD4.

If you got `automatic bind not successful`, the credentials reached the DC and it
rejected the bind. The script now does the bind by hand and prints the real
reason, including the Active Directory sub-code when there is one. Common ones:
`52e` is a wrong username or password, `775` is a locked account, `532` is an
expired password, `533` is a disabled account. If the message mentions
`unwillingToPerform` or `strongAuthRequired`, the DC is enforcing LDAP signing or
channel binding rather than rejecting your password.

If the bind is rejected with `invalid credentials (AD code 52e)`, the DC
evaluated the password and it did not match. This is not a transport or signing
problem, so the script does not retry, because each attempt raises the account's
bad-password count and can lock it out. When you are sure the password is right,
the usual causes are, in order: the shell mangled the password (re-run without
`--password` and type it at the hidden prompt, since characters like `$`, backtick,
`!`, `%`, `&`, and `"` break in PowerShell or cmd); the NTLM domain was the DNS
name rather than the short NetBIOS name, so use `CONTOSO\user` not
`contoso.local\user`; the UPN suffix differs from the DNS domain, so the real
logon UPN might be `jdoe@contoso.com` even though the directory is
`corp.contoso.local`; or the login name you use is not the account's
sAMAccountName. Verify the account is not already locked before trying again.

To keep the password away from the shell entirely, leave `--password` off. The
script then reads `$LDAP_PASSWORD` if set, otherwise prompts for it without
echoing. That is the most reliable way to pass a password with special
characters.

All of that only applies when you deliberately run as another account with
`--user`. If you just want to enumerate as yourself, drop `--user` entirely and
let the default current-user bind do the work — there is no password to get
wrong in the first place.

ldap mode options: `--dc`, `--domain`, `--user`, `--password`, `--auth`
(auto, ntlm, simple), `--kerberos` / `--current-user`, `--ssl` (LDAPS on 636),
`--gc`, `--page-size` (default 500).

### One domain or the whole forest

By default this queries the single domain that the DC you connect to belongs to.
It still reads the AD Sites subnet list, which is forest-wide, so `ad_subnets.txt`
covers everything regardless. The computer objects, though, come from just that
one domain.

On connect it enumerates every domain partition in the forest and prints the
list, so you can see what is out there. If there is more than one and you did not
ask for all of them, it says so.

To pull computers from every domain in the forest in one run, add `--gc`. That
connects to the Global Catalog on port 3268 (or 3269 with `--ssl`) and walks each
domain partition. The inventory records which domain each host came from, in the
`source` column.

```
python recon_hosts.py ldap --user 'CONTOSO\jdoe' --password 'secret' --gc -o recon_out
```

Two caveats. The Global Catalog holds a partial set of attributes, so a few
`servicePrincipalName` values can be missing from a GC scan. If you need complete
SPNs for a particular domain, run that domain without `--gc` by pointing `--dc`
at one of its controllers. And this covers one forest. A separate trusted forest
needs its own credentials, so run the tool again against a DC there.

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

Note that the discovery and scanning stages authenticate differently, on
purpose. The `ldap` mode binds as your current Windows login by default, because
reading the directory as yourself is exactly what you want and a normal domain
user can read all of it. The scanner, on the other hand, never reuses your login
— it sends every request unauthenticated, so its results reflect genuine
anonymous access rather than your own session.
