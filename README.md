# API Auth Recon

A small scanner for checking which HTTP APIs on an internal network actually
require authentication. You point it at a list of hosts, it finds the live web
services, looks for Swagger/OpenAPI specs, pulls the GET endpoints out of those
specs, and hits each one without any credentials to see whether it comes back
open or asks for a token.

It was built for authorized internal security assessments. Only send it at hosts
you have written permission to test.

## What it does

For every host you feed it, the script runs through four steps:

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
