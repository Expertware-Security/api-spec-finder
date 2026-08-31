#!/usr/bin/env python3
"""
recon_hosts.py  -  Build a hosts file for an internal assessment.

Three modes, so two people can split the work and merge at the end:

  recon_hosts.py ldap   ...   Active Directory discovery over LDAP
  recon_hosts.py subnet ...   local interfaces and/or explicit CIDRs, TCP sweep
  recon_hosts.py merge  ...   combine several hosts_*.txt into one hosts.txt

Each mode writes its own files so two operators on two machines never clobber
each other:

  ldap   -> hosts_ldap.txt,   inventory_ldap.csv,   ad_subnets.txt
  subnet -> hosts_subnet.txt, inventory_subnet.csv
  merge  -> hosts.txt

Natural handoff: the ldap operator produces ad_subnets.txt, hands it to the
subnet operator who feeds it with  subnet --cidr-file ad_subnets.txt.

Files are written and flushed as work happens and re-dumped on Ctrl-C, so an
interrupted run still leaves a usable list. Authorized assessments only.

Auth (a normal domain user can read all of this):
  - Default (no --user): bind as the CURRENT logged-in Windows user via SSPI /
    Kerberos. No username or password to type or mangle -- just run:
        ldap
    On a domain-joined Windows box this is the reliable path and needs no creds.
  - Explicit credential, if you must run as another account:
        ldap --user 'DOMAIN\\user' --password 'secret'   (NTLM)
        ldap --user user@domain.tld --ssl                 (simple bind over LDAPS)
  - DC and domain are auto-discovered from the environment / DNS when omitted.
"""

import argparse
import atexit
import csv
import glob
import hashlib
import ipaddress
import os
import re
import signal
import socket
import struct
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

import psutil
from rich.console import Console
from rich.progress import BarColumn, MofNCompleteColumn, Progress, TextColumn, TimeElapsedColumn

console = Console()


# ----------------------------------------------------------------------------- MD4 shim
# OpenSSL 3.x drops MD4 from the default provider, so hashlib.new('md4') fails
# with "unsupported hash type MD4". NTLM needs MD4 for the NT hash, so we supply
# a small pure-Python MD4 and route hashlib.new('md4') through it when the native
# one is missing. No extra packages, no system config changes.
def _md4_digest(msg):
    mask = 0xFFFFFFFF
    def rotl(x, n):
        return ((x << n) | (x >> (32 - n))) & mask
    A, B, C, D = 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476
    G = lambda x, y, z: (x & y) | (x & z) | (y & z)
    H = lambda x, y, z: x ^ y ^ z
    ml = len(msg)
    msg = msg + b"\x80"
    while len(msg) % 64 != 56:
        msg += b"\x00"
    msg += struct.pack("<Q", (ml * 8) & 0xFFFFFFFFFFFFFFFF)
    for off in range(0, len(msg), 64):
        X = list(struct.unpack("<16I", msg[off:off + 64]))
        a, b, c, d = A, B, C, D
        for k in (0, 4, 8, 12):
            a = rotl((a + ((b & c) | (~b & d)) + X[k]) & mask, 3)
            d = rotl((d + ((a & b) | (~a & c)) + X[k + 1]) & mask, 7)
            c = rotl((c + ((d & a) | (~d & b)) + X[k + 2]) & mask, 11)
            b = rotl((b + ((c & d) | (~c & a)) + X[k + 3]) & mask, 19)
        for k in (0, 1, 2, 3):
            a = rotl((a + G(b, c, d) + X[k] + 0x5a827999) & mask, 3)
            d = rotl((d + G(a, b, c) + X[k + 4] + 0x5a827999) & mask, 5)
            c = rotl((c + G(d, a, b) + X[k + 8] + 0x5a827999) & mask, 9)
            b = rotl((b + G(c, d, a) + X[k + 12] + 0x5a827999) & mask, 13)
        for k in (0, 2, 1, 3):
            a = rotl((a + H(b, c, d) + X[k] + 0x6ed9eba1) & mask, 3)
            d = rotl((d + H(a, b, c) + X[k + 8] + 0x6ed9eba1) & mask, 9)
            c = rotl((c + H(d, a, b) + X[k + 4] + 0x6ed9eba1) & mask, 11)
            b = rotl((b + H(c, d, a) + X[k + 12] + 0x6ed9eba1) & mask, 15)
        A = (A + a) & mask
        B = (B + b) & mask
        C = (C + c) & mask
        D = (D + d) & mask
    return struct.pack("<4I", A, B, C, D)


class _MD4:
    name = "md4"
    digest_size = 16
    block_size = 64

    def __init__(self, data=b""):
        self._buf = bytearray(data)

    def update(self, data):
        self._buf += data

    def digest(self):
        return _md4_digest(bytes(self._buf))

    def hexdigest(self):
        return self.digest().hex()

    def copy(self):
        c = _MD4()
        c._buf = bytearray(self._buf)
        return c


def install_md4_shim():
    """Route hashlib.new('md4') to the pure-Python MD4 if the native one is gone."""
    try:
        hashlib.new("md4")
        return False           # native MD4 works, nothing to do
    except Exception:
        pass
    _orig_new = hashlib.new

    def _patched_new(name, data=b"", **kw):
        if str(name).lower() == "md4":
            return _MD4(data)
        return _orig_new(name, data, **kw)

    hashlib.new = _patched_new
    return True


DEFAULT_SWEEP_PORTS = [80, 443, 445, 3389, 22, 8080, 8443]
MAX_SUBNET_HOSTS = 4096          # skip anything bigger than a /20 unless raised


# ----------------------------------------------------------------------------- output store
class Output:
    """Discovered items + atomic dump of a per-mode hosts file and inventory."""

    def __init__(self, outdir, tag):
        self.outdir = outdir
        self.tag = tag
        os.makedirs(outdir, exist_ok=True)
        self.hosts = {}          # line -> line, dedups
        self.inventory = []
        self.ad_subnets = []     # (cidr, site)
        self._lock = threading.Lock()
        self.hosts_path = os.path.join(outdir, f"hosts_{tag}.txt")
        self.inv_path = os.path.join(outdir, f"inventory_{tag}.csv")
        self.subnets_path = os.path.join(outdir, "ad_subnets.txt")

    def add_host(self, host, port=None, source="", os_name="", spns=""):
        host = host.strip().rstrip(".").lower()
        if not host:
            return
        line = f"{host}:{port}" if port else host
        with self._lock:
            self.hosts[line] = line
            self.inventory.append({"host": host, "port": port or "",
                                   "source": source, "os": os_name, "http_spns": spns})

    def add_subnet(self, cidr, site=""):
        with self._lock:
            self.ad_subnets.append((cidr, site))

    def dump(self):
        with self._lock:
            hosts = sorted(self.hosts.values())
            inv = list(self.inventory)
            subs = list(self.ad_subnets)
        _atomic_write(self.hosts_path, "\n".join(hosts) + ("\n" if hosts else ""))
        with open(self.inv_path, "w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=["host", "port", "source", "os", "http_spns"])
            w.writeheader()
            for row in inv:
                w.writerow(row)
        if subs:
            _atomic_write(self.subnets_path,
                          "".join(f"{c}\t{s}\n" for c, s in subs))


def _atomic_write(path, text):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(text)
    os.replace(tmp, path)


# ----------------------------------------------------------------------------- environment discovery
def discover_domain(explicit):
    if explicit:
        return explicit
    for var in ("USERDNSDOMAIN", "USERDOMAIN"):
        v = os.environ.get(var)
        if v and "." in v:
            return v.lower()
    return None


def discover_dc(explicit, domain):
    if explicit:
        return explicit
    ls = os.environ.get("LOGONSERVER", "").strip("\\")
    if ls:
        return ls
    if domain:
        try:
            import dns.resolver
            ans = dns.resolver.resolve(f"_ldap._tcp.dc._msdcs.{domain}", "SRV")
            recs = sorted(ans, key=lambda r: (r.priority, -r.weight))
            if recs:
                return str(recs[0].target).rstrip(".")
        except Exception:
            pass
    return None


def _is_ip(host):
    try:
        ipaddress.ip_address(str(host).strip())
        return True
    except ValueError:
        return False


def _dc_fqdn(dc, domain=None):
    """Resolve a DC reference to an FQDN.

    Current-user (SSPI/Kerberos) auth builds the service ticket from the DC's
    hostname (ldap/<fqdn>), so a bare NetBIOS name like LOGONSERVER gives back
    (e.g. 'DC01') or an IP can't be used directly. Try DNS, then fall back to
    stitching the short name onto the domain.
    """
    h = str(dc).strip().strip("\\")
    if not h or "." in h or _is_ip(h):
        return h
    try:
        fq = socket.getfqdn(h)
        if fq and "." in fq and not _is_ip(fq):
            return fq
    except Exception:
        pass
    if domain and "." in domain:
        return f"{h}.{domain}"
    return h


# ----------------------------------------------------------------------------- LDAP
def _first(v):
    if isinstance(v, (list, tuple)):
        return v[0] if v else None
    return v


def _http_spn_hosts(spns, domain):
    """Parse HTTP/... SPNs into (host, port_or_None), FQDN-normalised, deduped."""
    out = []
    for spn in spns or []:
        if not str(spn).upper().startswith("HTTP/"):
            continue
        rest = str(spn)[5:].split("/")[0]
        host, _, port = rest.partition(":")
        host = host.strip().rstrip(".").lower()
        if not host:
            continue
        if "." not in host and domain:
            host = f"{host}.{domain}"
        out.append((host, int(port) if port.isdigit() else None))
    seen, res = set(), []
    for h, p in out:
        if (h, p) not in seen:
            seen.add((h, p))
            res.append((h, p))
    return res


def choose_auth(user, forced):
    """Return 'ntlm' | 'simple' | None (with reason) for a given user string.

    NTLM needs a NetBIOS-style 'DOMAIN\\user'. A UPN 'user@domain.tld' works with
    a SIMPLE bind. A bare username with neither cannot be used.
    """
    if forced in ("ntlm", "simple"):
        return forced, ""
    if "\\" in user:
        return "ntlm", ""
    if "@" in user:
        return "simple", ""
    return None, ("user must be 'DOMAIN\\user' (for NTLM) or 'user@domain.tld' "
                  "(for a simple bind). In PowerShell quote it: --user 'CONTOSO\\jdoe'.")


AD_SUBCODES = {
    "52e": "invalid credentials (wrong username or password)",
    "525": "user not found",
    "530": "not permitted to log on at this time",
    "531": "not permitted to log on at this workstation",
    "532": "password expired",
    "533": "account disabled",
    "701": "account expired",
    "773": "user must reset password before logging on",
    "775": "account locked out",
}


def explain_bind(conn):
    """Human-readable reason from conn.result after a failed bind."""
    r = conn.result or {}
    desc = r.get("description", "")
    msg = r.get("message", "") or ""
    m = re.search(r"data ([0-9a-fA-F]+)", msg)
    if m:
        code = m.group(1).lower()
        if code in AD_SUBCODES:
            return f"{desc}: {AD_SUBCODES[code]} (AD code {code})"
    hints = {
        "strongAuthRequired": "the DC requires a secure channel; use --ssl "
                              "(LDAPS) for a simple bind, or NTLM with sealing.",
        "invalidCredentials": "username or password rejected.",
        "unwillingToPerform": "DC refused; often LDAP signing/channel binding "
                              "enforcement. Try --ssl, or NTLM with sealing.",
    }
    return f"{desc}. {hints.get(desc, msg)}".strip()


def list_forest_domains(conn, conf_dn, scope):
    """Return [(dnsRoot, nCName)] for every domain partition in the forest.

    Reads crossRef objects under CN=Partitions,<Configuration>. Domain partitions
    are the crossRefs whose systemFlags has the DOMAIN bit (0x2) set.
    """
    domains = []
    if not conf_dn:
        return domains
    try:
        conn.search(
            search_base=f"CN=Partitions,{conf_dn}",
            search_filter="(&(objectClass=crossRef)"
                          "(systemFlags:1.2.840.113556.1.4.803:=2))",
            search_scope=scope, attributes=["dnsRoot", "nCName"])
        for e in conn.entries:
            dnsroot = str(e.dnsRoot.value) if "dnsRoot" in e and e.dnsRoot.value else ""
            ncname = str(e.nCName.value) if "nCName" in e and e.nCName.value else ""
            if ncname:
                domains.append((dnsroot.lower(), ncname))
    except Exception:
        pass
    return domains


def ldap_recon(out, dc, domain, user, password, integrated, use_ssl, page_size, auth,
               use_gc, no_seal):
    from ldap3 import Server, Connection, ALL, NTLM, SIMPLE, SASL, KERBEROS, SUBTREE
    from ldap3.core.exceptions import LDAPException

    if not integrated:
        if install_md4_shim():
            console.print("[dim][ldap] native MD4 unavailable (OpenSSL 3); "
                          "using built-in MD4 for NTLM.[/dim]")

    if use_gc:
        port = 3269 if use_ssl else 3268
        kind = "Global Catalog (LDAPS)" if use_ssl else "Global Catalog"
    else:
        port = 636 if use_ssl else 389
        kind = "LDAPS" if use_ssl else "LDAP"

    # SSPI/Kerberos forms its service ticket from the DC's hostname, so for
    # current-user auth we need an FQDN, not a NetBIOS name or an IP.
    conn_host = _dc_fqdn(dc, domain) if integrated else dc
    console.print(f"[cyan][ldap][/cyan] connecting to {conn_host}:{port} ({kind})")
    try:
        from ldap3 import ENCRYPT
    except Exception:
        ENCRYPT = None

    try:
        server = Server(conn_host, port=port, use_ssl=use_ssl, get_info=ALL)
        if integrated:
            if _is_ip(conn_host):
                console.print("[yellow][ldap][/yellow] the DC is an IP address; "
                              "SSPI/Kerberos needs its hostname to build the ticket. "
                              "Pass --dc <dc.fqdn>, or use --user 'DOMAIN\\user' for "
                              "an NTLM bind.")
            console.print("[cyan][ldap][/cyan] binding as the current logged-in "
                          "Windows user (SSPI/Kerberos, no password)")
            conn = Connection(server, authentication=SASL, sasl_mechanism=KERBEROS,
                              auto_bind=False)
        elif user and password:
            method, reason = choose_auth(user, auth)
            if method is None:
                console.print(f"[red][ldap][/red] {reason}")
                return
            ldap_auth = NTLM if method == "ntlm" else SIMPLE
            kwargs = dict(user=user, password=password, authentication=ldap_auth,
                          auto_bind=False)
            # NTLM sealing satisfies most "LDAP signing required" DCs over plain 389.
            seal = (method == "ntlm" and not use_ssl and not no_seal and ENCRYPT)
            if seal:
                kwargs["session_security"] = ENCRYPT
            if method == "simple" and not use_ssl:
                console.print("[yellow][ldap][/yellow] simple bind over plain LDAP "
                              "sends the password in cleartext. Add --ssl for LDAPS.")
            console.print(f"[cyan][ldap][/cyan] bind as {user} ({method}"
                          f"{', sealed' if seal else ''})")
            conn = Connection(server, **kwargs)
        else:
            console.print("[red][ldap][/red] no usable credentials "
                          "(omit --user to bind as the current Windows user, or give "
                          "--user with --password).")
            return
    except LDAPException as e:
        console.print(f"[red][ldap][/red] connection setup failed: {e}")
        return
    except Exception as e:
        console.print(f"[red][ldap][/red] connection error: {e}")
        return

    # manual bind so we can report the real reason
    try:
        ok = conn.bind()
    except LDAPException as e:
        console.print(f"[red][ldap][/red] bind error: {e}")
        low = str(e).lower()
        if integrated and any(k in low for k in
                              ("kerberos", "gssapi", "sspi", "package", "winkerberos")):
            console.print("[dim]Current-user auth needs the Windows Kerberos backend. "
                          "Install it with:\n"
                          "    pip install winkerberos\n"
                          "then re-run. Or fall back to an explicit credential with "
                          "--user 'DOMAIN\\user'.[/dim]")
        return
    except Exception as e:
        console.print(f"[red][ldap][/red] bind error: {e}")
        if integrated:
            console.print("[dim]Current-user auth needs the Windows Kerberos backend "
                          "(pip install winkerberos), a domain-joined machine, and the "
                          "DC reachable by hostname. Or use --user 'DOMAIN\\user'.[/dim]")
        return
    if not ok:
        reason = explain_bind(conn)
        desc = (conn.result or {}).get("description", "")
        console.print(f"[red][ldap][/red] bind rejected: {reason}")

        transport_fail = desc in ("unwillingToPerform", "strongAuthRequired")
        # Only retry with sealing for transport/signing failures. NEVER retry on
        # invalidCredentials -- another attempt just raises badPwdCount and can
        # lock the account.
        if (transport_fail and not integrated and user and password and not use_ssl
                and ENCRYPT and choose_auth(user, auth)[0] == "ntlm" and not no_seal
                and conn.session_security != ENCRYPT):
            console.print("[yellow][ldap][/yellow] retrying NTLM with sealing...")
            try:
                conn2 = Connection(server, user=user, password=password,
                                   authentication=NTLM, session_security=ENCRYPT,
                                   auto_bind=False)
                if conn2.bind():
                    conn = conn2
                    console.print("[green][ldap][/green] sealed NTLM bind succeeded.")
                    ok = True
                else:
                    console.print(f"[red][ldap][/red] sealed retry also rejected: "
                                  f"{explain_bind(conn2)}")
            except Exception as e:
                console.print(f"[red][ldap][/red] sealed retry error: {e}")

        if not ok:
            if integrated:
                console.print("[dim]The current Windows user was rejected by the DC. "
                              "Check that the machine is domain-joined and the DC is "
                              "reachable by hostname (Kerberos can't use an IP). If the "
                              "DC enforces LDAPS channel binding, add --ssl. To run as "
                              "another account instead, use --user 'DOMAIN\\user'.[/dim]")
            elif "52e" in reason or desc == "invalidCredentials":
                console.print(
                    "[yellow]This is a genuine credential rejection, not a "
                    "transport problem. The script will NOT retry, because each "
                    "attempt raises badPwdCount and can lock the account.[/yellow]")
                console.print("[dim]Check, in order of likelihood:\n"
                              "  1. Password mangled by the shell. Re-run without "
                              "--password and type it at the prompt (special chars "
                              "like $ ` ! % & \" break in PowerShell/cmd).\n"
                              "  2. NTLM domain must be the short NetBIOS name: "
                              "'CONTOSO\\user', not 'contoso.local\\user'.\n"
                              "  3. For UPN, the suffix may differ from the DNS "
                              "domain (e.g. jdoe@contoso.com even though AD is "
                              "corp.contoso.local). Use the real logon UPN.\n"
                              "  4. The login name may not be the sAMAccountName.\n"
                              "Verify the account is not already locked before "
                              "trying again.[/dim]")
            else:
                console.print("[dim]If the DC enforces channel binding on LDAPS, or "
                              "signing on 389, try: --ssl for LDAPS, or --kerberos "
                              "with a valid ticket. UPN + --ssl does a TLS simple "
                              "bind.[/dim]")
            return
    console.print("[green][ldap][/green] bind ok.")

    info = server.info
    base_dn = info.other.get("defaultNamingContext", [None])[0] if info else None
    conf_dn = info.other.get("configurationNamingContext", [None])[0] if info else None
    root_dn = info.other.get("rootDomainNamingContext", [None])[0] if info else None
    if not base_dn:
        console.print("[red][ldap][/red] could not read defaultNamingContext.")
        conn.unbind()
        return

    # discover every domain partition in the forest (from Configuration/Partitions)
    domains = list_forest_domains(conn, conf_dn, SUBTREE)  # [(dnsRoot, nCName), ...]
    if domains:
        tag = " (root)" if root_dn else ""
        console.print(f"[cyan][ldap][/cyan] forest domains{tag}: "
                      + ", ".join(d for d, _ in domains))

    # decide which naming contexts to enumerate computers from
    if use_gc:
        search_bases = [(dnsroot, nc) for dnsroot, nc in domains] or \
                       [(domain or base_dn, base_dn)]
    else:
        this = next((d for d, nc in domains if nc == base_dn), domain or base_dn)
        search_bases = [(this, base_dn)]
        if len(domains) > 1:
            console.print("[yellow][ldap][/yellow] this is a single-domain scan. "
                          f"The forest has {len(domains)} domains -- add --gc to "
                          "enumerate all of them via the Global Catalog.")

    comp_filter = ("(&(objectCategory=computer)(objectClass=computer)"
                   "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))")
    total = 0
    for dnsroot, nc in search_bases:
        n_dom = 0
        try:
            entries = conn.extend.standard.paged_search(
                search_base=nc, search_filter=comp_filter, search_scope=SUBTREE,
                attributes=["dNSHostName", "name", "operatingSystem", "servicePrincipalName"],
                paged_size=page_size, generator=True)
            for e in entries:
                if e.get("type") != "searchResEntry":
                    continue
                a = e["attributes"]
                dns_name = _first(a.get("dNSHostName"))
                name = _first(a.get("name"))
                os_name = _first(a.get("operatingSystem")) or ""
                http_hosts = _http_spn_hosts(a.get("servicePrincipalName") or [], dnsroot)
                spn_str = ";".join(f"{h}:{p}" if p else h for h, p in http_hosts)
                host = dns_name or (f"{name}.{dnsroot}" if (name and dnsroot) else name)
                if host:
                    out.add_host(host, source=f"ldap-computer:{dnsroot}",
                                 os_name=os_name, spns=spn_str)
                    n_dom += 1
                for h, p in http_hosts:
                    out.add_host(h, port=p, source=f"ldap-http-spn:{dnsroot}",
                                 os_name=os_name)
            console.print(f"[green][ldap][/green] {dnsroot}: {n_dom} computers")
            total += n_dom
            out.dump()
        except Exception as e:
            console.print(f"[yellow][ldap][/yellow] {dnsroot}: search error: {e}")
    console.print(f"[green][ldap][/green] {total} computers total "
                  f"across {len(search_bases)} domain(s), HTTP SPNs folded in.")
    if use_gc:
        console.print("[dim]Note: the Global Catalog holds a partial attribute set; "
                      "some servicePrincipalName values may be missing. Re-run per "
                      "domain without --gc for complete SPNs if needed.[/dim]")

    if conf_dn:
        sub_base = f"CN=Subnets,CN=Sites,{conf_dn}"
        try:
            conn.search(search_base=sub_base, search_filter="(objectClass=subnet)",
                        search_scope=SUBTREE, attributes=["cn", "siteObject"])
            for e in conn.entries:
                cidr = str(e.cn.value) if "cn" in e else ""
                site = ""
                if "siteObject" in e and e.siteObject.value:
                    m = re.search(r"CN=([^,]+)", str(e.siteObject.value))
                    site = m.group(1) if m else ""
                if cidr:
                    out.add_subnet(cidr, site)
            console.print(f"[green][ldap][/green] {len(out.ad_subnets)} AD subnets "
                          f"-> {out.subnets_path}")
            out.dump()
            if out.ad_subnets:
                console.print(f"[dim]Hand off to your teammate:  "
                              f"python recon_hosts.py subnet --cidr-file "
                              f"{out.subnets_path}[/dim]")
        except Exception as e:
            console.print(f"[yellow][ldap][/yellow] subnet search skipped: {e}")

    conn.unbind()


# ----------------------------------------------------------------------------- subnets / sweep
def local_subnets(include_public=False):
    nets = {}
    for ifname, addrs in psutil.net_if_addrs().items():
        for a in addrs:
            if a.family != socket.AF_INET:
                continue
            ip, mask = a.address, a.netmask
            if not ip or not mask or ip.startswith("127.") or ip.startswith("169.254."):
                continue
            try:
                net = ipaddress.ip_network(f"{ip}/{mask}", strict=False)
            except ValueError:
                continue
            if not include_public and not net.is_private:
                continue
            nets[str(net)] = (net, f"{ifname} {ip}")
    return list(nets.values())


def parse_cidr_lines(text):
    """Accept plain CIDR lines and 'CIDR<tab>site' lines (ad_subnets.txt)."""
    nets = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        tok = re.split(r"[\s,]+", line)[0]
        try:
            nets.append((ipaddress.ip_network(tok, strict=False), "cidr"))
        except ValueError:
            console.print(f"[yellow][subnet][/yellow] skipping bad CIDR: {tok}")
    return nets


def tcp_alive(host, ports, timeout):
    for p in ports:
        try:
            with socket.create_connection((host, p), timeout=timeout):
                return p
        except Exception:
            continue
    return None


def sweep(out, subnets, ports, timeout, workers, max_hosts):
    targets = []
    for net, label in subnets:
        n = net.num_addresses - 2 if net.prefixlen < 31 else net.num_addresses
        if n > max_hosts:
            console.print(f"[yellow][subnet][/yellow] {net} ({label}) ~{n} hosts, "
                          f"skipping (raise --max-hosts to include)")
            continue
        console.print(f"[cyan][subnet][/cyan] sweeping {net} ({label})")
        for ip in net.hosts():
            targets.append(str(ip))
    if not targets:
        console.print("[yellow][subnet][/yellow] nothing to sweep.")
        return
    progress = Progress(TextColumn("[progress.description]{task.description}"),
                        BarColumn(), MofNCompleteColumn(), TimeElapsedColumn(),
                        console=console)
    alive = 0
    with progress:
        task = progress.add_task("[cyan]sweep", total=len(targets))
        with ThreadPoolExecutor(max_workers=workers) as ex:
            futs = {ex.submit(tcp_alive, ip, ports, timeout): ip for ip in targets}
            for fut in as_completed(futs):
                ip = futs[fut]
                try:
                    p = fut.result()
                except Exception:
                    p = None
                if p:
                    alive += 1
                    out.add_host(ip, source="subnet-sweep")
                    console.print(f"  [green][alive][/green] {ip} (tcp/{p})")
                    if alive % 20 == 0:
                        out.dump()
                progress.advance(task)
    console.print(f"[green][subnet][/green] {alive} live hosts")
    out.dump()


# ----------------------------------------------------------------------------- mode runners
def run_ldap(args):
    out = Output(args.outdir, "ldap")
    _install_finalizer(out, "ldap")
    domain = discover_domain(args.domain)
    dc = discover_dc(args.dc, domain)
    if not dc:
        console.print("[red][ldap][/red] no DC found (pass --dc).")
        return
    if domain:
        console.print(f"[cyan][ldap][/cyan] domain: {domain}")

    # Default: bind as the current logged-in Windows user (SSPI/Kerberos). An
    # explicit --user switches to that credential instead; --kerberos forces the
    # current-user path even if a --user was given.
    integrated = args.kerberos or not args.user
    if integrated:
        if args.user or args.password:
            console.print("[yellow][ldap][/yellow] ignoring --user/--password; "
                          "binding as the current logged-in Windows user.")
        console.print("[cyan][ldap][/cyan] authenticating as the current Windows "
                      "user (no username or password needed).")
    else:
        # Resolve the password without letting the shell mangle special characters:
        # explicit --password wins, then $LDAP_PASSWORD, then a hidden prompt.
        if not args.password:
            env_pw = os.environ.get("LDAP_PASSWORD")
            if env_pw is not None:
                args.password = env_pw
                console.print("[dim][ldap] using password from $LDAP_PASSWORD[/dim]")
            else:
                import getpass
                try:
                    args.password = getpass.getpass(f"Password for {args.user}: ")
                except (EOFError, KeyboardInterrupt):
                    console.print("\n[red][ldap][/red] no password provided.")
                    return

    try:
        ldap_recon(out, dc, domain, args.user, args.password,
                   integrated, args.ssl, args.page_size, args.auth, args.gc,
                   args.no_seal)
    except KeyboardInterrupt:
        console.print("\n[yellow]Ctrl-C -- saving what we have...[/yellow]")
    out.dump()
    console.print(f"\n[bold]LDAP done.[/bold] {len(out.hosts)} targets -> {out.hosts_path}")


def run_subnet(args):
    out = Output(args.outdir, "subnet")
    _install_finalizer(out, "subnet")
    ports = ([int(p) for p in args.ports.split(",")] if args.ports else DEFAULT_SWEEP_PORTS)
    subnets = []
    if args.interfaces:
        subnets += local_subnets(include_public=args.include_public)
        if not subnets:
            console.print("[yellow][subnet][/yellow] no private IPv4 interface subnets.")
    for c in args.cidr or []:
        try:
            subnets.append((ipaddress.ip_network(c, strict=False), "cidr"))
        except ValueError:
            console.print(f"[yellow][subnet][/yellow] bad --cidr: {c}")
    if args.cidr_file:
        try:
            subnets += parse_cidr_lines(open(args.cidr_file, encoding="utf-8").read())
        except OSError as e:
            console.print(f"[red][subnet][/red] cannot read {args.cidr_file}: {e}")
    if not (args.interfaces or args.cidr or args.cidr_file):
        console.print("[red][subnet][/red] give --interfaces and/or --cidr/--cidr-file.")
        return
    try:
        sweep(out, subnets, ports, args.timeout, args.workers, args.max_hosts)
    except KeyboardInterrupt:
        console.print("\n[yellow]Ctrl-C -- saving what we have...[/yellow]")
    out.dump()
    console.print(f"\n[bold]Subnet done.[/bold] {len(out.hosts)} targets -> {out.hosts_path}")


def run_merge(args):
    files = args.files or sorted(glob.glob(os.path.join(args.outdir, "hosts_*.txt")))
    if not files:
        console.print("[red][merge][/red] no input hosts files "
                      "(pass files or run modes first).")
        return
    combined = {}
    for f in files:
        try:
            for line in open(f, encoding="utf-8"):
                line = line.strip().lower()
                if line and not line.startswith("#"):
                    combined[line] = line
        except OSError as e:
            console.print(f"[yellow][merge][/yellow] skip {f}: {e}")
    os.makedirs(args.outdir, exist_ok=True)
    master = os.path.join(args.outdir, "hosts.txt")
    _atomic_write(master, "\n".join(sorted(combined.values())) + "\n")
    console.print(f"[green][merge][/green] {len(files)} files -> {len(combined)} "
                  f"unique targets -> {master}")
    console.print(f"[dim]Next:  python api_auth_recon.py -i {master} -o api_recon.jsonl[/dim]")


def _install_finalizer(out, mode):
    done = threading.Event()

    def finalize(*_):
        if done.is_set():
            return
        done.set()
        out.dump()
        console.print(f"[green]{mode} files written to {out.outdir}/[/green]")

    atexit.register(finalize)
    try:
        signal.signal(signal.SIGTERM, lambda *a: (finalize(), sys.exit(0)))
    except Exception:
        pass


# ----------------------------------------------------------------------------- CLI
def main():
    ap = argparse.ArgumentParser(description="Discovery for an internal assessment.")
    ap.add_argument("-o", "--outdir", default="recon_out", help="output directory")
    sub = ap.add_subparsers(dest="mode", required=True)

    p_ldap = sub.add_parser("ldap", help="Active Directory discovery over LDAP")
    p_ldap.add_argument("-o", "--outdir", default=argparse.SUPPRESS)
    p_ldap.add_argument("--dc", help="domain controller host/IP (auto if omitted). "
                        "For current-user auth pass a hostname/FQDN, not an IP")
    p_ldap.add_argument("--domain", help="AD domain FQDN (auto if omitted)")
    p_ldap.add_argument("--user", help="run as this account instead of the current "
                        "Windows user: DOMAIN\\user (NTLM) or user@domain.tld (simple)")
    p_ldap.add_argument("--password", help="password for --user. If omitted, taken "
                        "from $LDAP_PASSWORD or a hidden prompt (avoids shell "
                        "mangling of special characters)")
    p_ldap.add_argument("--kerberos", "--current-user", dest="kerberos",
                        action="store_true",
                        help="force binding as the current logged-in Windows user via "
                             "SSPI/Kerberos (this is already the default when no "
                             "--user is given)")
    p_ldap.add_argument("--auth", choices=["auto", "ntlm", "simple"], default="auto",
                        help="bind method: auto picks NTLM for DOMAIN\\user, "
                             "simple for user@domain.tld (default auto)")
    p_ldap.add_argument("--ssl", action="store_true", help="LDAPS on 636")
    p_ldap.add_argument("--gc", action="store_true",
                        help="query the Global Catalog (port 3268/3269) to enumerate "
                             "computers across ALL domains in the forest")
    p_ldap.add_argument("--no-seal", action="store_true",
                        help="disable NTLM sealing (sealing is on by default over "
                             "plain LDAP to satisfy DCs that require signing)")
    p_ldap.add_argument("--page-size", type=int, default=500)
    p_ldap.set_defaults(func=run_ldap)

    p_sub = sub.add_parser("subnet", help="local interfaces and/or CIDRs + TCP sweep")
    p_sub.add_argument("-o", "--outdir", default=argparse.SUPPRESS)
    p_sub.add_argument("--interfaces", action="store_true",
                       help="derive subnets from local NICs")
    p_sub.add_argument("--cidr", action="append",
                       help="explicit CIDR to sweep (repeatable)")
    p_sub.add_argument("--cidr-file", help="file of CIDRs (accepts ad_subnets.txt)")
    p_sub.add_argument("--ports", help="comma sweep ports "
                       "(default 80,443,445,3389,22,8080,8443)")
    p_sub.add_argument("--timeout", type=float, default=1.0, help="connect timeout s")
    p_sub.add_argument("--workers", type=int, default=200, help="sweep concurrency")
    p_sub.add_argument("--max-hosts", type=int, default=MAX_SUBNET_HOSTS,
                       help=f"skip subnets bigger than this (default {MAX_SUBNET_HOSTS})")
    p_sub.add_argument("--include-public", action="store_true",
                       help="also sweep non-private interface subnets")
    p_sub.set_defaults(func=run_subnet)

    p_mrg = sub.add_parser("merge", help="combine hosts_*.txt into one hosts.txt")
    p_mrg.add_argument("-o", "--outdir", default=argparse.SUPPRESS)
    p_mrg.add_argument("files", nargs="*",
                       help="hosts files to merge (default: hosts_*.txt in outdir)")
    p_mrg.set_defaults(func=run_merge)

    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
