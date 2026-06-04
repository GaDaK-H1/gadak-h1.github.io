---
title: "Authentication"
date: 2026-05-22
draft: false

description: "Theory, testing methodology, write ups and common attack techniques for Authentication."

tags:
  - Authentication 
  

categories:
  - concepts
  - web 
  - Labs-Solution

---

# Authentication 

  Authentication refers to the process of verifying a user’s identity, usually through credentials like usernames or email 

  addresses,passwords, or unique tokens/pin codes. Modern web applications rely on various authentication and authorization 
  
  mechanisms such as ***JSON Web Tokens (JWT) , OAuth , Security Assertion Markup Language (SAML)*** . 


# A07:2025 Authentication Failures 
  
  OWASP highlights several common weaknesses:

  - Permits automated attacks such as **credential stuffing** (using lists of known username/password pairs).
  - Allows **brute force** or other automated login attempts.
  - Uses **weak, default, or well-known passwords** (e.g., “Password1”, “admin/admin”).
  - Uses plain text, encrypted, or weakly hashed password storage (e.g., MD5, SHA‑1 without salt).
  - Lacks **multi‑factor authentication** (MFA) or has flawed MFA implementations.
  - Exposes **session identifiers** in URLs.
  - Does not properly **invalidate sessions** after logout, password reset, or a period of inactivity.
  - Accepts **weak password recovery mechanisms** (e.g., “secret question” based on easily discoverable information).

  ---

  # Common Authentication Mechanisms and Flaws

  ## 1. Password‑based Authentication

  **Weaknesses:**
  - Weak or default credentials.
  - Lack of account lockout / rate limiting → brute‑force and credential stuffing.
  - Password complexity policies that actually encourage predictable patterns (e.g., “Summer2025!”).
  - Leaked credentials from data breaches reused across sites.

  **Testing Methodology:**
  - Try common usernames (`admin`, `administrator`, `test`, `user`) and passwords (`admin`, `password`, `123456`, the application name, season+year).
  - Perform a brute‑force attack with a short wordlist, watching for differences in response length, status codes, error messages (e.g., “Incorrect password” vs “User does not exist” – user enumeration).
  - Check if the application uses a lockout mechanism; try to bypass with `X-Forwarded-For` header spoofing, or using different usernames from the same IP.
  - Test for **credential stuffing** by supplying real leaked credentials; watch for account takeover.
  - You can use `Seclists` for every default credentials , username enumeration & password enumeration.

  ## 2. Multi‑Factor Authentication (MFA)

  MFA requires a second factor (something you have, something you are). Flaws include:

  - **Bypassing MFA by modifying the response** (e.g., changing `"mfa_required": true` to `false`).
  - **Directly accessing authenticated endpoints** after passing first factor, skipping the second factor page.
  - **Reusing or brute‑forcing MFA tokens** because they lack rate limiting or have a small key space (4‑6 digit codes).
  - **Weak MFA reset flows** that allow an attacker to disable MFA for a victim’s account.

  **Testing:**  
  Capture a login that stops at the MFA step. Try to access a protected resource directly (e.g., `/my-account`) using the session cookie obtained after the first factor. Intercept and alter responses that indicate MFA status.

  **Futher More Reading:**
  
  `https://hacktricks.wiki/en/pentesting-web/2fa-bypass.html`

  Dafydd Stuttard, Marcus Pinto - The web application hacker's handbook_ finding and exploiting security flaws-Wiley (2011)

  # Portswigger Authentication Labs

  ## Lab: Username enumeration via different responses

  This lab is vulnerable to username enumeration and password brute‑force attacks. It has an account with a predictable username and password, which can be found using a wordlist.
  Solve the lab by enumerating a valid username, brute‑forcing its password, then accessing the account page.

  ***Analysis*** :
  
  Navigate to the login page and submit an arbitrary username/password. 

  The server returns "Invalid username" for non‑existent users and "Incorrect password" for valid ones.
  
  This difference lets us easily filter responses during fuzzing.

  Exploitation :

  Use ffuf to enumerate a valid username by filtering out all responses that contain that exact phrase:

  ```bash
  ffuf -w ~/Desktop/Portswigger/username.txt \
       -u https://LAB_URL/login \
       -d "username=FUZZ&password=test" \
       -fr "Invalid username"
  ```

  ![Username enumeration](/images/authentication/Lab1Authuser.PNG)

  ```bash
  ffuf -w ~/Desktop/Portswigger/passwords.txt \
       -u https://LAB_URL/login \
       -d "username=[username-You-Get-above]&password=FUZZ" \
       -fr "Invalid password"
  ```

  ![Password enumeration](/images/authentication/Lab1Authpass.PNG)

  If we get username, we can also enumerate the passwords like this again.

  We can also use password wordlists under `/usr/share/wordlists/seclists/Passwords/`  in real world scenarioes.


  ## Lab: Username enumeration via subtly different responses

  This lab is vulnerable to username enumeration and password brute‑force attacks, but the difference in responses is very subtle.
  Solve the lab by enumerating a valid username, brute‑forcing the password, and accessing the account page.

  ***Analysis*** : 

  Navigate to the login page and submit an arbitrary username/password.

  Invalid username & password we put  → Invalid username or password. 

  We will try to bruteforce base on this response we doesn't know is there any logic error or not.

  ***Exploitation*** :

  Use ffuf to enumerate a valid username by filtering out all responses that contain that exact phrase:

  ![Username enumeration](/images/authentication/Lab3Authuser.PNG)

  ```bash
  ffuf -w ~/Desktop/Portswigger/username.txt \
       -u https://LAB_URL/login \
       -d "username=FUZZ&password=test" \
       -fr "Invalid username or password\."
  ```

  Tip : ` \. ` is use to get the exact Regex character 

  We can see there is an output of username when we test with burp the error response of username correct or not is base on `.`  at the end of `Invalid username or password.` if the username is correct the response is `Invalid username or password` so we can consider there is a different error response.

  ![Password enumeration](/images/authentication/Lab3Authpass.PNG)


  ```bash
  ffuf -w ~/Desktop/Portswigger/passwords.txt \
       -u https://LAB_URL/login \
       -d "username=[username-You-Get-above]&password=FUZZ" \
       -fr "Invalid password"
  ```


  ## Lab: 2FA simple bypass

  This lab’s two‑factor authentication can be trivially bypassed. You have already obtained a valid username and password `carlos:montoya` but do not have access to the user’s 2FA verification code.
  Solve the lab by accessing the admin panel and deleting the user carlos.

  ***Analysis*** :
  
  After supplying the correct credentials, the application redirects and asks for a 4‑digit security code. 
  
  No other verification takes place – if we can simply skip the second step and request a protected page directly, the session is already considered unauthenticated.

  ***Explotation*** :

  We will use BurpSuite to catch the Log in as carlos:montoya request. Drop the request of 2FA  authentication.

  ![2FA](/images/authentication/2FAdrop.PNG)

  And let's see what will be happen when we visit back to /my-account page.

  ![2FA](/images/authentication/2FAmyaccount.PNG)

  We can see there is login without require the mfa code.

  ## Lab: Password reset broken logic

  This lab’s password reset functionality is flawed. You have credentials for a normal user (wiener:peter). Exploit the broken logic to reset the password of the user carlos, then log in and access his account page.

  ***Analysis***

  The reset flow  asks for a username, then sends a reset link to that user’s registered email.

  The link contains a password reset token which we will try to abuse.

  ***Explotation*** :

  Log in as `wiener:peter` and start the password reset process. Take the reset link form our email and catch the request of password-reset
  function. We can see there is password reset token and also paramters for changing username, new passwords etc.

  ![reset](/images/authentication/reset1.PNG)

  When we change the username parameter to `carlos` it redirects and password reset works. So we can consdier the token can be reused.

  ![reset](/images/authentication/reset2.PNG)

  ## Lab: Username enumeration via response timing

  This lab is vulnerable to username enumeration through response timing. Due to a subtle back‑end delay, requests with a valid username take slightly longer.
  Solve the lab by identifying a valid username, brute‑forcing its password, and accessing the account page.

  ***Analysis***

  The applcation just allow 3 times attempts after that it will block user ip to wait 30 minutes.

  We will use `X-Forwarded-For` header to bypass the login attempts.

  Let's think with  a test case and try out 

  Test case logic:

  ```bash
  If (username == false) {
      // server immediately rejects, password not checked
      return "Invalid username or password.";  // fast ~100ms
  }
  If (username == true && password == false) {
      // server computes password length,hash,  takes longer
      return "Invalid username or password.";  // slow ~500ms+
  }
  ```

  Base on above test case logic we think , we will try out in burp for username enumeration first by increasing the password length.

  ***Explotation*** :

  Send the /POST login request of username & password to intruder and we will enumerating the usernames.

  Mark the `X-Forwarded-For: $1$` & `username=$test$` in intruder. Choose Numbers (set 1 to 100) for `X-Forwarded-For: $1$` and for 
  `username=$test$` choose simple list & use from the lab given username payloads.

  Attack use with `PitchFork` & Change the concurrent thread pool to 1 instead of default thread in Resource pool.

  ![time](/images/authentication/timeAuth1.PNG)

  We look for timer different form Response receive and we saw one of the username is different which has 639.

  ![time](/images/authentication/timeAuth2.PNG)

  We use this username and enumerate the passwords as the previous process. Remember to change Numbers (set 101 to 200)

  ![time](/images/authentication/timeAuth3.PNG)

  We found there is 302 redirection and it works. We got usename and password.

  You just need to login with that username and password.


















