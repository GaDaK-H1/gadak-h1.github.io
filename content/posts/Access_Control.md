---
title: "Broken Access Control"
date: 2026-05-04
draft: false

description: "Theory, testing methodology, write ups and common attack techniques for Broken Access Control."

tags:
  - access-control
  

categories:
  - concepts
---

# Broken Access Control

Description.

Access control enforces policy such that users cannot act outside of their intended permissions. Failures typically lead to unauthorized information disclosure, modification or destruction of all data, or performing a business function outside the user's limits.


# Authentication Vs Authorization 

Authenticatoin is verifying a user's identity – typically through passwords, biometrics, multi-factor authentication, or tokens. Authentication happens before authorization and establishes a session or identity context.

Authorization is determining which resources, actions, and data you are permitted to access.


# A01:2025 Broken Access Control Sample Codes scenarioes

The following scenarios are taken directly from the OWASP Top 10:2025 documentation. They illustrate how broken access control manifests in real-world applications.

Scenario #1: The application uses unverified data in an SQL call that is accessing account information:

Java_Sample_Code :

 `pstmt.setString(1, request.getParameter("acct"));
  ResultSet results = pstmt.executeQuery( );`

An attacker can simply modify the browser's 'acct' parameter to send any desired account number. If not correctly verified, the attacker can access any user's account.

`https://example.com/app/accountInfo?acct=notmyacct`

Scenario #2: An attacker simply forces browsers to target URLs. Admin rights are required for access to the admin page.

`https://example.com/app/getappInfo`

`https://example.com/app/admin_getappInfo`

If an unauthenticated user can access either page, it's a flaw. If a non-admin can access the admin page, this is a flaw.

Scenario #3: An application puts all of their access control in their front-end. While the attacker cannot get to https://example.com/app/admin_getappInfo due to JavaScript code running in the browser, they can simply execute:

`$ curl https://example.com/app/admin_getappInfo`

from the command line.


# Attacking Technique 

Look for parameters that reference an object:

 Path: /api/user/1234, /files/550e8400-e29b-41d4-a716-446655440000 // fuzzing and change the file path, changing value 1234

 Query: ?id=42, ?invoice=2024-00001 // try to change the value behind parameter 

 Body / JSON: {"user_id": 321, "order_id": 987} // explore json data 

 Headers / Cookies: X-Client-ID: 4711 // identifying the Headers & Cookies 

 Prefer endpoints that read or update data (GET, PUT, PATCH, DELETE).

 # Tooling

   
 BurpSuite extensions: Authorize, Auto Repeater, Turbo Intruder.
 
 OWASP ZAP: Auth Matrix, Forced Browse.
 
 Github projects: bwapp-idor-scanner, Blindy (bulk IDOR hunting).



# Portswigger Acces Control Labs

  # Lab: Unprotected admin functionality

  This lab has an unprotected admin panel.Solve the lab by deleting the user carlos. 

  Explotation :

  We can identify the /robots.txt in the target url to know about which paths are allowed and disallowed.

  ![Disallowed paths in robots.txt](/images/access-control/Lab1.png)

  The file reveals the hidden `/administrator-panel` endpoint.

  Tip: 
  
  Many web servers contain a file named robots.txt in the web root that 
  contains a list of URLs that the site does not want web spiders to visit or search 
  engines to index. Sometimes, this file contains references to sensitive 
  functionality, which you are certainly interested in spidering. Some spidering tools 
  designed for attacking web applications check for the robots.txt file and use 
  all URLs within it as seeds in the spidering process. In this case, the robots.txt
  file may be counterproductive to the security of the web application.

  Also we can fuzzing the file path with gobuster which can be use in kali linux.

  We will use SecLists (https://github.com/danielmiessler/seclists) as our wordlists. Installation can be view on its github page. 

  `gobuster dir -u http://lab_URL -w /usr/share/wordlists/seclists/Discovery/Web
  Content/common.txt`

  
  ![Directory fuzzing](/images/access-control/Lab1-gobuster.png)

   change http://lab_URL into actual lab url and try it as automation.



  # Lab: Unprotected admin functionality with unpredictable URL

  This lab has an unprotected admin panel. It's located at an unpredictable location, but the location is disclosed somewhere in the application.

  Solve the lab by accessing the admin panel, and using it to delete the user carlos.


  Explotation :

  Try to look for Javascript codes in view-page-source.

  ![View-Page-Source](/images/access-control/Lab2.png)

  The Javascript codes reveal the file path of administrator.


  # Lab: User role controlled by request parameter


  This lab has an admin panel at /admin, which identifies administrators using a forgeable cookie.

  Solve the lab by accessing the admin panel and using it to delete the user carlos.

  You can log in to your own account using the following credentials: wiener:peter 

  Analysis :

  We have give credentials: `wiener:peter` 

  Use it and analysis the login request.
  
  ![Analysis-The-Request](/images/access-control/burp.png)

  We can see there is a session cookie + Admin = false which is really weird.

  What will happen if we change the Admin = true ? 

  Explotation :

  ![Admin-ture](/images/access-control/Admin.png)

  We can see Admin Panel when we fix the value of Admin = true 

  So we can consider session cookie is just to control users and for administrator it is control by Admin = value

  We can delete the carlos user to solve the lab. 

 # Lab: User role can be modified in user profile

  This lab has an admin panel at /admin. It's only accessible to logged-in users with a roleid of 2.

  Solve the lab by accessing the admin panel and using it to delete the user carlos.

  You can log in to your own account using the following credentials: wiener:peter.

   Analysis :

  We have give credentials: `wiener:peter` 

  Use it and analysis the login request.

  We can't do anything in client control like `?id=weiner` this to `?id=carlos` 

  So let's analysis what we can do in user profile ?

  ![Email-Change](/images/access-control/email.png)

  There is an email change function & we notice that when we test it in burp repeater we can see the response is coming with json data format which also have `roleid:value` 

  Exploit :

  We exploit by changing roleid value to 2 and when we follow and redirection it works. The Adminpanel is shown.

  ![Admin-Panel](/images/access-control/roleid.png)

  Delete the carlos user & we solve the lab. 

# Lab: User ID controlled by request parameter 

  This lab has a horizontal privilege escalation vulnerability on the user account page.

  To solve the lab, obtain the API key for the user carlos and submit it as the solution.

  You can log in to your own account using the following credentials: wiener:peter 

  Analysis : 

  We have give credentials: `wiener:peter` 

  Use it and analysis the login request.

  In url we can see like this : https://0a4f004c0467b2ee818a20e000b800d7.web-security-academy.net/my-account?id=wiener

  So as we mentioned above if we can change `?id=weiner` this to `?id=carlos`  what will be happen ?

  Explotation : 

  For this lab you can also solve from burp request or also can be solve form url.

  ![Carlos-API](/images/access-control/carlos.png)

  Just change `?id=carlos` and we can see we log in as carlos user and get API key. 

# Lab: User ID controlled by request parameter, with unpredictable user IDs 

  This lab has a horizontal privilege escalation vulnerability on the user account page, but identifies users with GUIDs.

  To solve the lab, find the GUID for carlos, then submit his API key as the solution.

  You can log in to your own account using the following credentials: wiener:peter 

  Analysis : 

  We have give credentials: `wiener:peter` 

  Use it and analysis the login request.

  This lab have as the same structure as above one but differnet is there is no such thing `?id=weiner`

  Instead values are change to GUID which is 128 bit text string use to navigate the users. 

  So what will we do instead ?

  When we go to `view posts` posts are tag along with their users, from there can we find out GUID of each user.

  Explotaion :

  We can find posts of carlos user. Try to click his username which tag along with user profile and we can see there is carlos GUID. 

  `https://0aa8001c049eab6785774ee2000700b4.web-security-academy.net/blogs?userId=8a202b10-ab46-4399-9902-dce6eea3529f`

  ![GUID](/images/access-control/GUID.png) 

  Try to change the GUID value in url or burp request as above `Lab: User ID controlled by request parameter` and we can get the carlos API key. 

# Lab: User ID controlled by request parameter with data leakage in redirect 

  This lab contains an access control vulnerability where sensitive information is leaked in the body of a redirect response.

  To solve the lab, obtain the API key for the user carlos and submit it as the solution.

  You can log in to your own account using the following credentials: wiener:peter 

  Analysis :

  We have given credentials: `wiener:peter` 

  Use it and analysis the login request.

  This lab have as the same structure as above one but the difference is if we change `?id=weiner` this to `?id=carlos` in URL 

  the webiste is redirect to login page so how does we gonna do ? Let's examine this in burp 

  Explotaion :

  ![data-lekage](/images/access-control/lekage.png)

  Try to intercept the login reuquest and in `GET /myaccount?id=weiner` try to change `?id=carlos`. After that  hit forward & we can see there is a hidden request or data-lekage about carlos profile before redirect like in actual url value changing.

  When we `follow redirection` we will get back to login page that's why changing value in url doesn't work. 






















