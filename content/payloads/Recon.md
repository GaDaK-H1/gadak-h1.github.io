---
title: "Recon & Enumeration Payloads"
date: 2026-08-16
draft: true
aliases:
  - /payloads/recon/
description: "Essential reconnaissance commands, tools, and techniques for pentesting and bug bounty."
tags:
  - recon
  - enumeration
categories:
  - payloads
---

## Shodan Query Filters

Shodan supports its own query filters, which let you narrow results significantly:

| Filter      | Description                                                                                       | Example                          |
| ----------- | ------------------------------------------------------------------------------------------------- | -------------------------------- |
| `country`   | Restrict results to a specific country code.                                                      | `country:IE`                     |
| `port`      | Filter by a specific port number or a range.                                                      | `port:22`                        |
| `org`       | Scope results in a named organisation or ASN Identifier (Who owns a range of IP addresses).        | `org:AS7224` (Amazon Web Services) |
| `hostname`  | Match against a specific hostname or domain.                                                      | `hostname:fakebank.com`          |

## Phase By Phase for Pentest Engagement

Port scanning - `namp`

Website - view, dir bruteforcing

## Metasploit Quick Reference

```
LHOST - our ip
LPORT - our-port

RHOST - victim ip
RPORT - victim port

show payloads
show options

set payload <payload_name>
set LHOST,RHOST <our-ip>
```

## Useful One-Liners

Find all password files on a system while suppressing errors:

```
find / -name password* 2>/dev/null
```

> `2>/dev/null` suppresses all error output.

SSH login:

```
ssh username@ip
```
