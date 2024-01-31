---
title: THM CMSpit Walkthrough
author: 0xzouhair
date: 2024-01-30 11:33:00 +0700
categories: [TryHackMe, Privilege Escalation]
tags: [THM, Linux, Privesc]
pin: false
math: true
mermaid: true
image:
  path: /assets/img/untitled folder/banner.jpg
---

**Description:** Dive into the world of web app hacking and privilege escalation with this TryHackMe machine, exploiting recent vulnerabilities.

**Difficulty:** Medium

**Machine Link:** [CMSpit on TryHackMe](https://tryhackme.com/room/cmspit)

## 1. Enumeration

![Nmap Scan Results](/assets/img/untitled folder/nmapscan.png)

Two ports are open:
- 22 [SSH]
- 80 [HTTP]

At port 80, I spot Cockpit CMS on the landing page.

![Cockpit CMS Landing Page](/assets/img/untitled%20folder/cms80.png)

## 2. Exploitation

Searching for "cockpit" in msfconsole, I identified a promising exploit.

![Cockpit CMS Exploit](/assets/img/untitled folder/exploit.png)

Configuring rhost, lhost, and lport, I executed the exploit successfully. Here's the output.

![User Enumeration](/assets/img/untitled folder/useren.png)

Next, I selected the 'admin' user and reran the exploit, gaining a shell.

![Getting Shell Access](/assets/img/untitled folder/shell.png)

## 3. Privilege Escalation

Now operating as www-data, I navigated to the home directory and discovered a user named `stux`.

Accessing user stux’s homepage, I stumbled upon an intriguing dbshell file. Examining its contents revealed the second flag and what appears to be a password.

![Home Directory Contents](/assets/img/untitled folder/db.png)

I tested the discovered password and successfully gained access. Running `sudo -l` provided an interesting output:

![Stux Permissions](/assets/img/untitled folder/stux.png)

The discovered permissions open up new avenues for privilege escalation. Let's leverage this and continue the exploration!

## 4. Ultimate Privilege Escalation

With the acquired sudo permissions for user `stux`, After a brief search, I stumbled upon this exploit: [CVE-2021-22204 ExifTool](https://github.com/convisolabs/CVE-2021-22204-exiftool)

The exploit requires some prerequisites:

```bash
sudo apt install djvulibre-bin exiftool
```

The usage involves setting up a listener:

```bash
nc -nvlp 9090  # or the port you specify in the exploit.py file
python3 exploit.py
```

Then, upload the generated image to the target machine and run:

```bash
sudo /usr/local/bin/exiftool image.jpg
```

Executing this payload triggered a successful root shell!

![Root Shell](assets/img/untitled folder/Rootshell.png)
