# About this plug-in
This plug-in allows users send an e-mail with CVE info to a specified
 e-mail account, using specified credentials. This could be used to
 send CVE information to teams that have to patch vulnerabilities.

# Installation and setup
The installation of this plug-in is like the installation of any
 plug-in, but the setup requires some extra steps.

## The plugins.ini file
The plug-in has three settings in the plugins.ini file. An example could
 be:

```
[Mailer]
Server:   smtp-mail.server.com
Port:     587
SendUser: sender@cveInstance.com
SendPass: badpassword123
RecvUser: techteam@mycompany.com
Subject:  Vulnerability to review
Template: ./etc/template.txt
```
 * `server` will be the mailserver an email is sent from.
   **Default:** localhost
 * `port` is the port of the mailservice on said mailserver.
   **Default:** 587
 * `senduser` is the email address the information is sent from.
   **Required**
 * `sendpass` is the password to the email address the information is
   sent from. **Required**
 * `recvuser` is the email address the information is sent to.
   **Required**
 * `subject` is the subject of the email. **Default:** Vulnerability to
   review
 * `template` is the location of the for the email. **Default:**
   `./etc/template.txt`

**NOTE:** The password is stored in plain text. We will look for a
 better method to store the password in the future, but for now, we
 recommend to restrict user access to the plugins.ini file, and to use
 a separate mail account for CVE-Search

## The template file
The template will be sent as the body of the e-mail. Certain tags can be
 used in this body:

 * **&lt;&lt;CVE&gt;&gt;**" - The CVE ID
 * **&lt;&lt;CVSS&gt;&gt;**" - The CVSS
 * **&lt;&lt;Subject&gt;&gt;**" - The summary of the CVE
 * **&lt;&lt;sources&gt;&gt;**" - The sources of the CVE
 * **&lt;&lt;CWE&gt;&gt;**" - The weaknesses targetted by the CVE
