# Modules
This repository contains all the modules developed and maintained by the
 [**CVE-Search**](https://github.com/cve-search/cve-search) team, that
 can be used to customize your CVE-Search instance. Below you can find a
 list of the type of customizations you can do, as well as the current
 modules we support:

## Plug-ins
 * **bookmarks** - Bookmark certain CVE's for later reference
 * **MISP** - Enrich your CVE-Search instance with MISP info
 * **notes** - Allow users to add notes to a CVE
 * **Reporting** - Make queries on the data and export them to a CSV
                   file
 * **seen** - Keep track of all the CVEs you've already seen in the past
 * **sendMail** - Easily send a mail with the CVE info to a specified
                  mail address
 * **team_collaboration** - Similar to `seen`, but on group level

## Authentication modules
 * **LDAP** - Authenticate users over LDAP

# Support
If you wish to share your plug-ins and modules with us, you can always
 create a pull request. However, please:
 * **Maintain** your plug-in, as CVE-Search grows and changes
 * Make sure you submit plug-ins for the **latest version** of
   CVE-Search
 * You document your plug-ins and their behavior well, by adding a
   **descriptive readme file**

#License
cve-search and its modules are free software released under the "Modified BSD license"

    Copyright (c) 2016 Pieter-Jan Moreels - https://github.com/pidgeyl/
