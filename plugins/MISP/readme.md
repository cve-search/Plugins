# About this plug-in
This plug-in queries information from your specified MISP api and
 displays it in the CVE information. It looks for threat-actors and
 tags added by users, and is searchable with the search function. It
 queries this data on every database update
 
# Installation and setup
The installation of this plug-in is like the installation of any
 plug-in, but the setup requires some extra steps. It also requires an
 external library.

## Installing the external library
The installation of this library is very easy and should be familiar:
 `sudo pip3 install -r requirements.txt`

## The plugins.ini file
The plug-in has two settings in the plugins.ini file. An example could
 be:

```
[MISP]
url: https://misp.istance.world
key: api-key 
```
 * `url` is the url of the MISP API. **Required:**
 * `key` is the API key for your MISP instance. **Required:**
