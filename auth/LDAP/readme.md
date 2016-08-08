# About this authentication method
Validates the username and password against a specified server over
 LDAP. Usernames can be <domain>\<username> as well as just the
 username. A default domain has to be passed to the plug-in.

# Installation and setup
The installation of this module is similar to every other authentication
 module, but requires extra configuration, and relies on a third party
 library.

## Installing the external library
The installation of this library is very easy and should be familiar:
 `sudo pip3 install ldap3`

## Configuration of the plug-in
The module takes the following arguments:

 * `domain` - The (NT) Domain name **Required**
 * `server` - The server to authenticate against **Required**
 * `sync` - When set, syncs the password with the local database **Optional (default False)**
 
#License
cve-search and its modules are free software released under the "Modified BSD license"

    Copyright (c) 2016 Pieter-Jan Moreels - https://github.com/pidgeyl/
