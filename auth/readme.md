# Authentication Module repository
In this directory, we will maintain some of our CVE-Search
 authentication modules. These modules can be added and removed however
 you see fit.
 
**The Authentication development of CVE-Search is still in progress!**

**Note:** Development of the authentication feature is mostly done by
 [PidgeyL](https://github.com/PidgeyL), so new features will come from
 [his branch](https://github.com/PidgeyL/cve-search) first. If you
 encounter compatibility issues, please keep this in mind. <br />
**Note:** The username of the authenticating user has to be present in
 the local database. <br />
**Note:** `local_only` users will bypass authentication done by modules.

# Installation
The installation of these modules is fairly easy. <br />
Installing a module is as easy as dragging it into the
 `./lib/authenticationMethods` folder, and modifying the
 `./etc/auth.txt` file. We will use the LDAP module as an example
 throughout this readme.

**Note:** Some plug-ins require third party libraries. Make sure to read
 the readme of the plug-in carefully.

## The auth file
The `./etc/auth.txt` file is used sequentially. The first module gets 
 used first, and so on. Lines starting with `#` are ignored. An example
 could be:

```
# Module	required/sufficient	  args
LDAP		  sufficient		        domain=CVESearch server=ldap.cve.search
```

### Module
Module is the name of the module, without the `.py` suffix. If for some
 reason you want to put the module in a subdirectory, use the path
 starting from the `./lib/authenticationMethods` folder, and replace
 every `/` by a `.`

### required/sufficient
A module can return three states:
 * **AUTHENTICATED** - The user is validated against this module 
 * **WRONG_CREDS** - The user is not validated against this module
 * **UNREACHABLE** - This module was unable to verify the user (e.g
                     the server is not reachable)

If a module is set to "required", authentication will only succeed if
 the module returns **AUTHENTICATED**. If it returns **WRONG_CREDS**,
 authentication will fail. If the module returns **UNREACHABLE**, the
 next module in the list is used. The last automatic fallback method is
 authentication against the local database. <br />
If a module is set to "sufficient", and the module returns
 **WRONG_CREDS**, authentication will not fail, but drop to the next
 module. The outcome of the authentication will depend on the first
 (responding) `required` module, or the database if all other modules
 fail.

### args
The arguments are passed to the module when the module gets created.
 It is important you do not put a space between the key and the value
 (`domain` is the key, `CVESearch` is the value), but you do separate
 key/value groups with a space or tab.

## Users
When authentication modules are used, all users will be subject to
 authentication against these modules. If you want to have a user who
 can bypass these authentication methods (e.g an emergency
 administrator), you can make him `local_only`. You do this by passing
 the `-l` flag to `./sbin/db_mgmt_admin.py` when creating the user.
