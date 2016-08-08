#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# LDAP Authentication for CVE-Search
#
# Software is free software released under the "Modified BSD license"
#
# Copyright (c) 2016 	Pieter-Jan Moreels - pieterjan.moreels@gmail.com

# Necessary imports
import ldap3
import os
import sys
import __main__
callLocation = os.path.dirname(os.path.realpath(__main__.__file__))
sys.path.append(os.path.join(callLocation, ".."))

from lib.Authentication import AuthenticationMethod
import lib.Authentication as auth
import lib.DatabaseLayer  as db

class LDAP(AuthenticationMethod):
  def __init__(self, domain="", server="", sync=False):
    if not (domain and server): raise(Exception)
    self.domain = domain
    self.server = server
    self.sync   = sync

  def validateUser(self, user, pwd):
    domain = self.domain
    if user.count("\\") == 1: # Domain added
      domain, user = user.split("\\")
    elif user.count("\\") > 1: # Wrong creds
      return auth.WRONG_CREDS

    serv = ldap3.Server(self.server, use_ssl=True)
    try:
      conn = ldap3.Connection(serv, user="%s\\%s"%(domain, user),
                              password=pwd, auto_bind=True)
      if self.sync:
        db.changePassword(user, pwd)
    except ldap3.core.exceptions.LDAPSocketOpenError:
      return auth.UNREACHABLE
    except ldap3.core.exceptions.LDAPBindError:
      return auth.WRONG_CREDS
    return auth.AUTHENTICATED
