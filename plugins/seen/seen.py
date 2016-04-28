#!/usr/bin/env python3.3
# -*- coding: utf-8 -*-
#
# Seen plug-in for CVE-Search
#
# Software is free software released under the "Modified BSD license"
#
# Copyright (c) 2016 	Pieter-Jan Moreels - pieterjan.moreels@gmail.com

# Necessary imports 
import os
import sys
import __main__
callLocation = os.path.dirname(os.path.realpath(__main__.__file__))
sys.path.append(os.path.join(callLocation, ".."))

from lib.Plugins import Plugin, WebPlugin
import lib.CVEs as cves
import lib.DatabaseLayer as db

class seen(WebPlugin):
  def __init__(self):
    super().__init__()
    self.name = "Seen CVEs"
    self.requiresAuth = True
    self.collectionName = "user_seen"

  def getCVEActions(self, cve, **args):
    userdata = db.p_queryOne(self.collectionName, {'user': args["current_user"].get_id()})
    if userdata and 'cves' in  userdata and cve in userdata['cves']:
      return [{'text': 'Unsee', 'action': 'unsee', 'icon': 'eye-close'}]
    else:
      return [{'text': 'See',   'action': 'see',   'icon': 'eye-open'}]

  def onCVEOpen(self, cve, **args):
    print("in open")
    print(cve)
    if args["current_user"].is_authenticated():
      query = {'user': args["current_user"].get_id()}
      print(query)
      db.p_addToList(self.collectionName, query, "cves", cve)

  def onCVEAction(self, cve, action, **args):
    try:
      if args["current_user"].is_authenticated():
        query = {'user': args["current_user"].get_id()}
        if action == "see":
          db.p_addToList(self.collectionName, query, "cves", cve)
        elif action == "unsee":
          db.p_removeFromList(self.collectionName, query, "cves", cve)
        return True
      return False
    except Exception as e:
      return False

  def getFilters(self, **args):
    return [{'id': 'Seen CVEs', 'filters': [{'id': 'hideSeen', 'type': 'select', 'values':[{'id':'show', 'text': 'Show'},
                                                                                           {'id':'hide', 'text': 'Hide'}]}]}]

  def doFilter(self, filters, **args):
    for fil in filters.keys():
      if fil == "hideSeen":
        if args["current_user"].is_authenticated():
          if filters[fil] == "hide":
            cves = db.p_queryOne(self.collectionName, {'user': args["current_user"].get_id()})
            cves = cves["cves"] if cves and 'cves' in cves else []
            return {'id': {"$nin": cves}}
    return {}

  def mark(self, cve, **args):
    userdata = db.p_queryOne(self.collectionName, {'user': args["current_user"].get_id()})
    if userdata and 'cves' in  userdata and cve in userdata['cves']:
      return (None, "#778899")
