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
import re
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
    if db.p_readUserSetting(self.collectionName, args["current_user"].get_id(), "buttons") == "show":
      userdata = db.p_queryOne(self.collectionName, {'user': args["current_user"].get_id()})
      if userdata and 'cves' in  userdata and cve in userdata['cves']:
        return [{'text': 'Unsee', 'action': 'unsee', 'icon': 'eye-close'}]
      else:
        return [{'text': 'See',   'action': 'see',   'icon': 'eye-open'}]

  def onCVEOpen(self, cve, **args):
    if args["current_user"].is_authenticated():
      if db.p_readUserSetting(self.collectionName, args["current_user"].get_id(), "mode") == "auto":
        query = {'user': args["current_user"].get_id()}
        db.p_addToList(self.collectionName, query, "cves", cve)

  def onCVEAction(self, cve, action, **args):
    try:
      if args["current_user"].is_authenticated():
        query = {'user': args["current_user"].get_id()}
        if action == "see":
          db.p_addToList(self.collectionName, query, "cves", cve)
        elif action == "unsee":
          db.p_removeFromList(self.collectionName, query, "cves", cve)
        elif action == "save_settings":
          mode      = args["fields"]["mode"][0]
          buttons   = args["fields"]["buttons"][0]
          mark      = args["fields"]["mark"][0]
          filters   = args["fields"]["filters"][0]
          markcolor = args["fields"]["markcolor"][0]
          if (mode    in ["auto", "manual"] and buttons in ["show", "hide"] and
              mark    in ["show", "hide"]   and filters in ["show", "hide"] and
               re.match("^#[0-9A-Fa-f]{6}$", markcolor)):
            db.p_writeUserSetting(self.collectionName, args["current_user"].get_id(), "mode", mode)
            db.p_writeUserSetting(self.collectionName, args["current_user"].get_id(), "buttons", buttons)
            db.p_writeUserSetting(self.collectionName, args["current_user"].get_id(), "mark", mark)
            db.p_writeUserSetting(self.collectionName, args["current_user"].get_id(), "filters", filters)
            db.p_writeUserSetting(self.collectionName, args["current_user"].get_id(), "markcolor", markcolor)
          else: return False
        return True
      return False
    except Exception as e:
      print(e)
      return False

  def getFilters(self, **args):
    if db.p_readUserSetting(self.collectionName, args["current_user"].get_id(), "filters") == "show":
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
    user = args["current_user"].get_id()
    if db.p_readUserSetting(self.collectionName, user, "mark") == "show":
      color = db.p_readUserSetting(self.collectionName, user, "markcolor")
      userdata = db.p_queryOne(self.collectionName, {'user': user})
      if userdata and 'cves' in  userdata and cve in userdata['cves']:
        return (None, color)

  def _getUserSetting(self, user, setting, default):
    s = db.p_readUserSetting(self.collectionName, user, setting)
    if not s:
      db.p_writeUserSetting(self.collectionName, user, setting, default)
      s = default
    return s

  def getPage(self, **args):
    if args["current_user"].is_authenticated():
      mode      = self._getUserSetting(args["current_user"].get_id(), "mode",      "auto")
      buttons   = self._getUserSetting(args["current_user"].get_id(), "buttons",   "show")
      mark      = self._getUserSetting(args["current_user"].get_id(), "mark",      "show")
      filters   = self._getUserSetting(args["current_user"].get_id(), "filters",   "show")
      markcolor = self._getUserSetting(args["current_user"].get_id(), "markcolor", "#778899")
      page="user_seen.html"
      return (page, {"mode": mode, "buttons": buttons, "mark": mark, "filters": filters,
                     "markcolor": markcolor, "uid": self.uid})
