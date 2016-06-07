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
if __name__ == '__main__':
  sys.path.append(os.path.join(callLocation, "..", ".."))
else:
  sys.path.append(os.path.join(callLocation, ".."))

from lib.Plugins import Plugin, WebPlugin
import lib.CVEs as cves
import lib.DatabaseLayer as db

class Collaboration(WebPlugin):
  def __init__(self):
    super().__init__()
    self.name = "Team Colaboration"
    self.shortName = None
    self.requiresAuth = True
    self.collectionName = self._createCollection()

  def loadSettings(self, reader):
    uid = "_"*(len(self.uid)-len(self.uid.strip("_")))
    self.name  =     reader.read("Colaboration"+uid, "name", "Team Colaboration")
    self.shortName = reader.read("Colaboration"+uid, "short name", "")
    collection =     reader.read("Colaboration"+uid, "collection", "").replace(" ", "_")
    self.collectionName = self._createCollection(collection)

  def _getUserSetting(self, user, setting, default):
    s = db.p_readUserSetting(self.collectionName, user, setting)
    if not s:
      db.p_writeUserSetting(self.collectionName, user, setting, default)
      s = default
    return s

  def _createCollection(self, subset=None):
    collection = "team_collab"
    if subset: collection = collection + "_" + subset
    return collection

  def _userAlowed(self, user):
    if user.is_authenticated():
      group = db.p_readSetting(self.collectionName, "group")
      if not group:
        db.p_writeSetting(self.collectionName, "group", [])
        group = []
      if user.get_id() in group:
        return True
    return False

  def getCVEActions(self, cve, **args):
    if self._userAlowed(args["current_user"]):
      if db.p_readUserSetting(self.collectionName, args["current_user"].get_id(), "buttons") == "show":
        userdata = db.p_queryOne(self.collectionName, {})
        shortname = self.shortName + " " if self.shortName else ""
        if userdata and 'cves' in  userdata and cve in userdata['cves']:
          return [{'text': shortname+'Uncheck', 'action': 'uncheck', 'icon': 'check'}]
        else:
          return [{'text': shortname+'Check',   'action': 'check',   'icon': 'unchecked'}]

  def onCVEOpen(self, cve, **args):
    if self._userAlowed(args["current_user"]):
      if db.p_readUserSetting(self.collectionName, args["current_user"].get_id(), "mode") == "auto":
        db.p_addToList(self.collectionName, {}, "cves", cve)

  def onCVEAction(self, cve, action, **args):
    try:
      if args["current_user"].is_authenticated():
        if action == "check":
          db.p_addToList(self.collectionName, {}, "cves", cve)
        elif action == "uncheck":
          db.p_removeFromList(self.collectionName, {}, "cves", cve)
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
    if self._userAlowed(args["current_user"]):
      if db.p_readUserSetting(self.collectionName, args["current_user"].get_id(), "filters") == "show":
        shortname = self.shortName + " " if self.shortName else ""
        return [{'id': shortname+'Checked', 'filters': [{'id': self.uid+"_"+'hidechecked', 'type': 'select',
                                                              'values':[{'id':'show', 'text': 'Show'},
                                                                        {'id':'hide', 'text': 'Hide'}]}]}]
    return []

  def doFilter(self, filters, **args):
    for fil in filters.keys():
      if fil == self.uid+"_"+"hidechecked":
        if self._userAlowed(args["current_user"]):
          if filters[fil] == "hide":
            cves = db.p_queryOne(self.collectionName, {})
            cves = cves["cves"] if cves and 'cves' in cves else []
            return {'id': {"$nin": cves}}
    return {}

  def mark(self, cve, **args):
    if self._userAlowed(args["current_user"]):
      user = args["current_user"].get_id()
      if db.p_readUserSetting(self.collectionName, user, "mark") == "show":
        color = db.p_readUserSetting(self.collectionName, user, "markcolor")
        userdata = db.p_queryOne(self.collectionName, {'user': user})
        if userdata and 'cves' in  userdata and cve in userdata['cves']:
          return (None, color)

  def getPage(self, **args):
    if self._userAlowed(args["current_user"]):
      mode      = self._getUserSetting(args["current_user"].get_id(), "mode",      "auto")
      buttons   = self._getUserSetting(args["current_user"].get_id(), "buttons",   "show")
      mark      = self._getUserSetting(args["current_user"].get_id(), "mark",      "show")
      filters   = self._getUserSetting(args["current_user"].get_id(), "filters",   "show")
      markcolor = self._getUserSetting(args["current_user"].get_id(), "markcolor", "#345678")
      page="team_collaboration.html"
      return (page, {"mode": mode, "buttons": buttons, "mark": mark, "filters": filters,
                     "markcolor": markcolor, "uid": self.uid, "name": self.name})

if __name__ == '__main__':
  import argparse
  argParser = argparse.ArgumentParser(description='Management interface for adding and deleting users from collaboration groups')
  argParser.add_argument('-a', type=str, action='append',     help='Append user')
  argParser.add_argument('-d', type=str, action='append',     help='Delete user')
  argParser.add_argument('-c', type=str,                      help='Collection to manipulate')
  argParser.add_argument('--drop',       action="store_true", help='Drop the collection specified')
  args = argParser.parse_args()

  if args.a or args.d:
    # Get collection to manipulate
    wd = Collaboration()
    collection = wd._createCollection(args.c)
    # Get list of users
    users = db.p_readSetting(collection, "group")
    if not users: users = []
    if type(users) is not list: users = [users]
    a = args.a if args.a else []
    d = args.d if args.d else []
    for user in a:
      if user not in users:
        users.append(user)
    for user in d:
      if user in users:
        users.remove(user)
    db.p_writeSetting(collection, "group", users)
  elif args.drop:
    # Get collection to manipulate
    wd = Collaboration()
    collection = wd._createCollection(args.c)
    print("You are manipulating %s"%collection)
    confirm = input("Do you want to drop the user list? [y/N]")
    if confirm.lower() in ["y", "yes"]: db.p_deleteSettings(collection)
    confirm = input("Do you want to drop the data? [y/N]")
    if confirm.lower() in ["y", "yes"]: db.p_drop(collection)
