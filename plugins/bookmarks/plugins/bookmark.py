#!/usr/bin/env python3.3
# -*- coding: utf-8 -*-
#
# Bookmark plug-in for CVE-Search
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

class bookmark(WebPlugin):
  def __init__(self):
    super().__init__()
    self.name = "Bookmarks"
    self.requiresAuth = True
    self.collectionName = "user_bookmarks"

  def getPage(self, **args):
    cvesp = cves.last(rankinglookup=True, namelookup=True, vfeedlookup=True, capeclookup=True,subscorelookup=True)
    cve=[cvesp.getcve(cveid=x) for x in db.p_queryOne(self.collectionName, {"user": args["current_user"].get_id()})['bookmarks']]
    page="bookmarks.html"
    return (page, {"cve": cve})

  def getCVEActions(self, **args):
    userdata = db.p_queryOne(self.collectionName, {'user': args["current_user"].get_id()})
    if userdata and 'bookmarks' in  userdata and args['cve'] in userdata['bookmarks']:
      return [{'text': 'Remove bookmark', 'action': 'unbookmark', 'icon': 'star'}]
    else:
      return [{'text': 'Bookmark', 'action': 'bookmark', 'icon': 'star-empty'}]

  def onCVEAction(self, cve, action, **args):
    try:
      query = {'user': args["current_user"].get_id()}
      if action == "bookmark":
        db.p_addToList(self.collectionName, query, "bookmarks", cve)
      elif action == "unbookmark":
        db.p_removeFromList(self.collectionName, query, "bookmarks", cve)
      return True
    except Exception as e:
      return False
