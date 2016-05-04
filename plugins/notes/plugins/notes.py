#!/usr/bin/env python3.3
# -*- coding: utf-8 -*-
#
# notes plug-in for CVE-Search
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

import lib.DatabaseLayer as db
from lib.Plugins import Plugin, WebPlugin

class notes(WebPlugin):
  def __init__(self):
    self.name = "Notes"
    self.requiresAuth = True
    self.collectionName = "notes"
    self.noteText='''
        <textarea id="noteID_%s" cols="50">%s</textarea>
        %s
        <a onclick="$.getJSON('/plugin/%s/_cve_action/save',{cve: '%s', id: '%s', text: $('#noteID_%s').val()},function(data){parseStatus(data);window.location='/cve/%s'});">
          <span class="glyphicon glyphicon-save" aria-hidden="true"></span></a>'''
    self.noteRemove='''
      <a onclick="$.getJSON('/plugin/%s/_cve_action/delete',{cve: '%s', id: '%s'},function(data){parseStatus(data);window.location='/cve/%s'})">
          <span class="glyphicon glyphicon-remove" aria-hidden="true"></span></a>'''
    # Ensure the database settings exist
    nid = db.p_readSetting(self.collectionName, "last_note")
    if not nid: db.p_writeSetting(self.collectionName, "last_note", 0)

  def search(self, text): 
    pass

  def _getNotesFor(self, cve, user):
    data = db.p_queryOne(self.collectionName, {'cve': cve})
    notes = []
    if data and 'notes' in  data and user in [x["user"] for x in data['notes'] if 'user' in x]:
      notes = [x for x in data['notes'] if x.get('user') == user]
    return notes

  def _deleteIfExists(self, cve, user, noteID):
    note = [x for x in self._getNotesFor(cve, user) if x["id"] == noteID]
    if note:
      db.p_removeFromList(self.collectionName, {'cve': cve}, "notes", note[0])

  def cvePluginInfo(self, cve, **args):
    if not args["current_user"].is_authenticated(): return
    returnData = ""
    for note in self._getNotesFor(cve, args["current_user"].get_id()):
      try:
        nid = note["id"]
        returnData += self.noteText%(nid, note["notes"], self.noteRemove%(self.getUID(), cve, nid, cve), self.getUID(), cve, nid, nid, cve)
      except:
        pass
    returnData += self.noteText%(0, "", "", self.getUID(), cve, 0, 0, cve)
    return {'title': "Notes", 'data': returnData}

  def onCVEAction(self, cve, action, **args):
    if args["current_user"].is_authenticated():
      if   action == "save":
        data = db.p_queryOne(self.collectionName, {'cve': cve})
        user = args["current_user"].get_id()
        # Ensure the entry exists
        if not data: db.p_addEntry(self.collectionName, {"cve": cve, "notes": []})
        # Get note if exists:
        self._deleteIfExists(cve, user, int(args["fields"]["id"][0]))
        # Add note
        nid = db.p_readSetting(self.collectionName, "last_note") + 1
        db.p_addToList(self.collectionName, {'cve': cve}, "notes", {'id': nid, 'user': user, 'notes': args["fields"]["text"][0]})
        # Update last note id
        db.p_writeSetting(self.collectionName, "last_note", nid)
        return True
      elif action == "delete":
        user = args["current_user"].get_id()
        self._deleteIfExists(cve, user, int(args["fields"]["id"][0]))
        return True
