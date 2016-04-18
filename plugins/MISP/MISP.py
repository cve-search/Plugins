#!/usr/bin/env python3.3
# -*- coding: utf-8 -*-
#
# MISP connector plug-in for CVE-Search
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

import dateutil.parser
import math
import pytz

from datetime import datetime
from pymisp import PyMISP

from lib.Plugins import Plugin, WebPlugin
from lib.ProgressBar import progressbar
import lib.DatabaseLayer as db

class MISP(WebPlugin):
  def __init__(self):
    super().__init__()
    self.name = "Malware Information Sharing Platform"
    self.collectionName = "info_misp"
    self.url = None
    self.key = None

  def loadSettings(self, reader):
    self.url = reader.read("MISP", "url", "")
    self.key = reader.read("MISP", "key", "")

  def onDatabaseUpdate(self):
    output = ""
    lastUpdate = db.p_readSetting(self.collectionName, "last_update")
    now = datetime.utcnow().replace(tzinfo = pytz.utc)
    if lastUpdate:
      last  = dateutil.parser.parse(lastUpdate)
      delta = now - last
      since = "%sm"%math.ceil(delta.total_seconds()/60)
    else:
      since = ""
    if self.url and self.key:
      try:
        # Misp interface
        misp = PyMISP(self.url, self.key, True, 'json')
      except:
        return "[-] Failed to connect to MISP. Wrong URL?"
      try:
        # Fetch data
        misp_last = misp.download_last(since)
        # Check data
        if 'message' in misp_last.keys():
          if misp_last['message'].lower().startswith('no matches'):       return "[+] MISP collection updated (0 updates)"
          elif misp_last['message'].startswith('Authentication failed.'): return "[-] MISP Authentication failed"
        if not 'response' in misp_last:   print(misp_last);                                return "[-] Error occured while fetching MISP data"
        # Nothing wrong so far, so let's continue
        bulk =[]
        for entry in progressbar(misp_last['response']):
          # Get info
          attrs=entry['Event']['Attribute']
          CVEs=   [x['value'] for x in attrs if x['type'] == 'vulnerability']
          if len(CVEs) == 0: continue
          threats=    [x['value'] for x in attrs if x['category'] == 'Attribution'       and x['type'] == 'threat-actor']
          tags   =    [x['value'] for x in attrs if x['category'] == 'Other'             and x['type'] == 'text']
          tags.extend([x['value'] for x in attrs if x['category'] == 'External analysis' and x['type'] == 'text'])
          # Add info to each CVE
          for cve in CVEs:
            item={'id':cve}
            if len(threats) !=0: item['threats'] = threats
            if len(tags)    !=0: item['tags'] = tags
            if len(item.keys())>1: bulk.append(item) # Avoid empty collections
        db.p_bulkUpdate(self.collectionName, "id", bulk)
        #update database info after successful program-run
        db.p_writeSetting(self.collectionName, "last_update", now.strftime("%a, %d %h %Y %H:%M:%S %Z"))
        return "[+] MISP collection updated (%s updates)"%len(bulk)
      except Exception as e: print(e);print(e);return "[-] Something went wrong..."
    else:     return "[-] MISP credentials not specified"


  def cvePluginInfo(self, cve, **args):
    misp = db.p_queryOne(self.collectionName, {'id': cve})
    if misp:
      misp.pop("id")
      data = "<table class='invisiTable'>"
      for key in misp.keys():
        data+="<tr> <td><b>%s</b></td> <td>"%key
        for value in misp[key]:
          data+="<pre>%s</pre>"%value
        data+="</td> </tr>"
      data += "</table>"
      return {'title': "MISP", 'data': data}

  def search(self, text, **args):
    threat = {'n': 'Threat',   'd': db.p_queryData(self.collectionName, {'threats': {"$regex": text, "$options": "-i"}})}
    misp_tag={'n': 'MISP tag', 'd': db.p_queryData(self.collectionName, {'tags':    {"$regex": text, "$options": "-i"}})}
    return [threat, misp_tag]
