#!/usr/bin/env python3.3
# -*- coding: utf-8 -*-
#
# SVF plug-in for CVE-Search
#
# Software is free software released under the "Modified BSD license"
#
# Copyright (c) 2016 	Pieter-Jan Moreels - pieterjan.moreels@gmail.com

# Necessary imports
import csv
import json
import os
import re
import sys
import __main__
callLocation = os.path.dirname(os.path.realpath(__main__.__file__))
sys.path.append(os.path.join(callLocation, ".."))

import lib.DatabaseLayer as db
from lib.Plugins import Plugin, WebPlugin
from lib.Toolkit import mergeSearchResults

from flask import Response
from io import StringIO
from dateutil.parser import parse as parse_datetime
import urllib
import traceback

class Reporting(WebPlugin):
  def __init__(self):
    self.name = "Reporting"
    self.requiresAuth = False
    self.collectionName = "reporting"

  # Copied the filter logic from index.py. Changes made are:
  #  > added self as function variable
  #  > added self to whitelist_mark and blacklist_mark
  #  > added plugManager as function variable
  #  > changed **pluginArgs() to **args and add as function variable
  def filter_logic(self, f, limit, skip, plugManager, **args):
    query = []
    # retrieving lists
    if f['blacklistSelect'] == "on":
      regexes = db.getRules('blacklist')
      if len(regexes) != 0:
        exp = "^(?!" + "|".join(regexes) + ")"
        query.append({'$or': [{'vulnerable_configuration': re.compile(exp)},
                              {'vulnerable_configuration': {'$exists': False}},
                              {'vulnerable_configuration': []}
                              ]})
    if f['whitelistSelect'] == "hide":
      regexes = db.getRules('whitelist')
      if len(regexes) != 0:
        exp = "^(?!" + "|".join(regexes) + ")"
        query.append({'$or': [{'vulnerable_configuration': re.compile(exp)},
                              {'vulnerable_configuration': {'$exists': False}},
                              {'vulnerable_configuration': []}
                              ]})
    if f['unlistedSelect'] == "hide":
      wlregexes = compile(db.getRules('whitelist'))
      blregexes = compile(db.getRules('blacklist'))
      query.append({'$or': [{'vulnerable_configuration': {'$in': wlregexes}},
                            {'vulnerable_configuration': {'$in': blregexes}}]})
    if f['rejectedSelect'] == "hide":
      exp = "^(?!\*\* REJECT \*\*\s+DO NOT USE THIS CANDIDATE NUMBER.*)"
      query.append({'summary': re.compile(exp)})

    # plugin filters
    query.extend(plugManager.doFilter(f, **args))

    # cvss logic
    if f['cvssSelect'] == "above":    query.append({'cvss': {'$gt': float(f['cvss'])}})
    elif f['cvssSelect'] == "equals": query.append({'cvss': float(f['cvss'])})
    elif f['cvssSelect'] == "below":  query.append({'cvss': {'$lt': float(f['cvss'])}})

    # date logic
    if f['timeSelect'] != "all":
      if f['startDate']:
        startDate = parse_datetime(f['startDate'], ignoretz=True, dayfirst=True)
      if f['endDate']:
        endDate   = parse_datetime(f['endDate'],   ignoretz=True, dayfirst=True)
      
      if f['timeSelect'] == "from":
        query.append({f['timeTypeSelect']: {'$gt': startDate}})
      if f['timeSelect'] == "until":
        query.append({f['timeTypeSelect']: {'$lt': endDate}})
      if f['timeSelect'] == "between":
        query.append({f['timeTypeSelect']: {'$gt': startDate, '$lt': endDate}})
      if f['timeSelect'] == "outside":
        query.append({'$or': [{f['timeTypeSelect']: {'$lt': startDate}}, {f['timeTypeSelect']: {'$gt': endDate}}]})
    cve=db.getCVEs(limit=limit, skip=skip, query=query)
    # marking relevant records
    if f['whitelistSelect'] == "on":   cve = self.whitelist_mark(cve)
    if f['blacklistSelect'] == "mark": cve = self.blacklist_mark(cve)
    plugManager.mark(cve, **args)
    cve = list(cve)
    return cve

  # Copied from index.py. Changes made are:
  #  > added self
  #  > added self to compile
  def whitelist_mark(self, cve):
    whitelistitems = self.compile(db.getRules('whitelist'))
    # ensures we're working with a list object, in case we get a pymongo.cursor object
    cve = list(cve)
    # check the cpes (full or partially) in the whitelist
    for cveid in cve:
        cpes = cveid['vulnerable_configuration']
        for c in cpes:
            if any(regex.match(c) for regex in whitelistitems):
                cve[cve.index(cveid)]['whitelisted'] = 'yes'
    return cve

  # Copied from index.py. Changes made are:
  #  > added self
  #  > added self to compile
  def blacklist_mark(self, cve):
    blacklistitems = self.compile(db.getRules('blacklist'))
    # ensures we're working with a list object, in case we get a pymongo.cursor object
    cve = list(cve)
    # check the cpes (full or partially) in the blacklist
    for cveid in cve:
        cpes = cveid['vulnerable_configuration']
        for c in cpes:
            if any(regex.match(c) for regex in blacklistitems):
                cve[cve.index(cveid)]['blacklisted'] = 'yes'
    return cve

  # Copied from index.py. Changes made are:
  #  > added self
  def compile(self, regexes):
    r=[]
    for rule in regexes:
      r.append(re.compile(rule))
    return r

  def getPage(self, **args):
    page="reporting.html"
    plugManager = args["plugin_manager"]
    filters = plugManager.getFilters(**args)
    return (page, {'filters': filters, 'plug_id': self.getUID()})

  def onCVEAction(self, cve, action, **args):
    if   action == "filter":
      try:
        filters = {x.split("=")[0]: x.split("=")[1] for x in args["fields"]['filter'][0].split("&")}
        filters = {x: urllib.parse.unquote(y) for x,y in filters.items()}
        fields  = json.loads(args["fields"]["fields"][0])
        limit = 0
        skip = 0
        cves = self.filter_logic(filters, limit, skip, args["plugin_manager"], **args)
        return {'status': 'plugin_action_complete', 'data': self.generateCSV(cves, fields)}
      except Exception as e:
        traceback.print_exc()
        return False
    elif action == "textsearch":
      try:
        text   = args["fields"]["text"][0]
        fields = json.loads(args["fields"]["fields"][0])
        dbResults = db.getSearchResults(text)
        plugResults = args["plugin_manager"].getSearchResults(text, **args)
        result = mergeSearchResults(dbResults, plugResults)
        cves=result['data']
        fields["reason"] = True
        return {'status': 'plugin_action_complete', 'data': self.generateCSV(cves, fields)}
      except Exception as e:
        traceback.print_exc()
        return False

  def generateCSV(self, cves, fields):
    fields = [x for x,y in fields.items() if y is True]
    memoryFile = StringIO()
    csv_file = csv.writer(memoryFile, delimiter=',', quotechar='"')
    csv_file.writerow(fields)
    for cve in cves:
      line = []
      for field in fields:
        try:
          line.append(cve[field])
        except:
          line.append("")
      csv_file.writerow(line)
    return memoryFile.getvalue()
