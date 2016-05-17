#!/usr/bin/env python3.3
# -*- coding: utf-8 -*-
#
# SendMail plug-in for CVE-Search
#
# Software is free software released under the "Modified BSD license"
#
# Copyright (c) 2016 	Pieter-Jan Moreels - pieterjan.moreels@gmail.com

# Necessary imports 
import os
import smtplib
import sys
import __main__
callLocation = os.path.dirname(os.path.realpath(__main__.__file__))
sys.path.append(os.path.join(callLocation, ".."))

from lib.Plugins import Plugin, WebPlugin
import lib.CVEs as cves
import lib.DatabaseLayer as db

class sendMail(WebPlugin):
  def __init__(self):
    super().__init__()
    self.name = "Forward CVE"
    self.requiresAuth = True
    
    self.serverCreds = (None, None)
    self.senderCreds = (None, None)
    self.techTeam    = ""
    self.subject     = ""
    self.template    = ""

  def loadSettings(self, reader):
    self.serverCreds = (reader.read("Mailer", "Server", "localhost"),
                        reader.read("Mailer", "Port", 587))
    self.senderCreds = (reader.read("Mailer", "SendUser", ""),
                        reader.read("Mailer", "SendPass", ""))
    self.techTeam    =  reader.read("Mailer", "RecvUser", "")
    self.subject     =  reader.read("Mailer", "Subject", "Vulnerability to review")
    template         =  reader.read("Mailer", "Template", "./etc/template.txt")
    template         =  os.path.join(callLocation, "..", template)
    try:
      self.template = open(template, "r").read()
    except:
      raise ValueError('Could not open the template! %s'%template)

  def getCVEActions(self, cve, **args):
    var = [self.serverCreds[0], self.techTeam, self.senderCreds[0], self.senderCreds[1]]
    if False in [type(x) == str for x in var]: return
    return [{'text': 'Send CVE to the tech team', 'action': 'sendMail', 'icon': 'envelope'}]

  def onCVEAction(self, cve, action, **args):
    if action == "sendMail":
      server=smtplib.SMTP('%s:%s'%(self.serverCreds))
      server.starttls()
      server.login(self.senderCreds[0], self.senderCreds[1])
      subject  = self.subject
      template = self.template
      cveInfo = db.getCVE(cve)
      cvss = cveInfo.get("cvss")
      if not cvss: cvss= "N/A"
      if type(cvss) == float: cvss=str(cvss)
      template = template.replace("<<CVE>>",     cveInfo.get("id"))
      template = template.replace("<<CVSS>>",    cvss)
      template = template.replace("<<Subject>>", cveInfo.get("summary"))
      template = template.replace("<<Sources>>", "\n".join(cveInfo.get("references")))
      cwe = "CWE:\n * " + cveInfo.get("cwe") if cveInfo.get("cwe") else ""
      template = template.replace("<<CWE>>", cwe)
      
      body="Subject: %s\n\n%s"%(subject, template)
      server.sendmail(self.senderCreds[0], self.techTeam, body)
      server.quit()
      return True
