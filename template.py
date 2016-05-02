## The class name should be the same as the file name
class template(WebPlugin):
## You may also wish to inherit from Plug-in, if your plug-in is not related to the web interface
  def __init__(self):
    self.name = "template"            ## What is the name of this plug-in?
    self.requiresAuth = False         ## Do users have to log in to use the plug-in?
    self.collectionName = "template"  ## Not required, but highly recommended
  # self.text = "default text"        ## Just a variable for this example
    
  ## Do not override the following functions.
  ## You may however wish to use them within your plug-in
  def getName(self):      return self.name    ## Used by the plug-in manager
  def getUID(self):       return self.uid     ## The UID is set by the plug-in manager. Editing the UID might result in plug-in failure.
  def setUID(self, uid):  self.uid = uid      ## Also used by the plug-in manager.
  def isWebPlugin(self):  return True         ## Distinguish the difference between web plug-ins and regular plug-ins.

  ## These functions may be overridden if you wish to use them
  ## When overridden, these functions should not return anything:

  ## Read the settings from ./etc/plugins.ini
  def loadSettings(self, reader):
    # self.text = reader.read("Template", "text", "Default text")
    pass

  ## This function gets triggered when the database is being updated. 
  def onDatabaseUpdate(self):
    pass

  ## When overridden, these functions should have a return value:

  ## This function gets triggered when the database is being queried
  def search(self, text):
    # return {'n': 'reason', 'd': db.p_queryData(self.collectionName, {'field': {"$regex": text, "$options": "-i"}})}
    ## the key 'n' is the reason the results match the search criteria, 'd' is the data
    pass

  ##
  ## These functions are specific for web plug-ins only.
  ##

  ## To override with returns
  
  ## Return the page you see when surfing to /plugins/<plugin>
  def getPage(self, **args):
    # return ("template.html", {'title': "Default title", 'text': self.text})
    ## The root of the html files is ./web/templates/plugins/
    return (None, None)

  ## Return subpages from the /plugins/<plugin>/<subpage>
  def getSubpage(self, page, **args):
    # text = "default"
    # if page == "test":
    #   text = "test"
    # return ("template.html", {'title': "Subpage %s"%page, 'text': text})
    return (None, None)

  ## Get list of available actions for CVEs
  def getCVEActions(self, cve, **args):
    # return [{'text': 'template action', 'action': 'pointless_action', 'icon': 'ice-lolly'}]
    ## You should have at least 'text' or 'icon' and 'action'
    return []

  ## Get filters you can use to filter the data on
  def getFilters(self, **args):
    # return [{'id': 'template', 'filters': [{'id': 'tSelect', 'type': 'select', 'values':[{'id':'show', 'text': 'Show'},
    #                                                                                      {'id':'hide', 'text': 'Hide'}]},
    #                                        {'id': 'tText', 'type': 'text'}                                               ]}]
    return []

  ## Transform web-filters to database filters
  def doFilter(self, filters, **args):
    # for fil in filters.keys():
    #   if fil == "tSelect":
    #     text = filters.get("tText", None)
    #     if filters[fil] == "hide" and text:
    #       return {"summary":{"$not": {"$regex":text}}}
    # return {}
    return []

  ## Get the information related to the plug-in
  def cvePluginInfo(self, cve, **args):
    # return {'title': "Template", 'data': 'just some random data'}
    pass

  ## Mark CVEs with specific colors or icons
  def mark(self, cve, **args):
    # end = int(cve[-5:].strip("-"))
    # if end % 4 == 0
    #   return (None, "#880000")
    # elif end % 5 == 0
    #   return ("ice-lolly", None)
    ## These are some pointless markings, but they work as an example :)
    return (None, None)

  ## To override without returns

  ## Gets triggered when a user clicks on an action button within the CVE page
  def onCVEAction(self, cve, action, **args):
    # if action == "pointless_action":
    #   print("It's a template, don't expect anything fancy ;)") 
    pass

  ## Gets triggered when a CVE gets opened
  def onCVEOpen(self, cve, **args):
    # print("The template opened %s"%cve)
    pass 


  
  
  
  
