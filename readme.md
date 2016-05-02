# Plug-in Repository
In this repository, we will maintain some of our CVE-Search plug-ins. These plug-ins can be added and removed however you see fit.  <br />
**The plug-in development of CVE-Search is still in progress!**
Currently only the `pluginmanager` branch from <a href="https://github.com/PidgeyL/cve-search/tree/pluginmanager">PidgeyL's fork</a> has this feature, and this feature will be released in CVE-Search 2.0 later on.

# Installation
The installation of plugins is fairly easy. <br />
As stated earlier, there are two types of plug-ins: Normal plug-ins and web plug-ins. The installation process is almost the same, the web plug-ins just take one more step. <br />
In the installation guide, we will use the bookmark plug-in as an example.
## Steps
 * Open the bookmarks folder.
 * Copy the content from the `plugins` folder to your CVE-Search's plug-in folder (We suggest ./plugins/, but you can place it anywhere).
 * **For web plug-ins:** copy the html page (in the `web.templates.plugins` folder) to the `./web/templates/plugins` folder of your CVE-Search
 * Edit the ./etc/plugins.txt file of your CVE-Search. An example can be found in this repository's etc folder.
 
# Developer information
## Error codes
 * **011** Plug-in page missing - Your plug-in did not respond to `getPage()`
 * **012** Plug-in page corrupt - The page your plug-in returned cannot be parsed correctly
 * **013** Plug-in page not found - The page your plug-in refers to cannot be found

## Variables
When programming a plug-in for CVE-Search, there are a few required and recommended variables.

 * Required
    * self.name - **the full name of the plug-in**
 * Defaults to be overridden if needed
    * self.requiresAuth - **is authentication require to use the plug-in?** - *default: False*
 * Recommended
    * self.collectionName - **The name of the collection in the database** - We recommend this to ensure you use the same collection accross your plug-in

## Functions
 There are a few functions you should and should not override. Here is a list
 
 * Do not override:
    * getName()
    * getUID()
    * setUID(uid)
    * isWebPlugin()
 * To override (when applicable) - All plug-ins:
    * loadSettings(reader) - **loads specified settings from the plug-in settings file**
    * onDatabaseUpdate() - **gets triggered when the database gets updated**
    * search(text) - **gets triggered when a database search is requested and should be used to search plug-in collections**
 * To override (when applicable) - Web plug-ins:
    * getPage(\*\*args) - __return a tupel of the file location of the HTML and a dictionary of the args to fill it in. *Example: return ("bookmarks.html", {"cve": cve})*__
    * getCVEActions(\*\*args) - __returns a list of dictionaries with action information *Example: return [{'text': 'Bookmark', 'action': 'bookmark', 'icon': 'star-empty'}]*__
    * onCVEAction(action \*\*args) - __gets triggered when an action button is pressed on the CVE information page__
    * cvePluginInfo(cve, \*\*args) - __gets the HTML of the plug-in information of the CVE *Example: return {'title': "Bookmarks", 'data': "&lt;b&gt; Bookmarked &lt;/b&gt;"}*__
    
