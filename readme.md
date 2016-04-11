# Plug-in Repository
In this repository, we will maintain some of our CVE-Search plug-ins. These plug-ins can be added and removed however you see fit.  <br />
**The plug-in development of CVE-Search is still in progress!**
Currently only the `pluginmanager` branch from <a href=www.github.com/PidgeyL/CVE-Search>PidgeyL's fork</a> has this feature, and this feature will be released in CVE-Search 2.0 later on.

# Installation
The installation of plugins is fairly easy. <br />
As stated earlier, there are two types of plug-ins: Normal plug-ins and web plug-ins. The installation process is almost the same, the web plug-ins just take one more step. <br />
In the installation guide, we will use the bookmark plug-in as an example.
## Steps
 * Open the bookmarks folder.
 * Copy the content from the `plugins` folder to your CVE-Search's plug-in folder (We suggest ./plugins/, but you can place it anywhere).
 * **For web plug-ins:** copy the html page (in the `web.templates.plugins` folder) to the `./web/templates/plugins` folder of your CVE-Search
 * Edit the ./etc/plugins.txt file of your CVE-Search. An example can be found in this repository's etc folder.
 
