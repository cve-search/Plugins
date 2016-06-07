# About this plug-in
This plug-in allows users to work together on tasks where actions have
 to be taken for CVEs. It adds a button to the CVE page to check or
 uncheck it and allows filtering through these CVEs. Multiple instances
 of this plug-in can be run, provided you set up the plugins.ini file
 correctly. More information below.

# Installation and setup
The installation of this plug-in is like the installation of any
 plug-in, but the setup requires some extra steps. By default, you will
 have one team, named "Team Colaboration", and the collection
 "team_collab".

## The plugins.ini file
The plug-in has three settings in the plugins.ini file. An example could
 be:

```
[Collaboration]
name: The A team
short name: A team
[Colaboration_]
name: SOC
collection: soc
```
 * `name` will be the name displayed in the plug-in info.
   **Default:** Team Colaboration
 * `short name` will be the name displayed in buttons and filters.
   **Default:** <blank> (nothing)
 * `collection` is the collection it will use in the database.
   **Default:** team_collab

## Managing users
You can manage the users in each collection by running the plug-in
 directly with python3. This assumes the plug-in is located two
 directories deeper than the root directory of CVE-Search (for example
 in `./plugins/Team-Collaboration/Collaboration.py`). The reason is
 relative imports.

The usage is pretty selfexplanatory:
 * **-h** prints the help
 * **-a** adds a user to the specified collection
 * **-d** deletes a user from the specified collection
 * **-c** specifies the collection (if not specified, uses the default)
 * **--drop** drops the specified collection settings and/or data
