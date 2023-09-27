# paoalto-policy-parser
Script converts paoalto XML encoded security policies into CSV

The script takes and argument of a file (-f/--file) of an XML type file. XML file is a paloalto configuration file.
Script extracts security policies from the Pao Alto configuration file into CVS format file with fields separated by ';'.
Script can take two arguments (optional argument):
1. -s/--service This switch converts custom made service names into PROTO-PORT format. It also cover grouped named service.
2. -a/--address This switch converts custom made address names into what has been defined in address book

TODO
NAT policies
