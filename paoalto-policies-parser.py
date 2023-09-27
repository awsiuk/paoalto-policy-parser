#by Łukasz Awsiukiewicz

import csv
import xml.etree.ElementTree as ET
import copy
import argparse
import os

#data structures
#Elements of this list will be based on 'policy' data strcuture (dictionary)
policies_set=[]
services_set=[]
hosts_set=[]

#define header for CVS, not used in any other purpose
policy_description=['VSYS','from-zone','to-zone',"policy-name", 'source-address','destination-address','application','source-identity',"global-from-zone","global-to-zone","action","application-name","category","description","tag"]

#fields mapping from SRX data strcutre SRX | PAOALTO (SRX parser project)
#source-identity from SRX = source-user
#application = service
policy = {
"VSYS": "GLOBAL",
"from-zone": [],
"to-zone": [],
"policy-name": "",
"source-address": [],
"destination-address": [],
"application": [],
"source-identity": [],
"global-from-zone": [],
"global-to-zone": [],
"action": [],
"application-name": [],
"category": [],
"description": [],
"tag": []
}

service = {
    "name": "",
    "service": []
}

host = {
    "name": "",
    "address": []
}


#Functions
def process_services(root):
    for item in root.findall("./result/config/devices/entry/vsys/entry/service/entry"):
        temp_service=copy.deepcopy(service)
        temp_service['name']=item.get('name')
        for port_element in item.findall("./protocol/udp/port"):
            temp_service['service'].append("UDP-"+port_element.text)
        for port_element in item.findall("./protocol/tcp/port"):
            temp_service['service'].append("TCP-"+port_element.text)
            exist=1
        services_set.append(temp_service)
    #check service groups and translate them into port proto-port list
    for item in root.findall("./result/config/devices/entry/vsys/entry/service-group/entry"):
        temp_service=copy.deepcopy(service)
        temp_service['name']=item.get('name')
        for port_element in item.findall("./members/member"):
            exist=0
            #go thrrough the list of existing services_set
            for service_element in services_set:
                #check 
                if port_element.text == service_element['name']:
                    exist=1
                    for element_on_list in service_element['service']:
                        temp_service["service"].append(element_on_list)
            if not exist:
                temp_service["service"].append(port_element.text)
        services_set.append(temp_service)

#build data list containing address book entires
#this will not do anything to main policies_set
def process_addresses(root):
    for item in root.findall("./result/config/devices/entry/vsys/entry/address-group/entry"):
        temp_addr=copy.deepcopy(host)
        temp_addr['name']=item.get('name')
        for address_element in item.findall("./static/member"):
            temp_addr['address'].append(address_element.text)
        hosts_set.append(temp_addr)

#this function takes build address book and replace custom names
#with defined in address book address e.g., expand address groups
def replace_addresses():
    print("replacing addresses")
    for policy in policies_set:
        for addr in hosts_set:
            for policy_addr in policy['source-address']:
                if policy_addr==addr['name']:
                    policy['source-address'].remove(policy_addr)
                    for address_group in addr['address']:
                        policy['source-address'].append(address_group)
            for policy_addr in policy['destination-address']:
                if policy_addr==addr['name']:
                    policy['destination-address'].remove(policy_addr)
                    for address_group in addr['address']:
                        policy['destination-address'].append(address_group)

#this function purpose is similar to previous
#replace custom made service names to valid proto-port name
def services_replace():
    print("replacing services")
    for policy in policies_set:
        for policy_service in policy['application']:
            for app_service in services_set:
                if app_service['name']==policy_service:
                    policy['application'].remove(policy_service)
                    for entry in app_service['service']:
                        policy['application'].append(entry)

#--- main script ---

#handle script arguments
parser = argparse.ArgumentParser(prog='paoalto-policy-parser',description='Script takes 1 argument of a config file (typically .conf) and outputs CSV file with ".csv" extension with the same name as orginal file.',epilog='by Lukasz Awsiukiewicz, biuro@la-tech.pl')
parser.add_argument('-f', '--file', help='%(prog)s --filein=<paoalto conf file in set format>', required=True)
parser.add_argument('-s', '--service', help='Converts custom made service name from address book to defined valid proto/port', required=False, action="store_true")
parser.add_argument('-a', '--address', help='%(prog)s --filein=<paoalto conf file in set format> -a', required=False, action="store_true")
a1 = parser.parse_args()


#test out if provided file exist
f_in_name=vars(a1)["file"]
if not(os.path.exists(f_in_name)):
    print("file not found!")
    exit()
f_out_name=f_in_name + ".csv"

#build XML structure object
tree = ET.parse(f_in_name)
root = tree.getroot()

print("building policies table")
#setup reference point in configuration of Pao Alto XML config file where to find policies
for item in root.findall("./result/config/devices/entry/vsys/entry/rulebase/security/rules/entry"):
    temp_policy=copy.deepcopy(policy)

    temp_policy['policy-name']=item.get('name')
    #grab details of the policy    
    for element in item.findall("./from/member"):
        temp_policy['from-zone'].append(element.text)
    for element in item.findall("./to/member"):
        temp_policy['to-zone'].append(element.text)
    for element in item.findall("./source/member"):
        temp_policy['source-address'].append(element.text)
    for element in item.findall("./destination/member"):
        temp_policy['destination-address'].append(element.text)
    for element in item.findall("./service/member"):
        temp_policy['application'].append(element.text)
    for element in item.findall("./application/member"):
        temp_policy['application-name'].append(element.text)
    for element in item.findall("./category/member"):
        temp_policy['category'].append(element.text)
    for element in item.findall("./tag/member"):
        temp_policy['tag'].append(element.text)
    for element in item.findall("./description"):
        temp_policy['description'].append(element.text)
    for element in item.findall("./action"):
        temp_policy['action'].append(element.text)
    policies_set.append(temp_policy)


#handle the additional and optional parameters
#replace the custom named addresses with what was defined in the address book
if vars(a1)["address"]:
    process_addresses(root)
    replace_addresses()
#replace the custom named services with wht was defined in the service address book
if vars(a1)["service"]:
    process_services(root)
    services_replace()

#write the content of the policies_set to the CSV file
with open(f_out_name,"w",newline='') as f:
    csv_writer = csv.DictWriter(f,fieldnames=policy_description,delimiter=';')
    csv_writer.writeheader()
    csv_writer.writerows(policies_set)
