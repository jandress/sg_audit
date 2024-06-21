#!/usr/bin/env python3

import boto3
from botocore.exceptions import NoCredentialsError, PartialCredentialsError
import configparser
import os
import csv
import datetime
import socket 

def get_ec2_instances(ec2):
#get the ec2 instances and their associated info
    print("in get_ec2_instances")
    found_instances = {}
    instance_public_ips = {}
    instance_private_ips = {}
    instance_ident = {}
    instance_tags = {}
    #just get the instances that are running
    instances = ec2.instances.filter(Filters=[{'Name': 'instance-state-name', 'Values': ['running'] }])
 
    #loop through the instances we found and get info on them
    for instance in instances:
        if instance.tags:
            for i in range(len(instance.tags)):
                if instance.tags[i]['Key'] == "Name":
                    instance_name = instance.tags[i]['Value']
        else:
            instance_name = "unknown"
        if instance.tags:
           instance_tags = ""
           for tag in instance.tags:
              tag_key = tag['Key']
              tag_value = tag['Value']
              tag_info = tag_key+": "+tag_value+", "
              instance_tags += tag_info
        else:
           instance_tags = "no tags found"
        instance_ident[instance.id] = instance_name
        values=[]
        for i in range(len(instance.security_groups)):
            values.append(instance.security_groups[i]['GroupId'])
            found_instances[instance.id] = values
            instance_public_ips[instance.id] = instance.public_ip_address
            instance_private_ips[instance.id] = instance.private_ip_address
    return (found_instances, instance_public_ips,instance_private_ips, instance_ident, instance_tags)
 
def inspect_security_group(ec2, sg_id):
#look at the security groups for ports open to the internet
    #print("in inspect_security_group")
    sg = ec2.SecurityGroup(sg_id)
    #print("security group = "+str(sg))
 
    open_cidrs = []
    for i in range(len(sg.ip_permissions)):
        to_port = ''
        ip_proto = ''
        if 'ToPort' in sg.ip_permissions[i]:
            to_port = sg.ip_permissions[i]['ToPort']
            #print("to_port = "+str(to_port))
            if '-1' in str(to_port):
                protocol = "All"
            else:
                try:
                    protocol = socket.getservbyport(to_port)
                except socket.error:
                    protocol = "unknown"
        else:
            protocol = ""
        #print("protocol = "+protocol)
        if 'IpProtocol' in sg.ip_permissions[i]:
            ip_proto = sg.ip_permissions[i]['IpProtocol']
            if '-1' in ip_proto:
                ip_proto = 'All'
        for j in range(len(sg.ip_permissions[i]['IpRanges'])):
            #cidr_string = "%s %s %s" % (sg.ip_permissions[i]['IpRanges'][j]['CidrIp'], ip_proto, to_port)
            cidr_string = ip_proto+" "+str(to_port)+"("+protocol+")"
 
            if sg.ip_permissions[i]['IpRanges'][j]['CidrIp'] == '0.0.0.0/0':
                #preventing an instance being flagged for only ICMP being open
                if ip_proto != 'icmp':
                    open_cidrs.append(cidr_string)
 
    return open_cidrs
 
def dump_to_csv(instance_list):
#dump out everything we found to a csv
  print("in dump_to_csv")
  list_length = len(instance_list[0])
  d = datetime.datetime.now()
  timestamp = str(d.date())
  filename = "sg_audit_"+timestamp+".csv" #output filename
  with open(filename, 'w') as instance_file:
        writer = csv.writer(instance_file, lineterminator='\n')
        #csv header row
        writer.writerow(['Account', 'Account ID','Region', 'Instance ID','Internal IP','External IP','Name','Tags','Security Group','Ports open to Internet'])
        for instance in instance_list:
           writer.writerow(instance)

if __name__ == "__main__":
    print("in main")
    #AWS credentials file goes here, this assumes the currently running user
    configdir = os.path.expandvars('/home/$USER/.aws/credentials')
    #print("configdir = "+configdir)

    staticregion = 'us-east-1'
    instance_list = []

    #read in the sections from the credentials file
    config = configparser.ConfigParser()
    config.read(configdir)

    #loop through each section in the credentials file - this allows us to search through multiple AWS accounts
    for section in config.sections():
        session = boto3.Session(profile_name=section)
        client = session.client('ec2', region_name = staticregion) #for getting the ec2 info
        stsclient = session.client('sts', region_name = staticregion) #for getting the account id
        iamclient = session.client('iam', region_name = staticregion) #for getting the account alias

        regions = [region['RegionName'] for region in client.describe_regions()['Regions']]

        for region in regions:
            account_id = stsclient.get_caller_identity()["Account"]
            #using account alias here is potentially less truthy than account name, but requires lesser permissions to get
            #this will still barf if user on the aws does not have IAM rights
            try:
               account_alias = iamclient.list_account_aliases()['AccountAliases'][0]
            except IndexError: #we'll get an index error if no alias is set
               account_alias = "no alias set" 
            print("Checking "+account_alias+" ("+account_id+")"+" "+region+" ")
            ec2 = session.resource('ec2', region_name = region)
            (ec2_instances, instance_public_ips, instance_private_ips, instance_ident, instance_tags) = get_ec2_instances(ec2)

            for instance in ec2_instances:
               for sg_id in ec2_instances[instance]:
                  open_cidrs = inspect_security_group(ec2, sg_id)
                  if open_cidrs: #only print if there are open cidrs
                     instance_info = account_alias, account_id, region, instance, instance_private_ips[instance], instance_public_ips[instance], instance_ident[instance], instance_tags, sg_id, open_cidrs
                     print(instance_info)
                     instance_list.append(instance_info)

    dump_to_csv(instance_list)
