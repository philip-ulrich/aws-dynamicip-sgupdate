# takes a list of hostnames and adds them to a security group(s) 

import boto3
import botocore
import dns.resolver
import json
import logging

ec2 = boto3.resource('ec2')
with open('config.json','r') as fin:
    config = json.load(fin)

logging.basicConfig(format='%(asctime)s - [%(levelname)s] - (%(name)s) %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p', level=logging.INFO)

def ResolveIP(hostnames,version):
    ipv4 = []
    ipv6 = []
    if version == 'ipv4':
        try: 
            for hostname in hostnames:
                for ip in dns.resolver.query(hostname, 'A') :
                    ipv4.append(str(ip))
        except dns.resolver.NoAnswer:
            logging.info('No "A" record found for domain {}'.format(hostname))
        except dns.resolver.NXDOMAIN:
            logging.info('No records found for domain {}'.format(hostname))

        return ipv4

    if version == 'ipv6':
        try:
            for hostname in hostnames:
                for ip in dns.resolver.query(hostname, 'AAAA') :
                    ipv6.append(str(ip))
        except dns.resolver.NoAnswer:
            logging.debug('No "AAAA" record found for domain {}'.format(hostname))
        except dns.resolver.NXDOMAIN:
            logging.debug('No records found for domain {}'.format(hostname))
        
        return ipv6

def AddRule(sgid,ip,version,fromport,toport,proto,direction):
    security_group = ec2.SecurityGroup('sgid')
    if direction == 'ingress':
        if version == 'ipv4':
            response = security_group.authorize_ingress(CidrIp=ip+'/32', FromPort=fromport, GroupId=sgid, IpProtocol=proto, ToPort=toport)
        if version == 'ipv6':
            response = security_group.authorize_ingress(CidrIpv6=ip, FromPort=fromport, GroupId=sgid, IpProtocol=proto, ToPort=toport)
    if direction == 'egress':
        if version == 'ipv4':
            response = security_group.authorize_egress(CidrIp=ip+'/32', FromPort=fromport, GroupId=sgid, IpProtocol=proto, ToPort=toport)
        if version == 'ipv6':
            response = security_group.authorize_egress(CidrIpv6=ip, FromPort=fromport, GroupId=sgid, IpProtocol=proto, ToPort=toport)
            
def main():
    ipv4, ipv6 = ResolveIP(config['hostnames'],'ipv4'), ResolveIP(config['hostnames'],'ipv6')
    try:
        for ip in ipv4:
            for rule in config['rules']:
                AddRule(rule['sgid'],ip,'ipv4',rule['fromport'],rule['toport'],rule['proto'],rule['direction'])
        for ip in ipv6:
            for rule in config['rules']:
                AddRule(rule['sgid'],ip,'ipv6',rule['fromport'],rule['toport'],rule['proto'],rule['direction'])
    except botocore.exceptions.ClientError as e:
        if "InvalidPermission.Duplicate" in str(e):
            logging.info("The following rule was attempted to be added, but already exists:\n{}".format(rule))
        else:
            logging.error(str(e))

if __name__ == '__main__':
    main()