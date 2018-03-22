 #! /usr/bin/env python
from __future__ import print_function
from multiprocessing import Process
from multiprocessing import Pool
from multiprocessing.dummy import Pool as ThreadPool
import csv,glob
import boto3
import os
import argparse
import json
import subprocess
import time
from IPy import IP
from getpass import getpass
import webbrowser


def get_account_alias():
    account_details = subprocess.check_output(['aws', 'iam', 'list-account-aliases'])
    account_details = json.loads(str(account_details))
    try:
        return account_details['AccountAliases'][0]
    except IndexError:
        return None


def get_account_id():
    caller_identity = subprocess.check_output(['aws', 'sts', 'get-caller-identity'])
    caller_identity = json.loads(str(caller_identity))
    try:
        return caller_identity['Account']
    except IndexError:
        return None


account_name = get_account_alias() or get_account_id()
timestmp = time.strftime("%Y%m%d-%H%M%S")
script_json = {}
script_json['account_info']={'aws-cli_profile':['default']}
script_json['account_info'].update({'date':timestmp})
script_json['account_info'].update({'aws_api_region':['us-east-1']})
script_json['account_info'].update({'aws_filter_region':['all']})
identity = subprocess.check_output(['aws', 'sts', 'get-caller-identity'])
identity = json.loads(str(identity))
script_json['account_info'].update({'caller_identity':identity})

def prowler(check):
    """ this function calls the prowler script """
    file_name = check
    with open('tools/prowler/%s.csv' %(check), 'w') as output:
        subprocess.call(['./prowler', '-M', 'csv', '-c', check], stdout=output, cwd='tools/prowler')
    
    csvfile = open('tools/prowler/%s.csv' %(check), 'r')
    jsonfile = open('tools/prowler/%s.json' %(check), 'w')
    fieldnames = ("aws-cli_profile", "account", "region", "check_no", "type", "score", "level", "check", "value")
    reader = csv.DictReader( csvfile, fieldnames)
    for row in reader:
        json.dump(row, jsonfile)
        jsonfile.write('\n')
    return 0

def multi_threaded_prowler():
    """ this function using multi-threading for prowler """
    checks = ['check13','check14', 'check15', 'check16', 'check17', 'check18', 'check19', 'check114', 'check115','check116', 'check118', 'check122', 'check123', 'check124', 'check21', 'check23', 'check24', 'check25', 'check26', 'check27', 'check28', 'check31','check32','check33','check34','check35','check36','check37','check38','check39', 'check310','check311','check312','check313','check314','check315','check43','check44','check45']
    #checks=['check14']
    p = Pool(5)
    p.map(prowler, checks)
    final_json = {}
    final_json['account_info']={'aws-cli_profile':['default']}
    final_json['account_info'].update({'date':timestmp})
    final_json['account_info'].update({'aws_api_region':['us-east-1']})
    final_json['account_info'].update({'aws_filter_region':['all']})
    identity = subprocess.check_output(['aws', 'sts', 'get-caller-identity'])
    identity = json.loads(str(identity))
    final_json['account_info'].update({'caller_identity':identity})
    report = []
    for check in checks:
        dict = {}
        data = []
        with open('tools/prowler/%s.json' %check, 'r') as f:
            for line in f:
                new_dict={}
                j = json.loads(line)
                dict['check'] =j['check']
                new_dict['check_no']=j['check_no']
                new_dict['score']=j['score']
                new_dict['level']=j['level']
                new_dict['type']=j['type']
                new_dict['region']=j['region']
                new_dict['value']=j['value']
                data.append(new_dict)
        dict['data']=data
        report.append(dict)
        final_json['report']=report
    for f in glob.glob("./tools/prowler/check*"):
        os.remove(f)
    with open('tools/prowler/final_json', 'w') as f:
         f.write(json.dumps(final_json))
    print ("Prowler Audit Done")
    return 0

def scout2():
    """ this function calls Scout2 tool """
    print ("Started Scout2")
    file_name = 'scout2_report'
    subprocess.call(['python', 'Scout2.py', '--no-browser', '--report-dir', '../../reports/AWS/aws_audit/%s/%s/%s' %(account_name, timestmp, file_name) ], cwd='tools/Scout2')
    print ("Scout2 Audit done")
    return 0

def csv_to_json(file):
    csvfile = open(file,'r')
    jsonfile = open('%s.json' %(file), 'w')
    fieldnames = ("aws-cli_profile", "account", "region", "check_no", "type", "score", "level", "check", "value")
    reader = csv.DictReader( csvfile, fieldnames)
    for row in reader:
        json.dump(row, jsonfile)
        jsonfile.write('\n')
    return 0
'''
def aws_security_test():
    """ this function runs aws_security_test tool """
    print ("Started aws_security_test")
    file_name = 'aws_security_test_report'
    with open('reports/aws_audit/%s/%s/delta/%s' % (account_name, timestmp, file_name), 'w') as output:
        subprocess.check_output(['python' ,'aws_security_test.py', '-c' ,'config/default.yml'], stderr=subprocess.DEVNULL, cwd='tools/aws-security-test')
    print ("aws_security_test Audit done")
    return 0
'''

def audit_aws_certs():
    """  this function audits AWS certs """
    print ("Started AWS cert audit")
    with open('reports/AWS/aws_audit/%s/%s/delta/certs' % (account_name, timestmp), 'w') as output:
        subprocess.call(['python', './scripts/audit_aws_certs.py'], stdout=output)
        if os.stat('reports/AWS/aws_audit/%s/%s/delta/certs' %(account_name, timestmp)).st_size == 0:
            output.write("default,account,null,null,INFO,scored,null,CERT_AUDIT,No information is available\n")
    csv_to_json('reports/AWS/aws_audit/%s/%s/delta/certs' % (account_name, timestmp))
    print ("Cert Audit Done")
    exit (0)
    return 0

def audit_aws_cf():
    """ this function is to audit Cloud Formation """
    print ("Started Cloud Formation Audit ")
    with open('reports/AWS/aws_audit/%s/%s/delta/cloud_formation' % (account_name, timestmp), 'w') as output:
        subprocess.call(['./scripts/audit_aws_cloud_formation.sh'], stdout=output)
        if os.stat('reports/AWS/aws_audit/%s/%s/delta/cloud_formation' %(account_name, timestmp)).st_size == 0:
            output.write("default,account,null,null,INFO,scored,null,CLOUD_FORMATION_AUDIT,No information is available")
    csv_to_json('reports/AWS/aws_audit/%s/%s/delta/cloud_formation' % (account_name, timestmp))
    print ("Cloud Formation Audit Done")
    return 0


def audit_aws_config():
    """ this function is to audit AWS config """
    print ("Started AWS config Audit ")
    with open('reports/AWS/aws_audit/%s/%s/delta/aws_config' % (account_name, timestmp), 'w') as output:
        subprocess.call(['./scripts/audit_aws_config.sh'], stdout=output)
        if os.stat('reports/AWS/aws_audit/%s/%s/delta/aws_config' %(account_name, timestmp)).st_size == 0:
            output.write("default,account,null,null,INFO,scored,null,CONFIG_AUDIT,No information is available")
    csv_to_json('reports/AWS/aws_audit/%s/%s/delta/aws_config' % (account_name, timestmp))
    print ("AWS config Audit Done")
    return 0


def audit_aws_dns():
    """ this function is to DNS """
    print ("Started AWS DNS Audit ")
    with open('reports/AWS/aws_audit/%s/%s/delta/dns' % (account_name, timestmp), 'w') as output:
        subprocess.call(['./scripts/audit_aws_dns.sh'], stdout=output)
        if os.stat('reports/AWS/aws_audit/%s/%s/delta/dns' %(account_name, timestmp)).st_size == 0:
            output.write("default,account,null,null,INFO,scored,null,DNS_AUDIT,No information is available")
    csv_to_json('reports/AWS/aws_audit/%s/%s/delta/dns' % (account_name, timestmp))
    print ("AWS DNS Audit Done")
    return 0


def audit_aws_ec():
    """ this function is to audit Elastic Cache """
    print ("Started AWS Elastic Cache Audit ")
    with open('reports/AWS/aws_audit/%s/%s/delta/ec' % (account_name, timestmp), 'w') as output:
        subprocess.call(['./scripts/audit_aws_ec.sh'], stdout=output)
        if os.stat('reports/AWS/aws_audit/%s/%s/delta/ec' %(account_name, timestmp)).st_size == 0:
            output.write("default,account,null,null,INFO,scored,null,ELASTIC_CACHE_AUDIT,No information is available")
    csv_to_json('reports/AWS/aws_audit/%s/%s/delta/ec' % (account_name, timestmp))
    print ("AWS Elastic Cache Audit Done ")
    return 0


def audit_aws_ec2():
    """ this function is to audit Instances """
    print ("Started AWS Instances Audit ")
    with open('reports/AWS/aws_audit/%s/%s/delta/ec2' % (account_name, timestmp), 'w') as output:
        subprocess.call(['./scripts/audit_aws_ec2.sh'], stdout=output)
        if os.stat('reports/AWS/aws_audit/%s/%s/delta/ec2' %(account_name, timestmp)).st_size == 0:
            output.write("default,account,null,null,INFO,scored,null,EC2_AUDIT,No information is available")
    csv_to_json('reports/AWS/aws_audit/%s/%s/delta/ec2' % (account_name, timestmp))
    print ("AWS Instances Audit Done ")
    return 0


def audit_aws_elb():
    """ this function is to audit Instances """
    print ("Started AWS Load-Balancer Audit ")
    with open('reports/AWS/aws_audit/%s/%s/delta/elb' % (account_name, timestmp), 'w') as output:
        subprocess.call(['./scripts/audit_aws_elb.sh'], stdout=output)
        if os.stat('reports/AWS/aws_audit/%s/%s/delta/elb' %(account_name, timestmp)).st_size == 0:
            output.write("default,account,null,null,INFO,scored,null,ELB_AUDIT,No information is available")
    csv_to_json('reports/AWS/aws_audit/%s/%s/delta/elb' % (account_name, timestmp))
    print ("AWS Load-Balancer Audit Done ")
    return 0


def audit_aws_es():
    """ this function is to audit Instances """
    print ("Started AWS Elastic-Search Audit ")
    with open('reports/AWS/aws_audit/%s/%s/delta/es' % (account_name, timestmp), 'w') as output:
        subprocess.call(['./scripts/audit_aws_es.sh'], stdout=output)
        if os.stat('reports/AWS/aws_audit/%s/%s/delta/es' %(account_name, timestmp)).st_size == 0:
            output.write("default,account,null,null,INFO,scored,null,ELASTIC_SEARCH_AUDIT,No information is available")
    csv_to_json('reports/AWS/aws_audit/%s/%s/delta/es' % (account_name, timestmp))
    print ("AWS Elastic-Search Audit Done ")
    return 0


def audit_aws_keys():
    """ this function is to audit Instances """
    print ("Started AWS SSH Audit ")
    with open('reports/AWS/aws_audit/%s/%s/delta/keys' % (account_name, timestmp), 'w') as output:
        subprocess.call(['./scripts/audit_aws_keys.sh'], stdout=output)
        if os.stat('reports/AWS/aws_audit/%s/%s/delta/keys' %(account_name, timestmp)).st_size == 0:
            output.write("default,account,null,null,INFO,scored,null,AWS_KEY_AUDIT,No information is available")
    csv_to_json('reports/AWS/aws_audit/%s/%s/delta/keys' % (account_name, timestmp))
    print ("AWS SSH Audit Done ")
    return 0


def audit_aws_rds():
    """ this function is to audit Instances """
    print ("Started AWS RDS Audit ")
    with open('reports/AWS/aws_audit/%s/%s/delta/rds' % (account_name, timestmp), 'w') as output:
        subprocess.call(['./scripts/audit_aws_rds.sh'], stdout=output)
        if os.stat('reports/AWS/aws_audit/%s/%s/delta/rds' %(account_name, timestmp)).st_size == 0:
            output.write("default,account,null,null,INFO,scored,null,RDS_AUDIT,No information is available")
    print ("AWS RDS Audit Done ")
    csv_to_json('reports/AWS/aws_audit/%s/%s/delta/rds' % (account_name, timestmp))
    return 0


def audit_aws_redshift():
    """ this function is to audit Instances """
    print ("Started AWS Redshift Audit ")
    with open('reports/AWS/aws_audit/%s/%s/delta/redshift' % (account_name, timestmp), 'w') as output:
        subprocess.call(['./scripts/audit_aws_redshift.sh'], stdout=output)
        if os.stat('reports/AWS/aws_audit/%s/%s/delta/redshift' %(account_name, timestmp)).st_size == 0:
            output.write("default,account,null,null,INFO,scored,null,REDSHIFT_AUDIT,No information is available")
    csv_to_json('reports/AWS/aws_audit/%s/%s/delta/redshift' % (account_name, timestmp))
    print ("AWS Redshift Audit Done ")
    return 0


def audit_aws_ses():
    """ this function is to audit Instances """
    print ("Started AWS SES Audit ")
    with open('reports/AWS/aws_audit/%s/%s/delta/ses' % (account_name, timestmp), 'w') as output:
        subprocess.call(['./scripts/audit_aws_ses.sh'], stdout=output)
        if os.stat('reports/AWS/aws_audit/%s/%s/delta/ses' %(account_name, timestmp)).st_size == 0:
            output.write("default,account,null,null,INFO,scored,null,SES_AUDIT,No information is available")
    csv_to_json('reports/AWS/aws_audit/%s/%s/delta/ses' % (account_name, timestmp))
    print ("AWS SES Audit Done ")
    return 0


def audit_aws_cdn():
    """ this function is to audit Instances """
    print ("Started AWS CDN Audit ")
    with open('reports/AWS/aws_audit/%s/%s/delta/cdn' % (account_name, timestmp), 'w') as output:
        subprocess.call(['./scripts/aws_cdn_audit.sh'], stdout=output)
        if os.stat('reports/AWS/aws_audit/%s/%s/delta/cdn' %(account_name, timestmp)).st_size == 0:
            output.write("default,account,null,null,INFO,scored,null,CDN_AUDIT,No information is available")
    csv_to_json('reports/AWS/aws_audit/%s/%s/delta/cdn' % (account_name, timestmp))
    print ("AWS CDN Audit Done ")
    return 0


def audit_aws_sns():
    """ this function is to audit Instances """
    print ("Started AWS SNS Audit ")
    with open('reports/AWS/aws_audit/%s/%s/delta/sns' % (account_name, timestmp), 'w') as output:
        subprocess.call(['./scripts/audit_aws_sns.sh'], stdout=output)
        if os.stat('reports/AWS/aws_audit/%s/%s/delta/sns' %(account_name, timestmp)).st_size == 0:
            output.write("default,account,null,null,INFO,scored,null,SNS_AUDIT,No information is available")
    csv_to_json('reports/AWS/aws_audit/%s/%s/delta/sns' % (account_name, timestmp))
    print ("AWS SNS Audit Done ")
    return 0


def audit_aws_vpcs():
    """ this function is to audit Instances """
    print ("Started AWS VPC Audit ")
    with open('reports/AWS/aws_audit/%s/%s/delta/vpc' % (account_name, timestmp), 'w') as output:
        subprocess.call(['./scripts/audit_aws_vpcs.sh'], stdout=output)
        if os.stat('reports/AWS/aws_audit/%s/%s/delta/vpc' %(account_name, timestmp)).st_size == 0:
            output.write("default,account,null,null,INFO,scored,null,VPC_AUDIT,No information is available")
    csv_to_json('reports/AWS/aws_audit/%s/%s/delta/vpc' % (account_name, timestmp))
    print ("AWS VPC Audit Done ")
    return 0

def trusted_advisor():
    with open('reports/AWS/aws_audit/%s/%s/final_report/trusted' %(account_name, timestmp),'w') as f:
        account_id = subprocess.check_output(['aws sts get-caller-identity --output text --query "Account"'], shell=True).strip()
        client = boto3.client('support', region_name='us-east-1')
        checks={'DqdJqYeRm5':'Security Groups - Specific Ports Unrestricted', 'BueAdJ7NrP':'Amazon S3 Bucket Logging', 'HCP4007jGY':'Security Groups - Specific Ports Unrestricted','1iG5NDGVre':'Security Groups - Unrestricted Access', 'a2sEc6ILx':'ELB Listener Security', 'xSqX82fQu':'ELB Security Groups','R365s2Qddf':'Amazon S3 Bucket Versioning','xuy7H1avtl':'Amazon Aurora DB Instance Accessibility','zXCkfM1nI3':'IAM Use','7DAFEmoDos':'MFA on Root Account','Yw2K9puPzl':'IAM Password Policy','12Fnkpl8Y5':'Exposed Access Keys','N425c450f2':'CloudFront Custom SSL Certificates in the IAM Certificate Store','N430c450f2':'CloudFront SSL Certificate on the Origin Server','Pfx0RwqBli':'Amazon S3 Bucket Permissions','nNauJisYIT':'Amazon RDS Security Group Access Risk'}
        for check in checks.keys():
            response = client.describe_trusted_advisor_check_result(checkId=check,language='en' )
            if response['result']['flaggedResources']:
                for i in response['result']['flaggedResources']:
                    if 'metadata' in i:
                        if check in ['N425c450f2','N430c450f2','Pfx0RwqBli','nNauJisYIT']:
                             f.write("default,%s,null,null,%s,Scored,null,%s,%s\n" % (account_id,i['status'],checks[check],i['metadata'][2]))
                        elif check in ['vjafUGJ9H0']:
                             f.write("default,%s,null,null,%s,Scored,null,%s,%s\n" % (account_id,i['status'],checks[check],i['metadata'][3]))
                        else:
                            f.write("default,%s,null,null,%s,Scored,null,%s,%s\n" % (account_id,i['status'],checks[check],i['metadata'][1]))
            else:
                f.write("default,%s,null,null,%s,Scored,null,%s,%s\n" % (account_id,response['result']['status'],checks[check],response['result']['status']))
    csv_to_json('reports/AWS/aws_audit/%s/%s/final_report/trusted' %(account_name, timestmp))
    trusted_advisor_to_json()
    
def trusted_advisor_to_json():
    data=[]
    with open('reports/AWS/aws_audit/%s/%s/final_report/trusted.json' %(account_name, timestmp), 'r') as f:
         for line in f:
             k = json.loads(line)
             data.append(k['check'])
    data=set(data)

    for i in data:
        with open ('reports/AWS/aws_audit/%s/%s/final_report/%s.txt' %(account_name, timestmp,i), 'w+') as f:
            with open('reports/AWS/aws_audit/%s/%s/final_report/trusted.json' %(account_name, timestmp), 'r') as j:
                for line in j:
                    k = json.loads(line)
                    if k['check']==i:
                        f.write(line)
    final_json={}
    report = []
    for f in glob.glob("reports/AWS/aws_audit/%s/%s/final_report/*.txt" %(account_name, timestmp)):
        dict = {}
        data = []
        with open(f, 'r') as g:
             for line in g:
                 new_dict={}
                 j = json.loads(line)
                 dict['check'] =j['check']
                 new_dict['check_no']=j['check_no']
                 new_dict['score']=j['score']
                 new_dict['level']=j['level']
                 new_dict['type']=j['type']
                 new_dict['region']=j['region']
                 new_dict['value']=j['value']
                 data.append(new_dict)
        dict['data']=data
        report.append(dict)
        final_json['report']=report
    with open('reports/AWS/aws_audit/%s/%s/final_report/final_json' % (account_name, timestmp), 'w') as f:
         f.write(json.dumps(final_json))
    for f in glob.glob("reports/AWS/aws_audit/%s/%s/final_report/*.txt" %(account_name, timestmp)):
        os.remove(f)
    json_to_html_trusted()
    
       
def json_to_final_json():
    report = []
    for f in glob.glob("reports/AWS/aws_audit/%s/%s/delta/*.json" %(account_name, timestmp)):
        dict = {}
        data = []
        with open(f, 'r') as g:
             for line in g:
                 new_dict={}
                 j = json.loads(line)
                 dict['check'] =j['check']
                 new_dict['check_no']=j['check_no']
                 new_dict['score']=j['score']
                 new_dict['level']=j['level']
                 new_dict['type']=j['type']
                 new_dict['region']=j['region']
                 new_dict['value']=j['value']
                 data.append(new_dict)
        dict['data']=data
        report.append(dict)
        script_json['report']=report 
    with open('reports/AWS/aws_audit/%s/%s/delta/final_json' % (account_name, timestmp), 'w') as f:
         f.write(json.dumps(script_json))
    for i in script_json['report']:
        if i['check'] in ['CDN_AUDIT','CERT_AUDIT','DNS_AUDIT','ELB_AUDIT']:
            with open('reports/AWS/aws_audit/%s/%s/delta/webnet.json' % (account_name, timestmp), 'a+') as f:
                f.write(json.dumps(i))
                f.write('\n')
        elif i['check'] in ['ELASTIC_CACHE_AUDIT','ELASTIC_SEARCH_AUDIT','RDS_AUDIT','REDSHIFT_AUDIT']:
            with open('reports/AWS/aws_audit/%s/%s/delta/datastores.json' % (account_name, timestmp), 'a+') as f:
                f.write(json.dumps(i))
                f.write('\n')
        elif i['check'] in ['CLOUD_FORMATION_AUDIT','SES_AUDIT','SNS_AUDIT']:      
            with open('reports/AWS/aws_audit/%s/%s/delta/notification.json' % (account_name, timestmp), 'a+') as f:
                f.write(json.dumps(i))
                f.write('\n')
        else:
            with open('reports/AWS/aws_audit/%s/%s/delta/configs.json' % (account_name, timestmp), 'a+') as f:
                f.write(json.dumps(i))
                f.write('\n')

def json_to_html(file,new_file):
    with open(new_file, 'w') as f: 
        with open('./tools/prowler/template1.txt', 'r') as g:
            for line in g:
                f.write(line)
        with open(file, 'r') as json_data:
             for line in json_data:
                 line = str(line)
                 final=json.loads(line)
                 f.write('<div class="col-xs-6 col-sm-3 col-md-3 item">\n')
                 f.write('<div class="thumbnail">\n')
                 f.write('<div class="caption">\n')
                 flag=0
                 for g in final['data']:
                     if g['type'] == 'WARNING':
                         flag=1
                 if flag == 0:
                     f.write('<div class="grid" style="background-color: green;">') 
                 else:
                     f.write('<div class="grid" style="background-color: red;">')
                 f.write('<h5>%s</h5>\n' %(final['check']))
                 f.write('</div>')
                 for k in final['data']:
                     if k['type'] == 'WARNING':
                          f.write('<p><span style="color:red">Warning: </span>%s</p>\n' %(k['value']))
                     else:
                          f.write('<p>%s<p>\n' %(k['value']))
                 f.write('</div>')
                 f.write('</div>')
                 f.write('</div>')
        with open('./tools/prowler/template2.txt', 'r') as k:
             for line in k:
                 f.write(line) 

def json_to_html_prowler():
    with open('./reports/AWS/aws_audit/%s/%s/delta/prowler_report.html' % (account_name, timestmp), 'w') as f:
        with open('./tools/prowler/template1.txt', 'r') as g:
             for line in g:
                  f.write(line)
        with open('./tools/prowler/final_json', 'r') as json_data:
             final=json.load(json_data)
             for i in final['report']:
                  f.write('<div class="col-xs-6 col-sm-3 col-md-3 item">\n')
                  f.write('<div class="thumbnail">\n')
		  f.write('<div class="caption">\n')
                  flag=0
                  for g in i['data']:
                     if g['type'] == 'WARNING':
                         flag=1
                  if flag == 0:
                     f.write('<div class="grid" style="background-color: green;">')
                  else:
                     f.write('<div class="grid" style="background-color: red;">')
                  f.write('<h5>%s</h5>\n' %(i['check']))
                  f.write('</div>')
                  for k in i['data']:
                       if k['type'] == 'WARNING':
                           f.write('<p><span style="color:red">Warning: </span>%s</p>\n' %(k['value']))
                       else:
                           f.write('<p>%s</p>\n' %(k['value']))
                  f.write('</div>\n')
                  f.write('</div>\n')
                  f.write('</div>\n')
        with open('./tools/prowler/template2.txt', 'r') as k:
             for line in k:
                 f.write(line) 

def json_to_html_trusted():
    with open('./reports/AWS/aws_audit/%s/%s/final_report/trusted_advisor.html' % (account_name, timestmp), 'w') as f:
        with open('./tools/prowler/template1.txt', 'r') as g:
             for line in g:
                  f.write(line)
        with open('./reports/AWS/aws_audit/%s/%s/final_report/final_json' % (account_name, timestmp), 'r') as json_data:
             final=json.load(json_data)
             for i in final['report']:
                  f.write('<div class="col-xs-6 col-sm-3 col-md-3 item">\n')
                  f.write('<div class="thumbnail">\n')
                  f.write('<div class="caption">\n')
                  flag=0
                  for g in i['data']:
                     if g['type'] in ['warning', 'error']:
                         flag=1
                  if flag == 0:
                     f.write('<div class="grid" style="background-color: green;">')
                  else:
                     f.write('<div class="grid" style="background-color: red;">')
                  f.write('<h5>%s</h5>\n' %(i['check']))
                  f.write('</div>')
                  for k in i['data']:
                       if k['type'] in ['warning', 'error']:
                           f.write('<p><span style="color:red">Warning: </span>%s</p>\n' %(k['value']))
                       else:
                           f.write('<p>%s</p>\n' %(k['value']))
                  f.write('</div>\n')
                  f.write('</div>\n')
                  f.write('</div>\n')
        with open('./tools/prowler/template2.txt', 'r') as k:
             for line in k:
                 f.write(line)

def merge_json():
    with open('reports/AWS/aws_audit/%s/%s/delta/final_json' % (account_name, timestmp), 'r') as f:
         for line in f:
              j1=json.loads(line)
    with open('./tools/prowler/final_json' ,'r') as k:
         for line in k:
             j2=json.loads(line)
   
    j1['report'].append(j2['report'])
    with open('reports/AWS/aws_audit/%s/%s/delta/final_json' %(account_name, timestmp), 'w') as f:
         f.write(json.dumps(j1))
    os.remove('./tools/prowler/final_json')
         
def main():
    """ main function """
    parser = argparse.ArgumentParser(description='this is to get IP address for lynis audit only')
    parser.add_argument('-aip','--audit_ip', help='The IP for which lynis Audit needs to be done .... by default tries root/Administrator if username not provided')
    parser.add_argument('-u','--user_name', help='The username of the user to be logged in,for a specific user')
    parser.add_argument('-pem','--pem_file', help='The pem file to access to AWS instance')
    parser.add_argument('-p', '--password', action='store_true', dest='password', help='hidden password prompt')
    parser.add_argument('-env', '--environment', help='The cloud on which the test-suite is to be run', choices=['aws','gcp'])
    parser.add_argument('-pId', '--project_name', help='Project Name for which GCP Audit needs to be run')
    args = parser.parse_args()
    if args.password:
        password = getpass()

    if (args.audit_ip):
        ip = IP(args.audit_ip)
        type = ip.iptype()
        default_region = subprocess.check_output(['aws', 'configure', 'get', 'region']).strip()
        if type == 'PUBLIC':
            operating_sys = subprocess.check_output(['aws', 'ec2', 'describe-instances', '--region', '%s' %default_region, '--filters', 'Name=ip-address,Values=%s' %(args.audit_ip), '--query', 'Reservations[*].Instances[*].[Platform]', '--output', 'text']).strip()
            private_ip = subprocess.check_output(['aws', 'ec2', 'describe-instances', '--region', '%s' %default_region, '--filters', 'Name=ip-address,Values=%s' %(args.audit_ip), '--query', 'Reservations[*].Instances[*].[PrivateIpAddress]', '--output', 'text']).strip()
            public_ip = args.audit_ip
        elif type == 'PRIVATE':
            operating_sys = subprocess.check_output(['aws', 'ec2', 'describe-instances', '--region', '%s' %default_region, '--filters', 'Name=network-interface.addresses.private-ip-address,Values=%s' %(args.audit_ip), '--query', 'Reservations[*].Instances[*].[Platform]', '--output', 'text']).strip()
            public_ip = subprocess.check_output(['aws', 'ec2', 'describe-instances', '--region', '%s' %default_region, '--filters', 'Name=network-interface.addresses.private-ip-address,Values=%s' %(args.audit_ip), '--query', 'Reservations[*].Instances[*].[PublicIpAddress]', '--output', 'text']).strip()
            private_ip = args.audit_ip
        if public_ip=='None':
           public_ip=""
        else:
            dns_name = subprocess.check_output(['host', public_ip]).strip().split(' ')[4]

        if operating_sys=='windows':
            print ("WINDOWS BOX FOUND!!!")
            if (args.audit_ip and not(args.user_name or args.pem_file or args.password)):
                subprocess.call(['./windows_remote.sh', account_name, dns_name, private_ip, public_ip], cwd='tools/Windows-Workstation-and-Server-Audit')
            elif args.audit_ip and args.user_name and not(args.pem_file or args.password):
                subprocess.call(['./windows_remote.sh', account_name, dns_name, private_ip, public_ip, args.user_name], cwd='tools/Windows-Workstation-and-Server-Audit')
            elif args.audit_ip and args.pem_file and not(args.user_name or args.password):
                subprocess.call(['./windows_remote.sh', account_name, dns_name, private_ip, public_ip, "", args.pem_file], cwd='tools/Windows-Workstation-and-Server-Audit')
            elif args.audit_ip and args.password and not(args.user_name or args.pem_file):
                subprocess.call(['./windows_remote.sh', account_name, dns_name, private_ip, public_ip, "", "", password],  cwd='tools/Windows-Workstation-and-Server-Audit')
            elif args.audit_ip and args.user_name and args.password and not(args.pem_file):
                subprocess.call(['./windows_remote.sh', account_name, dns_name, private_ip, public_ip, args.user_name, "", password],  cwd='tools/Windows-Workstation-and-Server-Audit')
            elif args.audit_ip and args.user_name and args.pem_file and not(args.password):
                subprocess.call(['./windows_remote.sh', account_name, dns_name, private_ip, public_ip, args.user_name, args.pem_file],  cwd='tools/Windows-Workstation-and-Server-Audit')
            elif args.audit_ip and args.password and args.pem_file and not(args.password):
                subprocess.call(['./windows_remote.sh', account_name, dns_name, private_ip, public_ip, "", args.pem_file, password], cwd='tools/Windows-Workstation-and-Server-Audit')
            else:
                subprocess.call(['./windows_remote.sh', account_name, dns_name, private_ip, public_ip, args.user_name, args.pem_file, password], cwd='tools/Windows-Workstation-and-Server-Audit')
        else:
            print ("LINUX BOX FOUND!!!")
            if (args.audit_ip and not(args.user_name or args.pem_file or args.password)):
                subprocess.call(['./lynis_remote.sh', account_name, dns_name, private_ip, public_ip], cwd='tools/lynis')
            elif args.audit_ip and args.user_name and not(args.pem_file or args.password):
                subprocess.call(['./lynis_remote.sh', account_name, dns_name, private_ip, public_ip, args.user_name], cwd='tools/lynis')
            elif args.audit_ip and args.pem_file and not(args.user_name or args.password):
                subprocess.call(['./lynis_remote.sh', account_name, dns_name, private_ip, public_ip, "", args.pem_file], cwd='tools/lynis')
            elif args.audit_ip and args.password and not(args.user_name or args.pem_file):
                subprocess.call(['./lynis_remote.sh', account_name, dns_name, private_ip, public_ip, "", "", password],  cwd='tools/lynis')
            elif args.audit_ip and args.user_name and args.password and not(args.pem_file):
                subprocess.call(['./lynis_remote.sh', account_name, dns_name, private_ip, public_ip, args.user_name, "", password],  cwd='tools/lynis')
            elif args.audit_ip and args.user_name and args.pem_file and not(args.password):
                subprocess.call(['./lynis_remote.sh', account_name, dns_name, private_ip, public_ip, args.user_name, args.pem_file, ""],  cwd='tools/lynis')
            elif args.audit_ip and args.password and args.pem_file and not(args.password):
                subprocess.call(['./lynis_remote.sh', account_name, dns_name, private_ip, public_ip, "", args.pem_file, password], cwd='tools/lynis')
            else:
                subprocess.call(['./lynis_remote.sh', account_name, dns_name, private_ip, public_ip, args.user_name, args.pem_file, password], cwd='tools/lynis')

    elif args.environment == 'gcp':
        if not args.project_name:
            print ("Please pass project name for the GCP Audit")
            print ("Exiting !!!")
            exit (0)
        else:
            subprocess.call(['mkdir', '-p', 'reports/GCP/%s/%s' %(args.project_name, timestmp)])
            print ("Starting GCP Audit")
            subprocess.call(['python', 'gscout.py', 'project', args.project_name], cwd='tools/G-Scout')
            if os.path.exists("tools/G-Scout/Report Output/%s" %(args.project_name)):
                project_directory = args.project_name + timestmp
                subprocess.check_output(['mv tools/G-Scout/Report\ Output/%s/* reports/GCP/%s/%s/' %(args.project_name, args.project_name, timestmp)], shell=True)
                subprocess.check_output(['rm -rf tools/G-Scout/Report\ Output/%s' %(args.project_name)], shell=True)
                webbrowser.open('file://'+os.path.realpath("./reports/GCP/%s/%s/All Ports Open to All.html") %(args.project_name, timestmp))
                fin = os.path.realpath("./reports/GCP/%s/%s/All\ Ports\ Open\ to\ All.html") %(args.project_name, timestmp)
                print ("THE FINAL REPORT IS LOCATED AT -------->  %s" % (fin))
                

    elif args.environment == 'aws':
        subprocess.call(['mkdir', '-p', 'reports/AWS/aws_audit/%s/%s/final_report' %(account_name, timestmp)])
        subprocess.call(['mkdir', '-p', 'reports/AWS/aws_audit/%s/%s/delta' %(account_name, timestmp)])
        p1 = Process(target=multi_threaded_prowler)
        p1.start()
        print ("Started Prowler")
        p2 = Process(target=scout2)
        p2.start()
        p4 = Process(target=audit_aws_certs)
        p4.start()
        p5 = Process(target=audit_aws_cf)
        p5.start()
        p6 = Process(target=audit_aws_config)
        p6.start()
        p7 = Process(target=audit_aws_dns)
        p7.start()
        p8 = Process(target=audit_aws_ec)
        p8.start()
        p9 = Process(target=audit_aws_ec2)
        p9.start()
        p10 = Process(target=audit_aws_elb)
        p10.start()
        p11 = Process(target=audit_aws_es)
        p11.start()
        p12 = Process(target=audit_aws_keys)
        p12.start()
        p13 = Process(target=audit_aws_rds)
        p13.start()
        p14 = Process(target=audit_aws_redshift)
        p14.start()
        p15 = Process(target=audit_aws_ses)
        p15.start()
        p16 = Process(target=audit_aws_sns)
        p16.start()
        p17 = Process(target=audit_aws_cdn)
        p17.start()
        p18 = Process(target=audit_aws_vpcs)
        p18.start()
        p19 = Process(target=trusted_advisor)
        p19.start()
        p1.join()
        p2.join()
        p4.join()
        p5.join()
        p6.join()
        p7.join()
        p8.join()
        p9.join()
        p10.join()
        p11.join()
        p12.join()
        p13.join()
        p14.join()
        p15.join()
        p16.join()
        p17.join()
        p18.join()
        p19.join()
        json_to_final_json()
        json_to_html_prowler()
        json_to_html('./reports/AWS/aws_audit/%s/%s/delta/webnet.json' % (account_name, timestmp), './reports/AWS/aws_audit/%s/%s/delta/webnet.html' %(account_name, timestmp))
        json_to_html('./reports/AWS/aws_audit/%s/%s/delta/datastores.json' % (account_name, timestmp), './reports/AWS/aws_audit/%s/%s/delta/datastores.html' %(account_name, timestmp))
        json_to_html('./reports/AWS/aws_audit/%s/%s/delta/notification.json' % (account_name, timestmp), './reports/AWS/aws_audit/%s/%s/delta/notification.html' %(account_name, timestmp))
        json_to_html('./reports/AWS/aws_audit/%s/%s/delta/configs.json' % (account_name, timestmp), './reports/AWS/aws_audit/%s/%s/delta/configs.html' %(account_name, timestmp))
        merge_json()
        subprocess.check_output(['cp -R ./tools/template/* ./reports/AWS/aws_audit/%s/%s/final_report/' % (account_name, timestmp)],shell=True)
        webbrowser.open('file://'+os.path.realpath("./reports/AWS/aws_audit/%s/%s/final_report/report.html") %(account_name, timestmp))
        fin = os.path.realpath("./reports/AWS/aws_audit/%s/%s/final_report/report.html") %(account_name, timestmp)
        print ("THE FINAL REPORT IS LOCATED AT -------->  %s" % (fin))

if __name__ == '__main__':
    main()
