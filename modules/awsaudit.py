from __future__ import print_function
import time
import subprocess
import json
import csv
import glob
import os
from multiprocessing import Process
from multiprocessing import Pool
import boto3


def get_account_alias():
    account_details = subprocess.check_output(['aws iam list-account-aliases'], shell=True)
    account_details = json.loads(str(account_details))
    try:
        return account_details['AccountAliases'][0]
    except IndexError:
        return None

def get_account_id():
    caller_identity = subprocess.check_output(['aws sts get-caller-identity'], shell=True)
    caller_identity = json.loads(str(caller_identity))
    try:
        return caller_identity['Account']
    except IndexError:
        return None

# timestmp and script required across all functions
account_name = get_account_alias() or get_account_id()
timestmp = time.strftime("%Y%m%d-%H%M%S")
script_json = {}
script_json['account_info'] = {'aws-cli_profile':['default']}
script_json['account_info'].update({'date':timestmp})
script_json['account_info'].update({'aws_api_region':['us-east-1']})
script_json['account_info'].update({'aws_filter_region':['all']})
identity = subprocess.check_output(['aws', 'sts', 'get-caller-identity'])
identity = json.loads(str(identity))
script_json['account_info'].update({'caller_identity':identity})


def prowler(check):
    """ this function calls the prowler script """
    file_name = check
    with open('tools/prowler/%s.csv' % (check), 'w') as output:
        subprocess.call(['./prowler', '-M', 'csv', '-c', check], stdout=output, cwd='tools/prowler')

    csvfile = open('tools/prowler/%s.csv' % (check), 'r')
    jsonfile = open('tools/prowler/%s.json' % (check), 'w')
    fieldnames = ("aws-cli_profile", "account", "region", "check_no",\
                  "type", "score", "level", "check", "value")
    reader = csv.DictReader(csvfile, fieldnames)
    for row in reader:
        json.dump(row, jsonfile)
        jsonfile.write('\n')
    return 0


def multi_threaded_prowler():
    """ this function using multi-threading for prowler """
    print ("Started Prowler")

    checks = ['check13', 'check14', 'check15', 'check16', 'check17', 'check18', 'check19',\
              'check114', 'check115', 'check116', 'check118', 'check122', 'check123', 'check124',\
              'check21', 'check23', 'check24', 'check25', 'check26', 'check27', 'check28', 'check31',\
              'check32', 'check33', 'check34', 'check35', 'check36', 'check37', 'check38', 'check39',\
              'check310', 'check311', 'check312', 'check313', 'check314', 'check315', 'check43',\
              'check44', 'check45']
    p = Pool(5)
    p.map(prowler, checks)
    final_json = {}
    final_json['account_info'] = {'aws-cli_profile':['default']}
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
                new_dict = {}
                j = json.loads(line)
                dict['check'] = j['check']
                new_dict['check_no'] = j['check_no']
                new_dict['score'] = j['score']
                new_dict['level'] = j['level']
                new_dict['type'] = j['type']
                new_dict['region'] = j['region']
                new_dict['value'] = j['value']
                data.append(new_dict)
        dict['data'] = data
        report.append(dict)
        final_json['report'] = report
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
    subprocess.call(['python', 'Scout2.py', '--no-browser', '--report-dir',\
                     '../../reports/AWS/aws_audit/%s/%s/%s' \
                     %(account_name, timestmp, file_name)], cwd='tools/Scout2')
    print ("Scout2 Audit done")
    return 0

def csv_to_json(file):
    """This function is used to convert prowler CSV output to common json"""
    csvfile = open(file, 'r')
    jsonfile = open('%s.json' %(file), 'w')
    fieldnames = ("aws-cli_profile", "account", "region", "check_no",\
                  "type", "score", "level", "check", "value")
    reader = csv.DictReader(csvfile, fieldnames)
    for row in reader:
        json.dump(row, jsonfile)
        jsonfile.write('\n')
    return 0

def audit_aws_certs():
    """  this function audits AWS certs """
    print ("Started AWS cert audit")
    with open('reports/AWS/aws_audit/%s/%s/delta/certs' % (account_name, timestmp), 'w') as output:
        subprocess.call(['python', './scripts/audit_aws_certs.py'], stdout=output)
        if os.stat('reports/AWS/aws_audit/%s/%s/delta/certs' %(account_name, timestmp)).st_size == 0:
            output.write("default,account,null,null,INFO,scored,null,CERT_AUDIT,No information is available\n")
    csv_to_json('reports/AWS/aws_audit/%s/%s/delta/certs' % (account_name, timestmp))
    print ("Cert Audit Done")
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
    with open('reports/AWS/aws_audit/%s/%s/final_report/trusted' %(account_name, timestmp), 'w') as f:
        account_id = subprocess.check_output(['aws sts get-caller-identity --output text --query "Account"'], shell=True).strip()
        try:
            client = boto3.client('support', region_name='us-east-1')
            checks = {'DqdJqYeRm5':'Security Groups - Specific Ports Unrestricted', 'BueAdJ7NrP':'Amazon S3 Bucket Logging',\
                'HCP4007jGY':'Security Groups - Specific Ports Unrestricted', '1iG5NDGVre':'Security Groups - Unrestricted Access',\
                'a2sEc6ILx':'ELB Listener Security', 'xSqX82fQu':'ELB Security Groups', 'R365s2Qddf':'Amazon S3 Bucket Versioning', \
                'xuy7H1avtl':'Amazon Aurora DB Instance Accessibility', 'zXCkfM1nI3':'IAM Use', '7DAFEmoDos':'MFA on Root Account',\
                'Yw2K9puPzl':'IAM Password Policy', '12Fnkpl8Y5':'Exposed Access Keys',\
                'N425c450f2':'CloudFront Custom SSL Certificates in the IAM Certificate Store',\
                'N430c450f2':'CloudFront SSL Certificate on the Origin Server', 'Pfx0RwqBli':'Amazon S3 Bucket Permissions',\
                'nNauJisYIT':'Amazon RDS Security Group Access Risk'}
            for check in checks.keys():
                response = client.describe_trusted_advisor_check_result(checkId=check, language='en')
                if response['result']['flaggedResources']:
                    for i in response['result']['flaggedResources']:
                        if 'metadata' in i:
                            if check in ['N425c450f2', 'N430c450f2', 'Pfx0RwqBli', 'nNauJisYIT']:
                                f.write("default,%s,null,null,%s,Scored,null,%s,%s\n" \
                                    % (account_id, i['status'], checks[check], i['metadata'][2]))
                            elif check in ['vjafUGJ9H0']:
                                f.write("default,%s,null,null,%s,Scored,null,%s,%s\n" \
                                    % (account_id, i['status'], checks[check], i['metadata'][3]))
                            else:
                                f.write("default,%s,null,null,%s,Scored,null,%s,%s\n" \
                                    % (account_id, i['status'], checks[check], i['metadata'][1]))
                else:
                    f.write("default,%s,null,null,%s,Scored,null,%s,%s\n" \
                        % (account_id, response['result']['status'], \
                           checks[check], response['result']['status']))
        except Exception:
            print ("Keys don't have read-only support permission")
    csv_to_json('reports/AWS/aws_audit/%s/%s/final_report/trusted' % (account_name, timestmp))


def aws_audit():
    """ This function used for calling all the AWS audit functions"""
    subprocess.call(['mkdir', '-p', 'reports/AWS/aws_audit/%s/%s/final_report' % (account_name, timestmp)])
    subprocess.call(['mkdir', '-p', 'reports/AWS/aws_audit/%s/%s/delta' % (account_name, timestmp)])
    p1 = Process(target=multi_threaded_prowler)
    p1.start()
    p2 = Process(target=scout2)
    p2.start()
    p3 = Process(target=audit_aws_certs)
    p3.start()
    p4 = Process(target=audit_aws_cf)
    p4.start()
    p5 = Process(target=audit_aws_config)
    p5.start()
    p6 = Process(target=audit_aws_dns)
    p6.start()
    p7 = Process(target=audit_aws_ec)
    p7.start()
    p8 = Process(target=audit_aws_ec2)
    p8.start()
    p9 = Process(target=audit_aws_elb)
    p9.start()
    p10 = Process(target=audit_aws_es)
    p10.start()
    p11 = Process(target=audit_aws_keys)
    p11.start()
    p12 = Process(target=audit_aws_rds)
    p12.start()
    p13 = Process(target=audit_aws_redshift)
    p13.start()
    p14 = Process(target=audit_aws_ses)
    p14.start()
    p15 = Process(target=audit_aws_sns)
    p15.start()
    p16 = Process(target=audit_aws_cdn)
    p16.start()
    p17 = Process(target=audit_aws_vpcs)
    p17.start()
    p18 = Process(target=trusted_advisor)
    p18.start()
    p1.join()
    p2.join()
    p3.join()
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
