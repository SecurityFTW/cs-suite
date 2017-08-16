from __future__ import print_function
from multiprocessing import Process
import os
import argparse
import json
import subprocess
import time
from IPy import IP
from getpass import getpass
import webbrowser

account_details = {}
account_details = subprocess.check_output(['aws', 'iam', 'list-account-aliases'])
account_details = json.loads(str(account_details))
account_name = account_details['AccountAliases'][0]
timestmp = time.strftime("%Y%m%d-%H%M%S")


def prowler():
    """ this function calls the prowler script """
    print ("started prowler")
    file_name = 'prowler_report.txt'
    with open('reports/aws_audit/%s/%s/delta/%s' % (account_name, timestmp, file_name), 'w') as output:
        subprocess.call(['./prowler', '-c', 'checkNotScout'], stdout=output, cwd='tools/prowler')
    print ("Prowler Audit done")
    return 0


def scout2():
    """ this function calls Scout2 tool """
    print ("Started Scout2")
    file_name = 'scout2_report'
    subprocess.call(['python', 'Scout2.py', '--no-browser', '--report-dir', '../../reports/aws_audit/%s/%s/%s' %(account_name, timestmp, file_name) ], cwd='tools/Scout2')
    print ("Scout2 Audit done")
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
    with open('reports/aws_audit/%s/%s/delta/certs' % (account_name, timestmp), 'w') as output:
        subprocess.call(['python', './scripts/audit_aws_certs.py'], stdout=output)
    print ("Cert Audit Done")
    return 0

def audit_aws_cf():
    """ this function is to audit Cloud Formation """
    print ("Started Cloud Formation Audit ")
    with open('reports/aws_audit/%s/%s/delta/cloud_formation' % (account_name, timestmp), 'w') as output:
        subprocess.call(['./scripts/audit_aws_cloud_formation.sh'], stdout=output)
    print ("Cloud Formation Audit Done")
    return 0


def audit_aws_config():
    """ this function is to audit AWS config """
    print ("Started AWS config Audit ")
    with open('reports/aws_audit/%s/%s/delta/aws_config' % (account_name, timestmp), 'w') as output:
        subprocess.call(['./scripts/audit_aws_config.sh'], stdout=output)
    print ("AWS config Audit Done")
    return 0


def audit_aws_dns():
    """ this function is to DNS """
    print ("Started AWS DNS Audit ")
    with open('reports/aws_audit/%s/%s/delta/dns' % (account_name, timestmp), 'w') as output:
        subprocess.call(['./scripts/audit_aws_dns.sh'], stdout=output)
    print ("AWS DNS Audit Done")
    return 0


def audit_aws_ec():
    """ this function is to audit Elastic Cache """
    print ("Started AWS Elastic Cache Audit ")
    with open('reports/aws_audit/%s/%s/delta/ec' % (account_name, timestmp), 'w') as output:
        subprocess.call(['./scripts/audit_aws_ec.sh'], stdout=output)
    print ("AWS Elastic Cache Audit Done ")
    return 0


def audit_aws_ec2():
    """ this function is to audit Instances """
    print ("Started AWS Instances Audit ")
    with open('reports/aws_audit/%s/%s/delta/ec2' % (account_name, timestmp), 'w') as output:
        subprocess.call(['./scripts/audit_aws_ec2.sh'], stdout=output)
    print ("AWS Instances Audit Done ")
    return 0


def audit_aws_elb():
    """ this function is to audit Instances """
    print ("Started AWS Load-Balancer Audit ")
    with open('reports/aws_audit/%s/%s/delta/elb' % (account_name, timestmp), 'w') as output:
        subprocess.call(['./scripts/audit_aws_elb.sh'], stdout=output)
    print ("AWS Load-Balancer Audit Done ")
    return 0


def audit_aws_es():
    """ this function is to audit Instances """
    print ("Started AWS Elastic-Search Audit ")
    with open('reports/aws_audit/%s/%s/delta/es' % (account_name, timestmp), 'w') as output:
        subprocess.call(['./scripts/audit_aws_es.sh'], stdout=output)
    print ("AWS Elastic-Search Audit Done ")
    return 0


def audit_aws_keys():
    """ this function is to audit Instances """
    print ("Started AWS SSH Audit ")
    with open('reports/aws_audit/%s/%s/delta/keys' % (account_name, timestmp), 'w') as output:
        subprocess.call(['./scripts/audit_aws_keys.sh'], stdout=output)
    print ("AWS SSH Audit Done ")
    return 0


def audit_aws_rds():
    """ this function is to audit Instances """
    print ("Started AWS RDS Audit ")
    with open('reports/aws_audit/%s/%s/delta/rds' % (account_name, timestmp), 'w') as output:
        subprocess.call(['./scripts/audit_aws_rds.sh'], stdout=output)
    print ("AWS RDS Audit Done ")
    return 0


def audit_aws_redshift():
    """ this function is to audit Instances """
    print ("Started AWS Redshift Audit ")
    with open('reports/aws_audit/%s/%s/delta/redshift' % (account_name, timestmp), 'w') as output:
        subprocess.call(['./scripts/audit_aws_redshift.sh'], stdout=output)
    print ("AWS Redshift Audit Done ")
    return 0


def audit_aws_ses():
    """ this function is to audit Instances """
    print ("Started AWS SES Audit ")
    with open('reports/aws_audit/%s/%s/delta/ses' % (account_name, timestmp), 'w') as output:
        subprocess.call(['./scripts/audit_aws_ses.sh'], stdout=output)
    print ("AWS SES Audit Done ")
    return 0


def audit_aws_cdn():
    """ this function is to audit Instances """
    print ("Started AWS CDN Audit ")
    with open('reports/aws_audit/%s/%s/delta/cdn' % (account_name, timestmp), 'w') as output:
        subprocess.call(['./scripts/aws_cdn_audit.sh'], stdout=output)
    print ("AWS CDN Audit Done ")
    return 0


def audit_aws_sns():
    """ this function is to audit Instances """
    print ("Started AWS SNS Audit ")
    with open('reports/aws_audit/%s/%s/delta/sns' % (account_name, timestmp), 'w') as output:
        subprocess.call(['./scripts/audit_aws_sns.sh'], stdout=output)
    print ("AWS SNS Audit Done ")
    return 0


def audit_aws_vpcs():
    """ this function is to audit Instances """
    print ("Started AWS VPC Audit ")
    with open('reports/aws_audit/%s/%s/delta/vpc' % (account_name, timestmp), 'w') as output:
        subprocess.call(['./scripts/audit_aws_vpcs.sh'], stdout=output)
    print ("AWS VPC Audit Done ")
    return 0



def main():
    """ main function """
    parser = argparse.ArgumentParser(description='this is to get IP address for lynis audit only')
    parser.add_argument('-aip','--audit_ip', help='The IP for which lynis Audit needs to be done .... by default tries root/Administrator if username not provided')
    parser.add_argument('-u','--user_name', help='The username of the user to be logged in,for a specific user')
    parser.add_argument('-pem','--pem_file', help='The pem file to access to AWS instance')
    parser.add_argument('-p', '--password', action='store_true', dest='password', help='hidden password prompt')
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


    else:
        subprocess.call(['mkdir', '-p', 'reports/aws_audit/%s/%s/delta' %(account_name, timestmp)])
        p1 = Process(target=prowler)
        p1.start()
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
        subprocess.check_output(['cat ./reports/aws_audit/%s/%s/delta/prowler_report.txt | ansi2html > ./reports/aws_audit/%s/%s/delta/prowler_report.html' % (account_name, timestmp,account_name, timestmp)],shell=True)
        subprocess.check_output(['cat ./reports/aws_audit/%s/%s/delta/cdn ./reports/aws_audit/%s/%s/delta/certs  ./reports/aws_audit/%s/%s/delta/dns ./reports/aws_audit/%s/%s/delta/elb | ansi2html > ./reports/aws_audit/%s/%s/delta/webnet.html'  %(account_name, timestmp,account_name, timestmp,account_name, timestmp,account_name, timestmp,account_name, timestmp)  ],shell=True)
        subprocess.check_output(['cat ./reports/aws_audit/%s/%s/delta/ec ./reports/aws_audit/%s/%s/delta/es  ./reports/aws_audit/%s/%s/delta/rds ./reports/aws_audit/%s/%s/delta/redshift | ansi2html > ./reports/aws_audit/%s/%s/delta/datastores.html'  %(account_name, timestmp,account_name, timestmp,account_name, timestmp,account_name, timestmp,account_name, timestmp)  ],shell=True)
        subprocess.check_output(['cat ./reports/aws_audit/%s/%s/delta/cloud_formation ./reports/aws_audit/%s/%s/delta/ses  ./reports/aws_audit/%s/%s/delta/sns | ansi2html > ./reports/aws_audit/%s/%s/delta/notification.html'  %(account_name, timestmp,account_name, timestmp,account_name, timestmp,account_name, timestmp,account_name, timestmp)  ],shell=True)
        subprocess.check_output(['cat ./reports/aws_audit/%s/%s/delta/ec2 ./reports/aws_audit/%s/%s/delta/vpc  ./reports/aws_audit/%s/%s/delta/keys ./reports/aws_audit/%s/%s/delta/vpc | ansi2html > ./reports/aws_audit/%s/%s/delta/configs.html'  %(account_name, timestmp,account_name, timestmp,account_name, timestmp,account_name, timestmp,account_name, timestmp)  ],shell=True)
        subprocess.check_output(['cp -R ./tools/template ./reports/aws_audit/%s/%s/final_report' % (account_name, timestmp)],shell=True)
        webbrowser.open('file://'+os.path.realpath("./reports/aws_audit/%s/%s/final_report/report.html") %(account_name, timestmp))
        fin = os.path.realpath("./reports/aws_audit/%s/%s/final_report/report.html") %(account_name, timestmp)
        print ("THE FINAL REPORT IS LOCATED AT -------->  %s" % (fin))

if __name__ == '__main__':
    main()
