from __future__ import print_function
import subprocess
import json
from IPy import IP

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

account_name = get_account_alias() or get_account_id()

def local_audit(audit_ip, user_name, pem_file, password):
    win_path = 'tools/Windows-Workstation-and-Server-Audit'
    lyn_path = 'tools/lynis'
    ip = IP(audit_ip)
    type = ip.iptype()
    default_region = subprocess.check_output(['aws', 'configure', 'get', 'region']).strip()
    if type == 'PUBLIC':
        operating_sys = subprocess.check_output(['aws', 'ec2', 'describe-instances', '--region', '%s' % default_region, '--filters','Name=ip-address,Values=%s' % (audit_ip), '--query', 'Reservations[*].Instances[*].[Platform]', '--output', 'text']).strip()
        private_ip = subprocess.check_output(['aws', 'ec2', 'describe-instances', '--region', '%s' % default_region, '--filters', 'Name=ip-address,Values=%s' % (audit_ip), '--query', 'Reservations[*].Instances[*].[PrivateIpAddress]', '--output', 'text']).strip()
        public_ip = audit_ip
    elif type == 'PRIVATE':
        operating_sys = subprocess.check_output(['aws', 'ec2', 'describe-instances', '--region', '%s' % default_region, '--filters', 'Name=network-interface.addresses.private-ip-address,Values=%s' % (audit_ip), '--query', 'Reservations[*].Instances[*].[Platform]', '--output', 'text']).strip()
        public_ip = subprocess.check_output(['aws', 'ec2', 'describe-instances', '--region', '%s' % default_region, '--filters', 'Name=network-interface.addresses.private-ip-address,Values=%s' % (audit_ip), '--query', 'Reservations[*].Instances[*].[PublicIpAddress]', '--output', 'text']).strip()
        private_ip = audit_ip
    if public_ip == 'None':
        public_ip = ""
    else:
        dns_name = subprocess.check_output(['host', public_ip]).strip().split(' ')[4]
    if operating_sys == 'windows':
        print ("WINDOWS BOX FOUND!!!")
        if (audit_ip and not (user_name or pem_file or password)):
            subprocess.call(['./windows_remote.sh', account_name, dns_name, private_ip, public_ip], cwd=win_path)
        elif audit_ip and user_name and not (pem_file or password):
            subprocess.call(['./windows_remote.sh', account_name, dns_name, private_ip, public_ip, user_name], cwd=win_path)
        elif audit_ip and pem_file and not (user_name or password):
            subprocess.call(['./windows_remote.sh', account_name, dns_name, private_ip, public_ip, "", pem_file], cwd=win_path)
        elif audit_ip and password and not (user_name or pem_file):
            subprocess.call(['./windows_remote.sh', account_name, dns_name, private_ip, public_ip, "", "", password], cwd=win_path)
        elif audit_ip and user_name and password and not (pem_file):
            subprocess.call(['./windows_remote.sh', account_name, dns_name, private_ip, public_ip, user_name, "", password], cwd=win_path)
        elif audit_ip and user_name and pem_file and not (password):
            subprocess.call(['./windows_remote.sh', account_name, dns_name, private_ip, public_ip, user_name, pem_file], cwd=win_path)
        elif audit_ip and password and pem_file and not (password):
            subprocess.call(['./windows_remote.sh', account_name, dns_name, private_ip, public_ip, "", pem_file, password], cwd=win_path)
        else:
            subprocess.call(['./windows_remote.sh', account_name, dns_name, private_ip, public_ip, user_name, pem_file, password], cwd=win_path)
    else:
        print ("LINUX BOX FOUND!!!")
        if (audit_ip and not (user_name or pem_file or password)):
            subprocess.call(['./lynis_remote.sh', account_name, dns_name, private_ip, public_ip], cwd=lyn_path)
        elif audit_ip and user_name and not (pem_file or password):
            subprocess.call(['./lynis_remote.sh', account_name, dns_name, private_ip, public_ip, user_name], cwd=lyn_path)
        elif audit_ip and pem_file and not (user_name or password):
            subprocess.call(['./lynis_remote.sh', account_name, dns_name, private_ip, public_ip, "", pem_file], cwd=lyn_path)
        elif audit_ip and password and not (user_name or pem_file):
            subprocess.call(['./lynis_remote.sh', account_name, dns_name, private_ip, public_ip, "", "", password], cwd=lyn_path)
        elif audit_ip and user_name and password and not (pem_file):
            subprocess.call(['./lynis_remote.sh', account_name, dns_name, private_ip, public_ip, user_name, "", password], cwd=lyn_path)
        elif audit_ip and user_name and pem_file and not (password):
            subprocess.call(['./lynis_remote.sh', account_name, dns_name, private_ip, public_ip, user_name, pem_file, ""], cwd=lyn_path)
        elif audit_ip and password and pem_file and not (password):
            subprocess.call(['./lynis_remote.sh', account_name, dns_name, private_ip, public_ip, "", pem_file, password], cwd=lyn_path)
        else:
            subprocess.call(['./lynis_remote.sh', account_name, dns_name, private_ip, public_ip, user_name, pem_file, password], cwd=lyn_path)
