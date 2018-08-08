import time
import datetime
from termcolor import colored
import subprocess
#print "\n\n" 
#print "################"
#print "  CERTS AUDIT   "
#print "################\n\n"
epoch=int(time.time())
account=subprocess.check_output(['aws', 'sts', 'get-caller-identity', '--output', 'text', '--query', 'Account'])
account=account.strip()
certs = subprocess.check_output(['aws', 'iam', 'list-server-certificates', '--region', 'us-east-1', '--query', 'ServerCertificateMetadataList[].ServerCertificateName', '--output', 'text'])
if  certs:
    for cert in certs.split('\t'):
        cert=str(cert).strip()
        expire_date=subprocess.check_output(['aws', 'iam','--region','us-east-1',  'get-server-certificate', '--server-certificate-name', '%s'%(cert), '--query', 'ServerCertificate.ServerCertificateMetadata.Expiration', '--output', 'text']).strip()
        expire_time=time.mktime(time.strptime(expire_date,'%Y-%m-%dT%H:%M:%SZ'))
        epoch=int(time.time())
        if epoch > expire_time:
            print ("default,%s,us-east-1,null,WARNING,Scored,null,CERT_AUDIT,certificate %s has expired") % (account,cert)
        else:
            print ("default,%s,us-east-1,null,PASS,Scored,null,CERT_AUDIT,certificate %s not expired") % (account,cert)
