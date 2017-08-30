import time
import datetime
from termcolor import colored
import subprocess
print "\n\n" 
print "################"
print "  CERTS AUDIT   "
print "################\n\n"
epoch=int(time.time())
certs = subprocess.check_output(['aws', 'iam', 'list-server-certificates', '--region', 'us-east-1', '--query', 'ServerCertificateMetadataList[].ServerCertificateName', '--output', 'text'])
if  certs:
    for cert in certs.split('\t'):
        cert=str(cert).strip()
        expire_date=subprocess.check_output(['aws', 'iam','--region','us-east-1',  'get-server-certificate', '--server-certificate-name', '%s'%(cert), '--query', 'ServerCertificate.ServerCertificateMetadata.Expiration', '--output', 'text']).strip()
        expire_time=time.mktime(time.strptime(expire_date,'%Y-%m-%dT%H:%M:%SZ'))
        epoch=int(time.time())
        if epoch > expire_time:
            print colored("certificate %s has expired",'red') % cert
        else:
            print colored("certificate %s not expired", 'green') % cert
