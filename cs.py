
#!/usr/bin/env python
from __future__ import print_function
from getpass import getpass
import argparse
from modules import logger
import os
import rm
import subprocess


def main():
    """ main function """
    parser = argparse.ArgumentParser(description='this is to get IP address for lynis audit only')
    parser.add_argument('-env', '--environment', required=True, help='The cloud on which the test-suite is to be run',
                        choices=['aws', 'gcp', 'azure', 'digitalocean'])
    parser.add_argument('-aip', '--audit_ip', required=False, help='The IP for which lynis Audit needs to be done .... by default tries root/Administrator if username not provided')
    parser.add_argument('-u', '--user_name', required=False, help='The username of the user to be logged in,for a specific user')
    parser.add_argument('-pem', '--pem_file', required=False, help='The pem file to access to AWS instance')
    parser.add_argument('-p', '--password', required=False, action='store_true', dest='password', help='hidden password prompt')
    parser.add_argument('-pId', '--project_id', help='Project ID for which GCP Audit needs to be run. Can be retrivied using `gcloud projects list`')
    parser.add_argument('-az_u', '--azure_user', required=False, help='username of azure account, optionally used if you want to run the azure audit with no user interaction.')
    parser.add_argument('-az_p', '--azure_pass', required=False, help='username of azure password, optionally used if you want to run the azure audit with no user interaction.')
    parser.add_argument('-o', '--output', required=False, default="cs-audit.log", help='writes a log in JSON of an audit, ideal for consumptions into SIEMS like ELK and Splunk. Defaults to cs-audit.log')
    parser.add_argument("-w", "--wipe", required=False, default=False, action='store_true',
                        help="rm -rf reports/ folder before executing an audit")
    parser.add_argument('-n', '--number', required=False, help='Retain number of report to store for a particular environment and user/project.')

    args = parser.parse_args()

    
    # set up logging
    log = logger.setup_logging(args.output, "INFO")

    log.info("starting cloud security suite v1.0")

    if args.number and args.wipe == True:
        print("Warning you can't use -w or -n flag at same time")
        exit(1)
    elif args.number:
        try:  
           int(args.number)
        except Exception as _:
            print("Please provide a number for -n option only. ")
            print("EXITTING!!")
            exit(1)

    if args.password:
        password = getpass()

    if args.wipe:
        log.info("wiping reports/ folder before running")
        rm.rm("reports/")

    if args.environment == 'gcp':
        from modules import gcpaudit
        if not args.project_id:
            print ("Please pass project ID for the GCP Audit")
            print ("Exiting !!!")
            exit(0)
        else:
            log.info("running gcp audit")
            gcpaudit.gcp_audit(args.project_id)
            log.info("completed gcp audit")

    elif args.environment == 'aws':
        from modules import awsaudit
        from modules import merger
        from modules import localaudit
        if args.audit_ip:
            if not(args.user_name):
                args.user_name = None
            if not(args.pem_file):
                args.pem_file = None
            if not(args.password):
                password = None
            log.info("running aws local audit")
            localaudit.local_audit(args.audit_ip, args.user_name, args.pem_file, password)
            log.info("completed aws local audit")
            exit(0)
        else:
            log.info("running aws audit")
            awsaudit.aws_audit()
            merger.merge()
            log.info("completed aws audit")

    elif args.environment == 'azure':
        if args.azure_user and args.azure_pass:
            print("using azure credentials passed via cli")
            subprocess.call(['az', 'login', '-u', args.azure_user, '-p', args.azure_pass])
        else:
            print("azure authentication required")
            subprocess.call(['az', 'login'])
        log.info("running azure audit")
        from modules import azureaudit
        azureaudit.azure_audit()
        log.info("completed azure audit")

    elif args.environment == 'digitalocean':
        from modules import doaudit
        try:
            do_api_key = os.environ['DO_KEY']
            do_access_key = os.environ['DO_ACCESS_KEY'] 
            do_secret_key = os.environ['DO_SECRET_KEY']
        except Exception as e:
            print ("Please export DO key/access and secret as DO_KEY,DO_ACCESS_KEY,DO_SECRET_KEY")
            print ("Exiting !!!")
            exit(0)
        doaudit.do_audit(do_api_key, do_access_key, do_secret_key)

    if args.number > 0 and args.wipe == False:
        from modules import retainnumberofreports
        retainnumberofreports.retain_reports(args.environment, int(args.number), args.project_id )
        exit(0)

if __name__ == '__main__':
    main()
 
