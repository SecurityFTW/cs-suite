 #!/usr/bin/env python
from __future__ import print_function
from getpass import getpass
import argparse
from modules import logger
import rm
         
def main():
    """ main function """
    parser = argparse.ArgumentParser(description='this is to get IP address for lynis audit only')
    parser.add_argument('-aip', '--audit_ip', help='The IP for which lynis Audit needs to be done .... by default tries root/Administrator if username not provided')
    parser.add_argument('-u', '--user_name', help='The username of the user to be logged in,for a specific user')
    parser.add_argument('-pem', '--pem_file', help='The pem file to access to AWS instance')
    parser.add_argument('-p', '--password', action='store_true', dest='password', help='hidden password prompt')
    parser.add_argument('-env', '--environment', help='The cloud on which the test-suite is to be run', choices=['aws', 'gcp', 'azure'], required=True)
    parser.add_argument('-pId', '--project_id', help='Project ID for which GCP Audit needs to be run. Can be retrivied using `gcloud projects list`')
    parser.add_argument('-o', '--output', required=False, default="cs-audit.log", help='writes a log in JSON of an audit, ideal for consumptions into SIEMS like ELK and Splunk. Defaults to cs-audit.log')
    parser.add_argument("-w", "--wipe", required=False, default=True, action='store_true',
                        help="rm -rf reports/ folder before executing an audit")

    args = parser.parse_args()

    # set up logging
    log = logger.setup_logging(args.output, "INFO")

    log.info("starting cloud security suite v1.0")

    if args.wipe:
        log.info("wiping reports/ folder before running")
        rm.rm("reports/")


    if args.password:
        password = getpass()

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
            exit(0)

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
            exit(0)

    elif args.environment == 'azure':
        from modules import azureaudit
        log.info("running azure audit")
        azureaudit.azure_audit()
        log.info("completed azure audit")
        exit(0)


if __name__ == '__main__':
    main()
