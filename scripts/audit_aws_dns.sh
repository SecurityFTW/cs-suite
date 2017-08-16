#!/usr/bin/env bash
# audit_aws_dns
#
# Refer to https://www.cloudconformity.com/conformity-rules/Route53/route-53-domain-auto-renew.html
# Refer to https://www.cloudconformity.com/conformity-rules/Route53/route-53-domain-expired.html
# Refer to https://www.cloudconformity.com/conformity-rules/Route53/sender-policy-framework-record-present.html
# Refer to https://www.cloudconformity.com/conformity-rules/Route53/route-53-domain-transfer-lock.html
#.

  RED='\033[0;31m'
  NC='\033[0m'
  GREEN='\033[0;32m'
  BOLD='\033[1m'
  printf "\n\n"
  printf "${BOLD}############\n"
  printf "  Route53\n"
  printf "############${NC}\n\n" 
  for  aws_region in ap-south-1 eu-west-2 eu-west-1 ap-northeast-2 ap-northeast-1 sa-east-1 ca-central-1 ap-southeast-1 ap-southeast-2 eu-central-1 us-east-1 us-east-2 us-west-1 us-west-2;do
      domains=`aws route53domains --region $aws_region list-domains --query 'Domains[].DomainName' --output text 2> /dev/null`
      for domain in $domains; do
           check=`aws route53domains get-domain-detail --region $aws_region --domain-name $domain |grep true`
           if [ ! "$check" ]; then
               printf "${RED}Domain $domain does not auto renew${NC}\n"
           else
               printf "${GREEN}Domain $domain does auto renew${NC}\n"
           fi
           cur_secs=`date "+%s"`
           exp_secs=`aws route53domains get-domain-detail --region $aws_region --domain-name $domain --query "ExpirationDate" --output text 2> /dev/null`
           if [ "$exp_secs" -lt "$cur_secs" ]; then
               printf "${RED}Warning:   Domain $domain registration has expired${NC}\n" 
           else
               printf "${GREEN}Domain $domain registration has not expired${NC}\n"
           fi
           check=`aws route53domains get-domain-detail --region $aws_region --domain-name $domain --query "Status" --output text 2> /dev/null | grep clientTransferProhibited`
           if [ ! "$check" ]; then
               printf "${RED}Domain $domain does not have Domain Transfer Lock enabled${NC}\n" 
           else
               printf "${GREEN}Domain $domain does have Domain Transfer Lock enabled${NC}\n"
           fi
      done
      zones=`aws route53 list-hosted-zones --region $aws_region --query "HostedZones[].Id" --output text 2> /dev/null |cut -f3 -d'/'`
      for zone in $zones; do
          spf=`aws route53 list-resource-record-sets --region $aws_region --hosted-zone-id $zone --query "ResourceRecordSets[?Type == 'SPF']" --output text`
          if [ ! "$spf" ]; then
              printf "${RED}Zone $zone does not have SPF records${NC}\n"
          else
              printf "${GREEN}Zone $zone  has SPF records${NC}\n"
          fi
      done
  done
