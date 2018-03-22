#!/usr/bin/env bash
# audit_aws_ses
#
# Refer to https://www.cloudconformity.com/conformity-rules/SES/dkim-enabled.html
#.#!/usr/bin/env bash
  RED='\033[0;31m'
  NC='\033[0m'
  GREEN='\033[0;32m'
  BOLD='\033[1m'
  #printf "\n\n"
  #printf "${BOLD}############\n"
  #printf "SES AUDIT\n"
  #printf "############${NC}\n\n"
  account=`aws sts get-caller-identity --output text --query 'Account'`
for  aws_region in ap-south-1 eu-west-2 eu-west-1 ap-northeast-2 ap-northeast-1 sa-east-1 ca-central-1 ap-southeast-1 ap-southeast-2 eu-central-1 us-east-1 us-east-2 us-west-1 us-west-2;do
  domains=`aws ses list-identities --region $aws_region --query Identities --output text 2> /dev/null`
  for domain in $domains; do
    check=`aws ses get-identity-dkim-attributes --region $aws_region --identities $domain |grep DkimEnabled |grep true`
    if [ ! "$check" ]; then
      printf "default,$account,$aws_region,null,WARNING,Scored,null,SES_AUDIT,Domain $domain does not have DKIM enabled\n"
    else
      printf "default,$account,$aws_region,null,PASS,Scored,null,SES_AUDIT,Domain $domain has DKIM enabled\n"
    fi
  done
done
