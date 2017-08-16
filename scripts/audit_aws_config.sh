#!/usr/bin/env bash
# audit_aws_config
#
# Refer to https://www.cloudconformity.com/conformity-rules/Config/aws-config-enabled.html
#.
  RED='\033[0;31m'
  NC='\033[0m'
  GREEN='\033[0;32m'
  BOLD='\033[1m'
  printf "\n\n"
  printf "${BOLD}############\n"
  printf "   Config\n"
  printf "############${NC}\n\n"
for  aws_region in ap-south-1 eu-west-2 eu-west-1 ap-northeast-2 ap-northeast-1 sa-east-1 ca-central-1 ap-southeast-1 ap-southeast-2 eu-central-1 us-east-1 us-east-2 us-west-1 us-west-2;do
  check=`aws configservice describe-configuration-recorders --region $aws_region`
  if [ ! "$check" ]; then
    printf "${RED}AWS Configuration Recorder not enabled${NC}\n"
  else
    printf "${GREEN}AWS Configuration Recorder enabled${NC}\n"
  fi
  check=`aws configservice --region $aws_region get-status |grep FAILED`
  if [ "$check" ]; then
    printf "${RED}AWS Config not enabled${NC}\n"
  else
    printf "${GREEN}AWS Config enabled in region $aws_region${NC}\n"
  fi
done
