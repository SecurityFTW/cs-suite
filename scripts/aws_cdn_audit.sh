#!/usr/bin/env bash
RED='\033[0;31m'
NC='\033[0m'
GREEN='\033[0;32m'
BOLD='\033[1m'
printf "\n\n"
printf "${BOLD}############\n"
printf " Cloudfront\n"
printf "############${NC}\n\n"
aws configure set preview.cloudfront true
cdns=`aws cloudfront list-distributions  --query 'DistributionList.Items[].Id' --output text` 
  for cdn in $cdns; do 
    # Check Cloudfront is using WAF
    check=`aws cloudfront get-distribution --id $cdn --query 'Distribution.DistributionConfig.WebACLId' --output text`
    if [ ! "$check" ]; then
      printf "${RED}Cloudfront $cdn is not WAF integration enabled${NC}\n"
    else
      printf "${GREEN}Cloudfront $cdn has WAF integration enabled${NC}\n"
    fi
    # Check logging is enabled
    check=`aws cloudfront get-distribution  --id $cdn --query 'Distribution.DistributionConfig.Logging.Enabled' |grep true`
    if [ ! "$check" ]; then
      printf "${RED}Cloudfront $cdn does not have logging enabled${NC}\n"
    else
      printf "${GREEN}Cloudfront $cdn does have logging enabled${NC}\n"
    fi
    # check SSL protocol versions being used against deprecated ones
    check=`aws cloudfront get-distribution  --id $cdn --query 'Distribution.DistributionConfig.Origins.Items[].CustomOriginConfig.OriginSslProtocols.Items' |egrep "SSLv3|SSLv2"`
    if [ "$check" ]; then
      printf "${RED}Cloudfront $cdn is using a deprecated verions of SSL${NC}\n"
    else
      printf "${GREEN}Cloudfront $cdn is not using a deprecated verions of SSL${NC}\n"
    fi
    # check if HTTP only being used 
    check=`aws cloudfront get-distribution  --id $cdn --query 'Distribution.DistributionConfig.Origins.Items[].CustomOriginConfig.OriginProtocolPolicy' |egrep "http-only"`
    if [ "$check" ]; then
      printf "${RED}Cloudfront $cdn is using HTTP only${NC}\n"
    else
      printf "${GREEN}Cloudfront $cdn is using HTTPS${NC}\n"
    fi
  done
