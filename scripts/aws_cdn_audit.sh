#!/usr/bin/env bash
RED='\033[0;31m'
NC='\033[0m'
GREEN='\033[0;32m'
BOLD='\033[1m'
#printf "\n\n"
#printf "${BOLD}############\n"
#printf " Cloudfront AUDIT\n"
#printf "############${NC}\n\n"
account=`aws sts get-caller-identity --output text --query 'Account'`
aws configure set preview.cloudfront true
cdns=`aws cloudfront list-distributions  --query 'DistributionList.Items[].Id' --output text` 
  for cdn in $cdns; do 
    # Check Cloudfront is using WAF
    check=`aws cloudfront get-distribution --id $cdn --query 'Distribution.DistributionConfig.WebACLId' --output text`
    if [ ! "$check" ]; then
      printf "default,$account,us-east-1,null,WARNING,Scored,null,CDN_AUDIT,Cloudfront $cdn is not WAF integration enabled\n"
    else
      printf "default,$account,us-east-1,null,PASS,Scored,null,CDN_AUDIT,Cloudfront $cdn has WAF integration enabled\n"
    fi
    # Check logging is enabled
    check=`aws cloudfront get-distribution  --id $cdn --query 'Distribution.DistributionConfig.Logging.Enabled' |grep true`
    if [ ! "$check" ]; then
      printf "default,$account,us-east-1,null,WARNING,Scored,null,CDN_AUDIT,Cloudfront $cdn does not have logging enabled\n"
    else
      printf "default,$account,us-east-1,null,PASS,Scored,null,CDN_AUDIT,Cloudfront $cdn does have logging enabled\n"
    fi
    # check SSL protocol versions being used against deprecated ones
    check=`aws cloudfront get-distribution  --id $cdn --query 'Distribution.DistributionConfig.Origins.Items[].CustomOriginConfig.OriginSslProtocols.Items' |egrep "SSLv3|SSLv2"`
    if [ "$check" ]; then
      printf "default,$account,us-east-1,null,WARNING,Scored,null,CDN_AUDIT,Cloudfront $cdn is using a deprecated verions of SSL\n"
    else
      printf "default,$account,us-east-1,null,PASS,Scored,null,CDN_AUDIT,Cloudfront $cdn is not using a deprecated verions of SSL\n"
    fi
    # check if HTTP only being used 
    check=`aws cloudfront get-distribution  --id $cdn --query 'Distribution.DistributionConfig.Origins.Items[].CustomOriginConfig.OriginProtocolPolicy' |egrep "http-only"`
    if [ "$check" ]; then
      printf "default,$account,us-east-1,null,WARNING,Scored,null,CDN_AUDIT,Cloudfront $cdn is using HTTP only\n"
    else
      printf "default,$account,us-east-1,null,PASS,Scored,null,CDN_AUDIT,Cloudfront $cdn is using HTTPS\n"
    fi
  done
