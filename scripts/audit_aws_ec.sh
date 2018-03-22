#!/usr/bin/env bash
# audit_aws_ec
#
# Refer to https://www.cloudconformity.com/conformity-rules/ElastiCache/elasticache-multi-az.html
#.
  RED='\033[0;31m'
  NC='\033[0m'
  GREEN='\033[0;32m'
  BOLD='\033[1m'
  #printf "\n\n"
  #printf "${BOLD}############\n"
  #printf " ElastiCache AUDIT\n"
  #printf "############${NC}\n\n"
  account=`aws sts get-caller-identity --output text --query 'Account'`
for  aws_region in ap-south-1 eu-west-2 eu-west-1 ap-northeast-2 ap-northeast-1 sa-east-1 ca-central-1 ap-southeast-1 ap-southeast-2 eu-central-1 us-east-1 us-east-2 us-west-1 us-west-2;do
  caches=`aws elasticache describe-replication-groups --region $aws_region --query 'ReplicationGroups[].ReplicationGroupId' --output text` 
  for cache in $caches; do 
    check=`aws elasticache describe-replication-groups --region $aws_region --replication-group-id $cache --query 'ReplicationGroups[].AutomaticFailover' |grep enabled`
    if [ ! "$check" ]; then
      printf "default,$account,$aws_region,null,WARNING,Scored,null,ELASTIC_CACHE_AUDIT,ElastiCache $cache is not Multi-AZ enabled\n"
    else
      printf "default,$account,$aws_region,null,PASS,Scored,null,ELASTIC_CACHE_AUDIT,ElastiCache $cache is Multi-AZ enabled\n"
    fi
  done
done
