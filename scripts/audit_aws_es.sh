#!/usr/bin/env bash
# audit_aws_es
#
# Refer to https://www.cloudconformity.com/conformity-rules/Elasticsearch/elasticsearch-domain-exposed.html
# Refer to https://www.cloudconformity.com/conformity-rules/Elasticsearch/elasticsearch-accessible-only-from-whitelisted-ip-addresses.html
#.
  RED='\033[0;31m'
  NC='\033[0m'
  GREEN='\033[0;32m'
  BOLD='\033[1m'
  #printf "\n\n"
  #printf "${BOLD}############\n"
  #printf "ElasticSearch\n"
  #printf "############${NC}\n\n"
  account=`aws sts get-caller-identity --output text --query 'Account'`
for  aws_region in ap-south-1 eu-west-2 eu-west-1 ap-northeast-2 ap-northeast-1 sa-east-1 ca-central-1 ap-southeast-1 ap-southeast-2 eu-central-1 us-east-1 us-east-2 us-west-1 us-west-2;do
  domains=`aws es list-domain-names --region $aws_region --query "DomainNames[].DomainName" --output text`
  for domain in $domains; do
    check=`aws es describe-elasticsearch-domain --domain-name $domain --query 'DomainStatus.AccessPolicies' --output text |grep Principle | grep "{\"AWS\":\"\*\"}"`
    if [ ! "$check" ]; then
      printf "default,$account,$aws_region,null,PASS,Scored,null,ELASTIC_SEARCH_AUDIT,Elasticsearch doamin $domain is not publicly accessible\n"
    else
      printf "default,$account,$aws_region,null,WARNING,Scored,null,ELASTIC_SEARCH_AUDIT,Elasticsearch doamin $domain is publicly accessible\n"
    fi
    check=`aws es describe-elasticsearch-domain --domain-name $domain --query 'DomainStatus.AccessPolicies' --output text |grep "aws:SourceIp" |grep "[0-9]\."`
    if [ ! "$check" ]; then
      printf "default,$account,$aws_region,null,WARNING,Scored,null,ELASTIC_SEARCH_AUDIT,Elasticsearch domain $domain does not have an IP based access policy\n"
    else
      printf "default,$account,$aws_region,null,PASS,Scored,null,ELASTIC_SEARCH_AUDIT,Elasticsearch doamin $domain has an IP based access policy\n"
    fi
  done
done
