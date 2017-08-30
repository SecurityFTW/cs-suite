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
  printf "\n\n"
  printf "${BOLD}############\n"
  printf "ElasticSearch\n"
  printf "############${NC}\n\n"
for  aws_region in ap-south-1 eu-west-2 eu-west-1 ap-northeast-2 ap-northeast-1 sa-east-1 ca-central-1 ap-southeast-1 ap-southeast-2 eu-central-1 us-east-1 us-east-2 us-west-1 us-west-2;do
  domains=`aws es list-domain-names --region $aws_region --query "DomainNames[].DomainName" --output text`
  for domain in $domains; do
    check=`aws es describe-elasticsearch-domain --domain-name $domain --query 'DomainStatus.AccessPolicies' --output text |grep Principle | grep "{\"AWS\":\"\*\"}"`
    if [ ! "$check" ]; then
      printf "${RED}Elasticsearch doamin $domain is not publicly accessible${NC}\n"
    else
      printf "${GREEN}Elasticsearch doamin $domain is publicly accessible${NC}\n"
    fi
    check=`aws es describe-elasticsearch-domain --domain-name $domain --query 'DomainStatus.AccessPolicies' --output text |grep "aws:SourceIp" |grep "[0-9]\."`
    if [ ! "$check" ]; then
      printf "${RED}Elasticsearch domain $domain does not have an IP based access policy${NC}\n"
    else
      printf "${GREEN}Elasticsearch doamin $domain has an IP based access policy${NC}\n"
    fi
  done
done
