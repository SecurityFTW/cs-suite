#!/usr/bin/env bash
# audit_aws_vpcs
#
# Refer http://docs.aws.amazon.com/AmazonCloudWatch/latest/DeveloperGuide/SettingLogRetention.html
# Refer to Section(s) 4.2 Page(s) 133-4  CIS AWS Foundations Benchmark v1.1.0
# Refer to Section(s) 4.3 Page(s) 135-7  CIS AWS Foundations Benchmark v1.1.0
# Refer to Section(s) 4.4 Page(s) 138-40 CIS AWS Foundations Benchmark v1.1.0
# Refer to Section(s) 4.5 Page(s) 141-2  CIS AWS Foundations Benchmark v1.1.0
# Refer to https://www.cloudconformity.com/conformity-rules/VPC/endpoint-exposed.html
#.
  RED='\033[0;31m'
  NC='\033[0m'
  GREEN='\033[0;32m'
  BOLD='\033[1m'
  #printf "\n\n"
  #printf "${BOLD}############\n"
  #printf "VPC AUDIT\n"
  #printf "############${NC}\n\n"
  account=`aws sts get-caller-identity --output text --query 'Account'`
for  aws_region in ap-south-1 eu-west-2 eu-west-1 ap-northeast-2 ap-northeast-1 sa-east-1 ca-central-1 ap-southeast-1 ap-southeast-2 eu-central-1 us-east-1 us-east-2 us-west-1 us-west-2;do
    endpoints=`aws ec2 describe-vpc-endpoints --region $aws_region --query 'VpcEndpoints[*].VpcEndpointId' --output text`
  for enpoint in $endpoints; do
    check=`aws ec2 describe-vpc-endpoints --region $aws_region --vpc-endpoint-ids $enpoint --query 'VpcEndpoints[].PolicyDocument' |grep Principal |egrep "\*|{\"AWS\":\"\*\"}"`
    if [ "$check" ]; then
      printf "default,$account,$aws_region,null,WARNING,Scored,null,VPC_AUDIT,VPC $vpc has en exposed enpoint\n"
    else
      printf "default,$account,$aws_region,null,PASS,Scored,null,VPC_AUDIT,VPC $vpc does not have an exposed endpoint\n"
    fi
  done
  # Check for VPC peering
	peers=`aws ec2 describe-vpc-peering-connections --region $aws_region --query VpcPeeringConnections --output text`
  if [ ! "$peers" ]; then
    printf "default,$account,$aws_region,null,WARNING,Scored,null,VPC_AUDIT,VPC peering is not being used\n"
  else
    vpcs=`aws ec2 describe-vpcs --region $aws_region --query Vpcs[].VpcId --output text`
    for vpc in $vpcs; do
      check=`aws ec2 describe-route-tables --region $aws_region --filter "Name=vpc-id,Values=$vpc" --query "RouteTables[*].{RouteTableId:RouteTableId, VpcId:VpcId, Routes:Routes,AssociatedSubnets:Associations[*].SubnetId}" |grep GatewayID |grep pcx-`
      if [ "$check" ]; then
        printf "default,$account,$aws_region,null,WARNING,Scored,null,VPC_AUDIT,VPC peering is being used review VPC: $vpc\n"
      else
        printf "default,$account,$aws_region,null,PASS,Scored,null,VPC_AUDIT,VPC $vpc does not have a peer as it's gateway\n"
      fi
    done
  fi
  # Check for VPC flow logging
  logs=`aws ec2 describe-flow-logs --region $aws_region --query FlowLogs[].FlowLogId --output text`
  if [ "$logs" ]; then
    vpcs=`aws ec2 describe-vpcs --region $aws_region --query Vpcs[].VpcId --output text`
    for vpc in $vpcs; do
      check=`aws ec2 describe-flow-logs --region $aws_region --query FlowLogs[].ResourceId --output text`
      if [ "$check" ]; then
        active=`aws ec2 describe-flow-logs --region $aws_region --filter "Name=resource-id,Values=$vpc" |grep FlowLogStatus |grep ACTIVE`
        if [ ! "$active" ]; then
          printf "default,$account,$aws_region,null,WARNING,Scored,null,VPC_AUDIT,VPC $vpc has flow logs but they are not active\n"
        else
          printf "default,$account,$aws_region,null,PASS,Scored,null,VPC_AUDIT,VPC $vpc has active flow logs\n"
        fi
      else
        printf "default,$account,$aws_region,null,WARNING,Scored,null,VPC_AUDIT,VPC $vpc does not have flow logs in region $aws_region\n"
      fi
    done
  else
    printf "default,$account,$aws_region,null,INFO,Scored,null,VPC_AUDIT,There are no VPC $vpc flow logs $aws_region\n"
  fi
done
