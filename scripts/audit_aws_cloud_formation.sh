#!/usr/bin/env bash
# audit_aws_cf
#
# Refer to https://www.cloudconformity.com/conformity-rules/CloudFormation/cloudformation-stack-notification.html
# Refer to https://www.cloudconformity.com/conformity-rules/CloudFormation/cloudformation-stack-policy.html
#.
  RED='\033[0;31m'
  NC='\033[0m'
  GREEN='\033[0;32m'
  BOLD='\033[1m'
  # Check Cloud Formation stacks are using SNS
  #printf "\n\n"
  #printf "${BOLD}##############\n"
  #printf "CloudFormation AUDIT\n"
  #printf "##############${NC}\n\n"
  account=`aws sts get-caller-identity --output text --query 'Account'`
for  aws_region in ap-south-1 eu-west-2 eu-west-1 ap-northeast-2 ap-northeast-1 sa-east-1 ca-central-1 ap-southeast-1 ap-southeast-2 eu-central-1 us-east-1 us-east-2 us-west-1 us-west-2;do
  stacks=`aws cloudformation list-stacks --region $aws_region --query "StackSummaries[?StackStatus != 'DELETE_COMPLETE'].StackId" --output text` 
  for stack in $stacks; do 
    check=`aws cloudformation describe-stacks --region $aws_region --stack-name $stack --query 'Stack[].NotificationARNs' --output text`
    stack=`printf "$stack" |cut -f2 -d/`
    if [ ! "$check" ]; then
      printf "default,$account,$aws_region,null,WARNING,Scored,null,CLOUD_FORMATION_AUDIT,SNS topic does not exist for CloudFormation stack $stack\n"
    else 
      printf "default,$account,$aws_region,null,PASS,Scored,null,CLOUD_FORMATION_AUDIT,SNS topic does exist for CloudFormation stack $stack\n"
    fi
  done
  # Check stacks have a policy
  stacks=`aws cloudformation list-stacks --region $aws_region --query "StackSummaries[?StackStatus != 'DELETE_COMPLETE'].StackName" --output text`
    for stack in $stacks; do 
    check=`aws cloudformation get-stack-policy --region $aws_region --stack-name $stack --query 'StackPolicyBody' --output text 2> /dev/null`
    if [ ! "$check" ]; then
      printf "default,$account,$aws_region,null,WARNING,Scored,null,CLOUD_FORMATION_AUDIT,CloudFormation stack $stack does not have a policy\n"
    else
      printf "default,$account,$aws_region,null,PASS,Scored,null,CLOUD_FORMATION_AUDIT,CloudFormation stack $stack has a policy\n"
    fi
  done
done
