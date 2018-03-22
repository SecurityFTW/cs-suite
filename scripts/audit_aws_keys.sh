#!/usr/bin/env bash
# audit_aws_keys
#
# Refer to Section(s) 2.8 Page(s) 85-6 CIS AWS Foundations Benchmark v1.1.0
# Refer to https://www.cloudconformity.com/conformity-rules/IAM/unnecessary-ssh-public-keys.html
# Refer to https://www.cloudconformity.com/conformity-rules/KMS/key-rotation-enabled.html
# Refer to https://www.cloudconformity.com/conformity-rules/KMS/unused-customer-master-key.html
  RED='\033[0;31m'
  NC='\033[0m'
  GREEN='\033[0;32m'
  BOLD='\033[1m'
  #printf "\n\n"
  aws_region=`aws configure get region`
  #printf "${BOLD}############\n"
  #printf "AWS SSH AUDIT\n"
  #printf "############${NC}\n\n"
  # Check for SSH keys
  account=`aws sts get-caller-identity --output text --query 'Account'`
  users=`aws iam list-users --query 'Users[].UserName' --output text`
  for user in $users; do
    check=`aws iam list-ssh-public-keys --region $aws_region --user-name $user |grep Active |wc -l`
    if [ "$check" -gt 1 ]; then
      printf "default,$account,us-east-1,null,WARNING,Scored,null,AWS_KEY_AUDIT,User $user does has more than one active SSH key\n"
    else
      printf "default,$account,us-east-1,null,PASS,Scored,null,AWS_KEY_AUDIT,User $user does not have any active SSH key\n"
    fi 
  done
