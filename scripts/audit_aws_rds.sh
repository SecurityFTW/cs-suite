#!/usr/bin/env bash
# audit_aws_rds
#
# Refer to https://www.cloudconformity.com/conformity-rules/RDS/rds-auto-minor-version-upgrade.html
# Refer to https://www.cloudconformity.com/conformity-rules/RDS/rds-automated-backups-enabled.html
# Refer to https://www.cloudconformity.com/conformity-rules/RDS/rds-encryption-enabled.html
# Refer to https://www.cloudconformity.com/conformity-rules/RDS/rds-publicly-accessible.html
# Refer to https://www.cloudconformity.com/conformity-rules/RDS/rds-encrypted-with-kms-customer-master-keys.html
# Refer to https://www.cloudconformity.com/conformity-rules/RDS/instance-not-in-public-subnet.html
# Refer to https://www.cloudconformity.com/conformity-rules/RDS/rds-master-username.html
#.
  RED='\033[0;31m'
  NC='\033[0m'
  GREEN='\033[0;32m'
  BOLD='\033[1m'
  #printf "\n\n"
  #printf "${BOLD}############\n"
  #printf " RDS AUDIT\n"
  #printf "############${NC}\n\n"
  account=`aws sts get-caller-identity --output text --query 'Account'`
for  aws_region in ap-south-1 eu-west-2 eu-west-1 ap-northeast-2 ap-northeast-1 sa-east-1 ca-central-1 ap-southeast-1 ap-southeast-2 eu-central-1 us-east-1 us-east-2 us-west-1 us-west-2;do
  dbs=`aws rds describe-db-instances --region $aws_region --query 'DBInstances[].DBInstanceIdentifier' --output text`
  for db in $dbs; do
    check=`aws rds describe-db-instances --region $aws_region --db-instance-identifier $db --query 'DBInstances[].MasterUsername' |grep "awsuser"`
    if [ "$check" ]; then
      echo -e "default,$account,$aws_region,null,WARNING,Scored,null,RDS_AUDIT,RDS instance $db is using aws-user as master username"
    else
      echo -e "default,$account,$aws_region,null,PASS,Scored,null,RDS_AUDIT,RDS instance $db is not using aws-user as master username"
    fi
  done
done
