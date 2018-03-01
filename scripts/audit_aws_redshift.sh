#!/usr/bin/env bash
# audit_aws_redshift
#
# Refer to https://www.cloudconformity.com/conformity-rules/Redshift/cluster-allow-version-upgrade.html
# Refer to https://www.cloudconformity.com/conformity-rules/Redshift/redshift-cluster-audit-logging-enabled.html
# Refer to https://www.cloudconformity.com/conformity-rules/Redshift/redshift-cluster-encrypted.html
# Refer to https://www.cloudconformity.com/conformity-rules/Redshift/redshift-cluster-encrypted-with-kms-customer-master-keys.html
# Refer to https://www.cloudconformity.com/conformity-rules/Redshift/redshift-cluster-in-vpc.html
# Refer to https://www.cloudconformity.com/conformity-rules/Redshift/redshift-parameter-groups-require-ssl.html
# Refer to https://www.cloudconformity.com/conformity-rules/Redshift/redshift-cluster-publicly-accessible.html
#.
  RED='\033[0;31m'
  NC='\033[0m'
  GREEN='\033[0;32m'
  BOLD='\033[1m'
  #printf "\n\n"
  #printf "${BOLD}############\n"
  #printf "RedShift AUDIT\n"
  #printf "############${NC}\n\n"
  account=`aws sts get-caller-identity --output text --query 'Account'`
for  aws_region in ap-south-1 eu-west-2 eu-west-1 ap-northeast-2 ap-northeast-1 sa-east-1 ca-central-1 ap-southeast-1 ap-southeast-2 eu-central-1 us-east-1 us-east-2 us-west-1 us-west-2;do
  dbs=`aws redshift describe-clusters --region $aws_region --query 'Clusters[].ClusterIdentifier' --output text`
  for db in $dbs; do
    # Check if version upgrades are enabled
    check=`aws redshift describe-clusters --region $aws_region --cluster-identifier $db --query 'Clusters[].AllowVersionUpgrade' |grep true`
    if [ ! "$check" ]; then
       printf "default,$account,$aws_region,null,WARNING,Scored,null,REDSHIFT_AUDIT,Redshift instance $db does not have version upgrades enabled\n"
    else
       printf "default,$account,$aws_region,null,PASS,Scored,null,REDSHIFT_AUDIT,Redshift instance $db has version upgrades enabled\n"
    fi
    # Check if audit logging is enabled
    check=`aws redshift describe-logging-status --region $aws_region --cluster-identifier $db |grep true`
    if [ ! "$check" ]; then
      printf "default,$account,$aws_region,null,WARNING,Scored,null,REDSHIFT_AUDIT,Redshift instance $db does not have logging enabled\n"
    else
      printf "default,$account,$aws_region,null,PASS,Scored,null,REDSHIFT_AUDIT,Redshift instance $db has logging enabled\n"
    fi
    # Check if encryption is enabled
    check=`aws redshift describe-logging-status --region $aws_region --cluster-identifier $db --query 'Clusters[].Encrypted' |grep true`
    if [ ! "$check" ]; then
      printf "default,$account,$aws_region,null,WARNING,Scored,null,REDSHIFT_AUDIT,Redshift instance $db does not have encryption enabled\n"
    else
      printf "default,$account,$aws_region,null,PASS,Scored,null,REDSHIFT_AUDIT,Redshift instance $db has encryption enabled\n"
    fi
    # Check if KMS keys are being used
    check=`aws redshift describe-logging-status --region $aws_region --cluster-identifier $db --query 'Clusters[].[Encrypted,KmsKeyId]' |grep true`
    if [ ! "$check" ]; then
      printf "default,$account,$aws_region,null,WARNING,Scored,null,REDSHIFT_AUDIT,Redshift instance $db is not using KMS keys\n"
    else
      printf "default,$account,$aws_region,null,PASS,Scored,null,REDSHIFT_AUDIT,Redshift instance $db is using KMS keys\n"
    fi
    # Check if EC2-VPC platform is being used rather than EC2-Classic
    check=`aws redshift describe-logging-status --region $aws_region --cluster-identifier $db --query 'Clusters[].VpcId' --output text`
    if [ ! "$check" ]; then
      printf "default,$account,$aws_region,null,WARNING,Scored,null,REDSHIFT_AUDIT,Redshift instance $db may be using the EC2-Classic platform\n"
    else
      printf "default,$account,$aws_region,null,PASS,Scored,null,REDSHIFT_AUDIT,Redshift instance $db is using the EC2-VPC platform\n"
    fi
    # Check that parameter groups require SSL
    groups=`aws redshift describe-logging-status --region $aws_region --cluster-identifier $db --query 'Clusters[].ClusterParameterGroups[].ParameterGroupName[]' --output text`
    for group in $groups; do
      check=`aws redshift describe-cluster-parameters --region $aws_region --parameter-group-name $group --query 'Parameters[].Description' |grep -i ssl`
      if [ ! "$check" ]; then
        printf "default,$account,$aws_region,null,WARNING,Scored,null,REDSHIFT_AUDIT,Redshift instance $db parameter group $group is not using SSL\n"
      else
        printf "default,$account,$aws_region,null,PASS,Scored,null,REDSHIFT_AUDIT,Redshift instance $db parameter group $group is using SSL\n"
      fi
    done
    # Check if Redshift is publicly available
    check=`aws redshift describe-logging-status --region $aws_region --cluster-identifier $db --query 'Clusters[].PubliclyAccessible' |grep true`
    if [ "$check" ]; then
      printf "default,$account,$aws_region,null,WARNING,Scored,null,REDSHIFT_AUDIT,Redshift instance $db is publicly available\n"
    else
      printf "default,$account,$aws_region,null,PASS,Scored,null,REDSHIFT_AUDIT,Redshift instance $db is not publicly available\n"
    fi
  done
done
