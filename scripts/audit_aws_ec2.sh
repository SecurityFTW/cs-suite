#!/usr/bin/env bash
# audit_aws_ec2
#
# Refer to https://www.cloudconformity.com/conformity-rules/EC2/default-securitygroups-in-use.html
# Refer to https://www.cloudconformity.com/conformity-rules/EC2/ec2-instance-using-iam-roles.html
# Refer to https://www.cloudconformity.com/conformity-rules/EC2/publicly-shared-ami.html
# Refer to https://www.cloudconformity.com/conformity-rules/EBS/ebs-encrypted.html
# Refer to https://www.cloudconformity.com/conformity-rules/EBS/ebs-encrypted-with-kms-customer-master-keys.html
#.
  RED='\033[0;31m'
  NC='\033[0m'
  GREEN='\033[0;32m'
  BOLD='\033[1m'
  #printf "\n\n"
  #printf "${BOLD}############\n"
  #printf "EC2 AUDIT\n"
  #printf "############${NC}\n\n"
  account=`aws sts get-caller-identity --output text --query 'Account'`
for  aws_region in ap-south-1 eu-west-2 eu-west-1 ap-northeast-2 ap-northeast-1 sa-east-1 ca-central-1 ap-southeast-1 ap-southeast-2 eu-central-1 us-east-1 us-east-2 us-west-1 us-west-2;do
  check=`aws ec2 describe-instances --region $aws_region --query 'Reservations[*].Instances[?!IamInstanceProfile==\`true\`].InstanceId[]' --output text`
  if [[ ! -z $check ]];then
      checkb=`aws ec2 describe-instances --region $aws_region --query 'Reservations[*].Instances[?!IamInstanceProfile==\`true\`].InstanceId[]' --output text`
      printf "default,$account,$aws_region,null,WARNING,Scored,null,EC2_AUDIT,List of servers which are not associated with IamInstanceProfile $check \n"
  fi
  public=`aws ec2 describe-images --region $aws_region --owners self --query 'Images[?Public==\`true\`].ImageId' --output text`
    if [ "$public" ]; then
      printf "default,$account,$aws_region,null,WARNING,Scored,null,EC2_AUDIT,List of Images which are public $public\n"
    fi
  check=`aws ec2 describe-volumes --region $aws_region --query 'Volumes[?Encrypted==\`false\`].VolumeId' --output text`
  if [[ ! -z $check ]];then
      checkb=`aws ec2 describe-volumes --region $aws_region --query 'Volumes[?Encrypted==\`false\`].VolumeId' --output text`
      printf "default,$account,$aws_region,null,WARNING,Scored,null,EC2_AUDIT,List of volumes which are not encrypted $checkb\n"
  fi
  kms=`aws ec2 describe-volumes --region $aws_region --query 'Volumes[?!KmsKeyId==\`true\`].VolumeId' --output text`
  if [[ ! -z $kms ]];then
      kmsb=`aws ec2 describe-volumes --region $aws_region --query 'Volumes[?!KmsKeyId==\`true\`].VolumeId' --output text`
      printf "default,$account,$aws_region,null,WARNING,Scored,null,EC2_AUDIT,List of volumes which are not encrypted with KMS key are $kmsb\n"
  fi
done
