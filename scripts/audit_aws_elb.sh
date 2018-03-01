#!/usr/bin/env bash
# audit_aws_elb
#
# Refer to http://docs.aws.amazon.com/elasticloadbalancing/latest/classic/elb-security-policy-table.html
# Refer to https://www.cloudconformity.com/conformity-rules/ELB/elb-access-log.html
# Refer to https://www.cloudconformity.com/conformity-rules/ELB/elb-insecure-ssl-ciphers.html
# Refer to https://www.cloudconformity.com/conformity-rules/ELB/elb-insecure-ssl-protocols.html
# Refer to https://www.cloudconformity.com/conformity-rules/ELB/elb-listener-security.html
# Refer to https://www.cloudconformity.com/conformity-rules/ELB/elb-security-group.html
#.
  RED='\033[0;31m'
  NC='\033[0m'
  GREEN='\033[0;32m'
  BOLD='\033[1m'
  #printf "\n\n"
  #printf "${BOLD}############\n"
  #printf "  ELB AUDIT  \n"
  #printf "############${NC}\n\n"
  account=`aws sts get-caller-identity --output text --query 'Account'`
  for  aws_region in ap-south-1 eu-west-2 eu-west-1 ap-northeast-2 ap-northeast-1 sa-east-1 ca-central-1 ap-southeast-1 ap-southeast-2 eu-central-1 us-east-1 us-east-2 us-west-1 us-west-2;do

       elbs=`aws elb describe-load-balancers --region $aws_region --query "LoadBalancerDescriptions[].LoadBalancerName" --output text`
           for elb in $elbs; do
               #echo "$elb"
               protocols=`aws elb describe-load-balancers --region $aws_region --load-balancer-name $elb  --query "LoadBalancerDescriptions[].ListenerDescriptions[].Listener[].Protocol" --output text`
               for protocol in $protocols;do
                   if [ "$protocol" == "HTTP" ];then
                      https=`aws elb describe-load-balancers --region $aws_region --load-balancer-name $elb --query "LoadBalancerDescriptions[].ListenerDescriptions[].Listener[]" | grep -B 1 80, | grep 443`
                      if [ ! "$https" ];then
                         printf "default,$account,$aws_region,null,WARNING,Scored,null,ELB_AUDIT,$elb is running only on http\n"
                      fi  
                   fi
               done
               list=`aws elb describe-load-balancer-policies --region $aws_region --load-balancer-name $elb --output text`
                for cipher in SSLv2 RC2-CBC-MD5 PSK-AES256-CBC-SHA PSK-3DES-EDE-CBC-SHA KRB5-DES-CBC3-SHA KRB5-DES-CBC3-MD5 \
                    PSK-AES128-CBC-SHA PSK-RC4-SHA KRB5-RC4-SHA KRB5-RC4-MD5 KRB5-DES-CBC-SHA KRB5-DES-CBC-MD5 \
                    EXP-EDH-RSA-DES-CBC-SHA EXP-EDH-DSS-DES-CBC-SHA EXP-ADH-DES-CBC-SHA EXP-DES-CBC-SHA \
                    SSLv3 EXP-RC2-CBC-MD5 EXP-KRB5-RC2-CBC-SHA EXP-KRB5-DES-CBC-SHA EXP-KRB5-RC2-CBC-MD5 \
                    EXP-KRB5-DES-CBC-MD5 EXP-ADH-RC4-MD5 EXP-RC4-MD5 EXP-KRB5-RC4-SHA EXP-KRB5-RC4-MD5; do
                    check=`echo "$list" |grep $cipher |grep true`
                    if [ "$check" ]; then
                        printf "default,$account,$aws_region,null,WARNING,Scored,null,ELB_AUDIT,ELB $elb is using deprecated cipher $cipher\n"
                    fi
                done
           done
  done
