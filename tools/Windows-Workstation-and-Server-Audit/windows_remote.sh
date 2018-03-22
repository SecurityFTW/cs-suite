#!/usr/bin/env bash
RED='\033[0;31m'
NC='\033[0m'
GREEN='\033[0;32m'
BOLD='\033[1m'
YELLOW='\033[0;33m'
time_stamp=`date "+%Y%m%d-%H%M"`
if [ "$#" -eq 4 ];then
   printf "${YELLOW}Attempting to copy files via SCP as Administrator user ......\n scp Administrator@$2 i.e Administrator@$3/Administrator@$4 ${NC}\n"
   scp=`scp -o "StrictHostKeyChecking no" -q ./Audit.ps1 Administrator@$2:/tmp`
   status=$?
   if [ $status -eq 0 ];then
      printf "${GREEN}Audit file copied over the server${NC}\n"
      printf "${YELLOW}Attempting to SSH the server..... \n ssh Administrator@$2 i.e Administrator@$3/Administrator@$4 ${NC}\n"
      audit=`ssh -o "StrictHostKeyChecking no" Administrator@$2  "cd /tmp;powershell -File Audit.ps1"`
      if [ $status -eq 0 ];then
         printf "${GREEN}Windows Audit Done${NC}\n"
         mkdir -p ../../reports/AWS/local_audit/$1/$3-$4/
         file=`scp Administrator@$2:/tmp/WIN* ../../reports/AWS/local_audit/$1/$3-$4/windows.report_$time_stamp.html`       
         printf "${GREEN}Cleaning up files${NC}\n"
         clean=`ssh Administrator@$2 "rm -rf /tmp/WIN-*"`
         printf "${BOLD} Report ------> reports/AWS/local_audit/$1/$3-$4/windows.report_$time_stamp.html${NC}\n"
         open "../../reports/AWS/local_audit/$1/$3-$4/windows.report_$time_stamp.html"
      else
         printf "${RED}Not able SSH the server...please try using help 'python cs.py -h'${NC}\n"
      fi
   else
      printf "${RED}Not able to SCP please try using help 'python cs.py -h'${NC}\n"
   fi

elif [[ -z "$6" && -z "$7" ]];then
   printf "${YELLOW}Attempting to copy files via SCP  ......\n scp $5@$2 i.e $5@$3/$5@$4 ${NC}\n"
   scp=`scp -o "StrictHostKeyChecking no" -q ./Audit.ps1 $5@$2:~/`
   status=$?
   if [ $status -eq 0 ];then
      printf "${GREEN}Audit file copied over the server${NC}\n"
      printf "${YELLOW}Attempting to SSH the server..... \n ssh $5@$2 i.e $5@$3/$5@$4 ${NC}\n"
      audit=`ssh -o "StrictHostKeyChecking no" $5@$2 "cd ~;powershell -File Audit.ps1"`
      if [ $status -eq 0 ];then
         printf "${GREEN}Windows Audit Done${NC}\n"   
         mkdir -p ../../reports/AWS/local_audit/$1/$3-$4/
         file=`scp $5@$2:~/WIN* ../../reports/AWS/local_audit/$1/$3-$4/windows.report_$time_stamp.html`
         printf "${GREEN}Cleaning up files${NC}\n"
         clean=`ssh $5@$2 "rm -rf ~/WIN-*"`
         printf "${BOLD} Report ------> reports/AWS/local_audit/$1/$3-$4/windows.report_$time_stamp.html${NC}\n"
         open "../../reports/AWS/local_audit/$1/$3-$4/windows.report_$time_stamp.html"
      else
         printf "${RED}Not able SSH the server...please try using help 'python cs.py -h'${NC}\n"
      fi
   else
      printf "${RED}Not able to SCP please try using help 'python cs.py -h'${NC}\n"   
   fi

elif [[ -z "$5" && -z "$7" ]];then
     printf "${YELLOW}Attempting to copy files via SCP  ......\n scp -i $6 Administrator@$2${NC}\n"
     scp=`scp -i $6 -o "StrictHostKeyChecking no" -q ./Audit.ps1 Administrator@$2:/tmp`
     status=$?
     if [ $status -eq 0 ];then
        printf "${GREEN}Audit file copied over the server${NC}\n"
        printf "${YELLOW}Attempting to SSH the server..... \n ssh -i $6 Administrator@$2 i.e Administrator@$3/Administrator@$4 ${NC}\n"
        audit=`ssh -o "StrictHostKeyChecking no" -i $6 Administrator@$2 "cd /tmp;powershell -File Audit.ps1"`
        if [ $status -eq 0 ];then
           printf "${GREEN}Windows Audit Done${NC}\n"
           mkdir -p ../../reports/AWS/local_audit/$1/$3-$4/
           file=`scp -i $6  Administrator@$2:/tmp/WIN* ../../reports/AWS/local_audit/$1/$3-$4/windows.report_$time_stamp.html`
           printf "${GREEN}Cleaning up files${NC}\n"
           clean=`ssh -i $6  Administrator@$2 "rm -rf /tmp/WIN-*"`
           printf "${BOLD} Report ------> reports/AWS/local_audit/$1/$3-$4/windows.report_$time_stamp.html${NC}\n"
           open "../../reports/AWS/local_audit/$1/$3-$4/windows.report_$time_stamp.html"
        else
           printf "${RED}Not able SSH the server...please try using help 'python cs.py -h'${NC}\n"        
        fi
     else
        printf "${RED}Not able to SCP please try using help 'python cs.py -h'${NC}\n"
     fi   

elif [[ -z "$5" && -z "$6" ]];then
     printf "${YELLOW}Attempting to copy files via SCP  ......\n sshpass -p "password" scp Administrator@$2 i.e Administrator @$3/Administrator@$4 ${NC}\n"
     scp=`sshpass -p $7 scp -o "StrictHostKeyChecking no" -q ./Audit.ps1 Administrator@$2:/tmp`
     status=$?
     if [ $status -eq 0 ];then
        printf "${GREEN}Audit file copied over the server${NC}\n"
        printf "${YELLOW}Attempting to SSH the server..... \n sshpass -p password ssh Administrator@$2 ${NC}\n"
        audit=`sshpass -p $7 ssh -o 'StrictHostKeyChecking no' Administrator@$2 "cd /tmp;powershell -File Audit.ps1"`
        if [ $status -eq 0 ];then
           printf "${GREEN}Windows Audit Done${NC}\n"
           mkdir -p ../../reports/AWS/local_audit/$1/$3-$4/
           file=`sshpass -p $7 scp Administrator@$2:/tmp/WIN* ../../reports/AWS/local_audit/$1/$3-$4/windows.report_$time_stamp.html`
           printf "${GREEN}Cleaning up files${NC}\n"
           clean=`sshpass -p $7 ssh Administrator@$2 "rm -rf /tmp/WIN-*"`
           printf "${BOLD} Report ------> reports/AWS/local_audit/$1/$3-$4/windows.report_$time_stamp.html${NC}\n"
           open "../../reports/AWS/local_audit/$1/$3-$4/windows.report_$time_stamp.html"
        else
           printf "${RED}Not able SSH the server...please try using help 'python cs.py -h'${NC}\n"
        fi
     else
        printf "${RED}Not able to SCP please try using help 'python cs.py -h'${NC}\n"
     fi 

elif [ -z "$6" ];then
     printf "${YELLOW}Attempting to copy files via SCP  ......\n sshpass -p "password" scp $5@$2 i.e $5@$3/$5@$4 ${NC}\n"
     scp=`sshpass -p $7 scp -o "StrictHostKeyChecking no" -q ./Audit.ps1 $5@$2:~/`
     status=$?
     if [ $status -eq 0 ];then
       printf "${GREEN}Audit file copied over the server${NC}\n"
       printf "${YELLOW}Attempting to SSH the server..... \n sshpass -p password ssh $5@$2 ${NC}\n"
       audit=`sshpass -p $7 ssh -o 'StrictHostKeyChecking no' $5@$2 "cd ~;powershell -File Audit.ps1"`
       if [ $status -eq 0 ];then
           printf "${GREEN}Windows Audit Done${NC}\n"
           mkdir -p ../../reports/AWS/local_audit/$1/$3-$4/
           file=`sshpass -p $7 scp $5@$2:~/WIN* ../../reports/AWS/local_audit/$1/$3-$4/windows.report_$time_stamp.html`
           printf "${GREEN}Cleaning up files${NC}\n"
           clean=`sshpass -p $7 ssh $5@$2 "rm -rf ~/WIN-*"`
           printf "${BOLD} Report ------> reports/AWS/local_audit/$1/$3-$4/windows.report_$time_stamp.html${NC}\n"
           open "../../reports/AWS/local_audit/$1/$3-$4/windows.report_$time_stamp.html"
        else
           printf "${RED}Not able SSH the server...please try using help 'python cs.py -h'${NC}\n"
        fi
     else
        printf "${RED}Not able to SCP please try using help 'python cs.py -h'${NC}\n"
     fi
elif [ -z "$7" ];then
   printf "${YELLOW}Attempting to copy files via SCP  ......\n scp -i $6 $5@$2 i.e $5@$3/$5@$4 ${NC}\n"
   scp=`scp -i $6 -o "StrictHostKeyChecking no" -q ./Audit.ps1 $5@$2:~/`
   status=$?
   if [ $status -eq 0 ];then
      printf "${GREEN}Audit file copied over the server${NC}\n"
      printf "${YELLOW}Attempting to SSH the server..... \n ssh -i $6 $5@$2  ${NC}\n"
      audit=`ssh -i $6 -o 'StrictHostKeyChecking no' $5@$2 "cd ~;powershell -File Audit.ps1"`
      if [ $status -eq 0 ];then
          printf "${GREEN}Windows Audit Done${NC}\n"
          mkdir -p ../../reports/AWS/local_audit/$1/$3-$4/
          file=`scp -i $6 $5@$2:~/WIN* ../../reports/AWS/local_audit/$1/$3-$4/windows.report_$time_stamp.html`
          printf "${GREEN}Cleaning up files${NC}\n"
          clean=`ssh -i $6 $5@$2 "rm -rf ~/WIN-*"`
          printf "${BOLD} Report ------> reports/AWS/local_audit/$1/$3-$4/windows.report_$time_stamp.html${NC}\n"
          open "../../reports/AWS/local_audit/$1/$3-$4/windows.report_$time_stamp.html"
      else
       printf "${RED}Not able SSH the server...please try using help 'python cs.py -h'${NC}\n"
      fi
   else
       printf "${RED}Not able to SCP please try using help 'python cs.py -h'${NC}\n"
   fi
elif [ -z "$5" ];then
   printf "${YELLOW}Attempting to copy files via SCP  ......\n sshpass -p "password" scp -i $6 Administrator@$2 i.e Administrator@$3/Administrator@$4 ${NC}\n"
   scp=`sshpass -p $7 scp -i $6 -o "StrictHostKeyChecking no" -q ./Audit.ps1  Administrator@$2:/tmp`
   status=$?
   if [ $status -eq 0 ];then
       printf "${GREEN}Audit file copied over the server${NC}\n"
       printf "${YELLOW}Attempting to SSH the server..... \n sshpass -p password ssh -i $6 Administrator@$2  ${NC}\n"
       audit=`sshpass -p password ssh -i $6 -o "StrictHostKeyChecking no" Administrator@$2 "cd /tmp;powershell -File Audit.ps1"`
       status=$?
       if [ $status -eq 0 ];then
           printf "${GREEN}Windows Audit Done${NC}\n"
           mkdir -p ../../reports/AWS/local_audit/$1/$3-$4
           file=`sshpass -p password scp -i $6 Administrator@$2:/tmp/WIN* ../../reports/AWS/local_audit/$1/$3-$4/windows.report_$time_stamp.html`
           printf "${GREEN}Cleaning up files${NC}\n"
           clean=`sshpass -p $7 ssh -i $6 Administrator@$2 "rm -rf /tmp/WIN-*"`
           printf "${BOLD} Report ------> reports/AWS/local_audit/$1/$3-$4/windows.report_$time_stamp.html${NC}\n"
           open "../../reports/AWS/local_audit/$1/$3-$4/windows.report_$time_stamp.html"
       else
           printf "${RED}Not able SSH the server with user Administrator... try using help 'python cs.py -h'${NC}\n"
       fi
   else
       printf "${RED}Not able to SCP please try using help 'python cs.py -h'${NC}\n"
   fi
else
   printf "${YELLOW}Attempting to copy files via SCP  ......\n sshpass -p "password" scp -i $6 $5@$2 i.e $5@$3/$5@$4 ${NC}\n"
   scp=`sshpass -p $7 scp -i $6 -o "StrictHostKeyChecking no" -q ./Audit.ps1  $5@$2:~/`
   status=$?
   if [ $status -eq 0 ];then
       printf "${GREEN}Audit file copied over the server${NC}\n"
       printf "${YELLOW}Attempting to SSH the server..... \n sshpass -p password ssh -i $6 $5@$2  ${NC}\n"
       audit=`sshpass -p password ssh -i $6 -o "StrictHostKeyChecking no" $5@$2 "cd ~;powershell -File Audit.ps1"`
       status=$?
       if [ $status -eq 0 ];then
           printf "${GREEN}Windows Audit Done${NC}\n"
           mkdir -p ../../reports/AWS/local_audit/$1/$3-$4
           file=`sshpass -p password scp -i $6 $5@$2:~/WIN* ../../reports/AWS/local_audit/$1/$3-$4/windows.report_$time_stamp.html`
           printf "${GREEN}Cleaning up files${NC}\n"
           clean=`sshpass -p $7 ssh -i $6 $5@$2 "rm -rf ~/WIN-*"`
           printf "${BOLD} Report ------> reports/AWS/local_audit/$1/$3-$4/windows.report_$time_stamp.html${NC}\n"
           open "../../reports/AWS/local_audit/$1/$3-$4/windows.report_$time_stamp.html"
       else
           printf "${RED}Not able SSH the server with user $5... try using help 'python cs.py -h'${NC}\n"
       fi
   else
       printf "${RED}Not able to SCP please try using help 'python cs.py -h'${NC}\n"
   fi


fi
