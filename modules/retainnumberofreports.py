#!/usr/bin/env python
import os
import pathlib
import glob
import time
import shutil
import logging
from modules import gcpaudit
from modules import awsaudit
from modules import azureaudit

def getListOfFoldersToDelete(directory, number):
    try:
        list_of_all_folders = sorted(glob.glob(os.path.join(directory, '*/')), reverse=True)
        list_of_all_folders = list_of_all_folders[number:]
        return list_of_all_folders
    except Exception as identifier:
        logging.exception(identifier)


def deleteUnrequiredFolder(directory, number):
    try:
        deletingList = getListOfFoldersToDelete(directory, number)
        for folder in deletingList:
            shutil.rmtree(folder)
    except IndexError as identifier:
        print("There is an Index Error.")
    except Exception as identifier:
        logging.exception(identifier)


def retainReports(enviroment, number):
    aws_report_path = 'reports/AWS/aws_audit'
    gcp_report_path = 'reports/GCP'
    azure_report_path = 'reports/AZURE'
    current_path = os.getcwd()
    if(enviroment == "aws"):
        cleanReports(current_path, aws_report_path, number, awsaudit.account_name)
        
    elif(enviroment == "azure"):
        cleanReports(current_path, azure_report_path, number, azureaudit.account_name)

    elif(enviroment == 'gcp'):
        cleanReports(current_path, gcp_report_path, number, gcpaudit.project_name)


def cleanReports(current_path, cloud_report_default_path, number, account_name):
    try:
        report_default_path = os.path.join(current_path, cloud_report_default_path)
        os.chdir(report_default_path)
        cloud_account_final_path = pathlib.Path(account_name)
        if cloud_account_final_path.exists():
            cloud_account_path = os.path.join(report_default_path, account_name)
            os.chdir(cloud_account_path)
            deleteUnrequiredFolder(cloud_account_path, number)
    except Exception as identifier:
        logging.exception(identifier)
