#!/usr/bin/env python
import os
import pathlib
import glob
import time
import shutil
import logging

def listOfFolder(number, directory):
    try:
        listOfReports = []
        for i in range(number):
            listOfReports.append(sorted(glob.glob(os.path.join(directory, '*/')))[-i-1])
        return listOfReports
    except Exception as identifier:
        logging.exception(identifier)
    

def inverseList(directory, number):
    try:
        totalFolderList = sorted(glob.glob(os.path.join(directory, '*/')))
        selectedFolder = listOfFolder(number, directory)
        ListOfDeletingFolder = set(totalFolderList).difference(selectedFolder)
        return ListOfDeletingFolder
    except Exception as identifier:
        logging.exception(identifier)


def deleteListOfFolder(directory, number):
    
    if(number < 0):
        exit(1)
    else:
        try:
            deletingList = inverseList(directory, number)
            for i in deletingList:
                shutil.rmtree(i)
        except IndexError:
            pass


def numberOfReports(enviroment, number):
    currentPath = os.getcwd()
    
    if(enviroment == 'aws'):
        aws(currentPath, number)
        
    elif(enviroment == 'azure'):
        azure(currentPath, number)

    elif(enviroment == 'gcp'):
        gcp(currentPath, number)


def aws(currentPath, number):
    try:
        from modules import awsaudit
        awsPath = os.path.join(currentPath, 'reports/AWS/aws_audit')
        os.chdir(awsPath)
        aws = pathlib.Path(awsaudit.account_name)
        if aws.exists():
            awsUser = os.path.join(awsPath, awsaudit.account_name)
            os.chdir(awsUser)
            deleteListOfFolder(awsUser, number)
    except Exception as identifier:
        logging.exception(identifier)

def gcp(currentPath, number):
    try:
        from module import gcpaudit
        gcpPath = os.path.join(currentPath, 'reports/GCP')
        os.chdir(gcpPath)
        gcp = pathlib.Path(gcpaudit.project_name)
        if gcp.exists():
            gcpUser = os.path.join(gcp, gcpaudit.project_name)
            os.chdir(gcpUser)
            deleteListOfFolder(gcpUser, number)
    except Exception as identifier:
        logging.exception(identifier)

def azure(currentPath, number):
    try:
        from modules import azureaudit
        azurePath = os.path.join(currentPath, 'reports/AZURE')
        os.chdir(azurePath)
        azure = pathlib.Path(azureaudit.account_name)
        if azure.exists():
            azureUser = os.path.join(azurePath, azureaudit.account_name)
            os.chdir(azureUser)
            deleteListOfFolder(azureUser, number)
    except Exception as identifier:
        logging.exception(identifier)