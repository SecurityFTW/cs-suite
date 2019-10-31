#!/usr/bin/env python
"""
This module is to define the retention period for reports
"""
import os
import pathlib
import glob
import shutil
import logging


def get_folders_list(directory, number):
    """Function to get folder list"""
    try:
        list_of_all_folders = sorted(glob.glob(os.path.join(directory, '*/')), reverse=True)
        list_of_all_folders = list_of_all_folders[number:]
        return list_of_all_folders
    except Exception as identifier:
        logging.exception(identifier)


def delete_folder(directory, number):
    """Function to delete the folder"""
    try:
        deleting_list = get_folders_list(directory, number)
        for folder in deleting_list:
            shutil.rmtree(folder)
    except IndexError as identifier:
        print("There is an Index Error.")
    except Exception as identifier:
        logging.exception(identifier)


def retain_reports(enviroment, number,project_name):
    """Function to retain reports on the basis days"""
    aws_report_path = 'reports/AWS/aws_audit'
    gcp_report_path = 'reports/GCP'
    azure_report_path = 'reports/AZURE'
    current_path = os.getcwd()
    if enviroment == "aws":
        from modules import awsaudit
        clean_reports(current_path, aws_report_path, number, awsaudit.account_name)

    elif enviroment == "azure":
        from modules import azureaudit
        clean_reports(current_path, azure_report_path, number, azureaudit.account_name)

    elif enviroment == 'gcp':
        from modules import gcpaudit
        clean_reports(current_path, gcp_report_path, number,project_name)


def clean_reports(current_path, cloud_report_default_path, number, account_name):
    """Function to cleanup reports"""
    try:
        report_default_path = os.path.join(current_path, cloud_report_default_path)
        os.chdir(report_default_path)
        cloud_account_final_path = pathlib.Path(account_name)
        if cloud_account_final_path.exists():
            cloud_account_path = os.path.join(report_default_path, account_name)
            os.chdir(cloud_account_path)
            delete_folder(cloud_account_path, number)
    except Exception as identifier:
        logging.exception(identifier)
