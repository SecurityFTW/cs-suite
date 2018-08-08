 #! /usr/bin/env python
from __future__ import print_function
import subprocess

def main():
    """ main function """
    try:
        print ("Installing dependencies...")
        subprocess.call(['sudo', 'pip', 'install', '-r', 'requirements.txt'])
        print ("Installing AWS CLI") # WINDOWS HAS NO SUDO
        subprocess.call(['sudo', 'pip', 'install', 'awscli', '--ignore-installed', 'six'])
        print ("Installing sshpass")
        subprocess.call(['sudo', 'tar', '-xvf', 'sshpass-1.06.tar.gz'], cwd = './tools')
        subprocess.check_output(['sudo', './configure'], cwd='tools/sshpass-1.06')
        subprocess.call(['sudo', 'make', 'install'], cwd='tools/sshpass-1.06/')
        print ("Please enter your AWS credetionals")
        subprocess.call(['aws', 'configure'])
    except:
        print ("FAILED in one of the steps")

if __name__ == '__main__':
    main()
