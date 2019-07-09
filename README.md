# Cloud Security Suite (cs-suite) - Version 3.0

## Pre-requisites for Manual setup
* OS - MacOS or Linux
* Python 2.7
* pip
* git
* gcc (for sshpass installation (OS Audit). Not a mandatory pre-requisite)
* AWS Audit - AWS ReadOnly Keys
* GCP Audit - gcloud setup
* Azure Audit - Azure user read-only access
	
## Installation

```bash
git clone https://github.com/SecurityFTW/cs-suite.git
cd cs-suite/
sudo python setup.py
```

### Virtual Environment Installation
(in order to avoid missing with the already installed python libraries)
   
 - install [virtualenv](https://virtualenv.pypa.io/en/latest/) `pip install virtualenv`
 - create a python 2.7 local enviroment `virtualenv -p python2.7 venv`  
 - activate the virtual enviroment `source venv/bin/activate` 
 - install project dependencies `pip install -r requirements.txt`
 - run the tool via `python cs.py -h`

### AWS Configuration
- In AWS create a IAM user with at least the following policy `arn:aws:iam::aws:policy/ReadOnlyAccess` 
- In your local [install aws cli](https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-install.html) `brew install awsscli` _for OSX_  
- Configure AWS cli `aws configure`

### GCP Configuration
- create a [project](https://cloud.google.com/resource-manager/docs/creating-managing-projects) in GCP
- create a [service account](https://cloud.google.com/iam/docs/creating-managing-service-account-keys#creating_service_account_keys), download its key JSON and place it on the root of this project (example `cs-suite/keyfile.json`)
- Install [google cloud sdk](https://cloud.google.com/sdk/install#installation_options)
- configure google clound sdk `gcloud init`  

### Azure Comfiguration

Note - Generate a set of ReadOnly AWS keys which the tool will ask to finish the installation process. For GCP, setup google cloud SDK.


## Running cs-suite

```bash
To run AWS Audit - python cs.py -env aws
To run GCP Audit - python cs.py -env gcp -pId <project_name>
To run Azure Audit - python cs.py -env azure
```
- The final report will be available in `reports` directory

- The final AWS Audit report looks like below:

![AWS Audit report](AWS_Audit_Report.png)

- The final GCP Audit report looks like below:

![GCP Audit report](GCP_Audit_Report.png)


## Docker Setup

- Create a local directory `aws` with `credentials` and `config` files

- The `config` file looks like below

```bash
$ cat aws/config

[default]
output = json
region = us-east-1

```
- The `credentials` file looks like below

```bash
$ cat aws/credentials

[default]
aws_access_key_id = XXXXXXXXXXXXXXX
aws_secret_access_key = XXXXXXXXXXXXXXXXXXXXXXXXX
```
***Note: This tool requires `arn:aws:iam::aws:policy/ReadOnlyAccess` IAM policy***

- Then run the follwing docker command to start (passing your specific enviroment)

```bash
docker run -v `pwd`/aws:/root/.aws -v `pwd`/reports:/app/reports securityftw/cs-suite -env aws
```

## Documentation
[https://securityftw.github.io](https://securityftw.github.io)

## Thanks
* Scout2 - https://github.com/nccgroup/Scout2
* Prowler - https://github.com/Alfresco/prowler
* Lunar - https://github.com/lateralblast/lunar
* Lynis - https://github.com/CISOfy/lynis
* G-Scout - https://github.com/nccgroup/G-Scout
* @alanrenouf - https://github.com/alanrenouf/Windows-Workstation-and-Server-Audit
* Ranjeet Sengar - https://github.com/sengar23
