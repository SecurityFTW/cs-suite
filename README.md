# Cloud Security Suite (cs-suite)

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

- Then run the follwing docker command to start

```bash
docker run -v `pwd`/aws:/root/.aws -v `pwd`/reports:/app/reports securityftw/cs-suite
```
- The final report will be available in `reports` directory

- The final report looks like below

![cs-suite report](cs-suite.png)

## Pre-requisites for Manual setup
* Python 2.7
* pip
* git
* gcc (for sshpass installation (OS Audit). Not a mandatory pre-requisite)
	
## Installation

```bash
git clone https://github.com/SecurityFTW/cs-suite.git
cd cs-suite/
sudo python setup.py
```

Note - Generate a set of ReadOnly AWS keys which the tool will ask to finish the installation process.

### Virtual Environment installation
(So you don't mess with the already installed python libraries)
   
 - `pip install virtualenvwrapper`
 - add it to the respective rc file of your shell (bashrc/zshrc) (for fish shell users check [virtualfish](https://github.com/adambrenecki/virtualfish))
 - `echo "source /usr/local/bin/virtualenvwrapper.sh" >> ~/.bashrc`
 - source the file 
    `source ~/.bashrc`
 - `cd cs-suite/` 
 -  `mkvirtualenv cssuite`
 -  `workon cssuite`
 - `pip install -r requirements-virtual.txt`
 - `aws configure`  

Once installation is done, the tool will ask you for the AWS keys and region. These two are mandatory for the tool to work.

### Running cs-suite

```bash
python cs.py
```

## Documentation
[https://securityftw.github.io/Docs](https://securityftw.github.io/Docs)

## Thanks
* Scout2 - https://github.com/nccgroup/Scout2
* Prowler - https://github.com/Alfresco/prowler
* Lunar - https://github.com/lateralblast/lunar
* Lynis - https://github.com/CISOfy/lynis
* @alanrenouf - https://github.com/alanrenouf/Windows-Workstation-and-Server-Audit
* Ranjeet Sengar - https://github.com/sengar23
