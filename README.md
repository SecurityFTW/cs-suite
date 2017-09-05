# Cloud Security Suite (cs-suite)

# Pre-requisites
	Python 2.7
	pip
	git
	
# Installation #
	git clone https://github.com/SecurityFTW/cs-suite.git
	cd cs-suite/
	sudo python setup.py
Note - Generate a set of ReadOnly AWS keys which the tool will ask to finish the installation process.

### Virtual Environment installation
   (So you don't mess with the already installed python libraries)
   
 - `pip install virtualenvironmentwrapper`
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

## Run ##
	python cs.py

## Documentation ##
<https://securityftw.github.io/Docs/>

## Thanks ##
	Scout2 - https://github.com/nccgroup/Scout2
	Prowler - https://github.com/Alfresco/prowler
	Lynis - https://github.com/CISOfy/lynis
	@alanrenouf - https://github.com/alanrenouf/Windows-Workstation-and-Server-Audit
	Ranjeet Sengar - https://github.com/sengar23
