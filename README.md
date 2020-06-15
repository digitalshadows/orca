
# Orca - Targeted OSINT Framework

<p align="center">
  <img src="https://user-images.githubusercontent.com/18053679/62146061-80890480-b2ec-11e9-9b37-2ceb43af24a2.jpg" width="200" height="200">
</p>

When performing OSINT reconnaissance against a target, it’s often very difficult to accurately define the scope. There are so many sources of information and so many diverse types of data. It quickly becomes overwhelming. While there are many excellent OSINT tools already available to the discerning OSINTer, their focus is usually on breadth of collection. Our experience is that asset traceability and narrowly-focused discovery help us to discover the best results. To that end, we’ve developed a tool: the “Orca”. This approach focuses on comprehensive asset discovery coupled with narrow scoping to avoid false positives.

The Orca does the following:
* Domain discovery with Google and SHODAN
* Sub Domain Enumeration Lookups
* Service discovery with SHODAN
* Export to .xlsx


## Contents

- [Installation - Recommended](#installation---recommended)
- [Installation - Manual](#installation---manual)
- [Usage](#usage)
- [License](#license)


## Installation - Recommended 

Orca has been tested on Ubuntu 18.04 and Kali 2019, it may work on other platforms, but we have not confirmed this.

Orca is written in Python 3 and requires Pip to install dependencies. If you haven't already, you need to install them:

```apt install python3 python3-pip```

Orca also requires Docker for the database and CVE search, please follow the instructions below:

### Kali
https://medium.com/@airman604/installing-docker-in-kali-linux-2017-1-fbaa4d1447fe

### Ubuntu 
https://docs.docker.com/install/linux/docker-ce/ubuntu/

To configure the database required for your Orca projects, you can run the following from the root of the project:

```sudo docker-compose up -d```

If you don't have docker-compose installed, you can install it with:

```sudo -H pip3 install docker-compose --upgrade```

The orca-recon application can be installed by running from the project root:

```sudo -H pip3 install .```

### Activate Tab Completion:

Optional - but recommended! 

Once your Orca installation is set up and working, run the following to activate tab completion. 


To enable Bash completion:

``` echo "$(_ORCA_RECON_COMPLETE=source orca-recon)" > ~/.orca/orca-recon-complete.sh```

```echo '. ~/.orca/orca-recon-complete.sh' >> ~/.bashrc```

For zsh users:

```echo "$(_ORCA_RECON_COMPLETE=source_zsh orca-recon)" > ~/.orca/orca-recon-complete.sh```

```echo '. ~/.orca/orca-recon-complete.sh' >> ~/.zshrc```

### Installation - Script

For ease of use and effeciency, there is now an install script for Orca that will automate the above steps. This script has been tested and works on Ubuntu 18.04 LTS and Kali 2020.2. Prior to running the script, provide your Shodan API key to the variable. 

Make the script executable:

``` chmod +x orcainstaller.sh```

Then run the script with sudo:

``` sudo ./orcainstaller.sh```

This might take a few minutes, but when it's finished, Orca will be installed and bash autocompletion will be enabled.

### Additional Services (Exploit Lookups)

If you wish to use the Orca to search for services which have publicly available exploits. You will also need to install CVE-Search. For instructions on how to do this. See the 'CVE-Search' section below.
## Usage

You can run the orca using the `orca-recon` command. Orca uses the `click` text user interface and provides contextual help from the script itself. 

```
Usage: orca-recon [OPTIONS] COMMAND [ARGS]...

Options:
  -h, --help  Show this message and exit.

Commands:
  add       Add/Import asset data which you would like to enumerate.
  discover  Discover additional asset data for enumeration.
  enum      Enumerate the assets to get additional information.
  explore   Explore discovered data, and manage projects.
  export    Export data to a file.
  init      Initialize the Orca command-line
```
The first thing a user should do is to setup their Shodan API credentials. Run:

```$ orca-recon init <shodan_api_key>```

Credentials profiles are stored in the user's home directory in the following location:

```$HOME/.orca/shodan_api_key```

This may also prompt the user to download and parse the data required for ipasn. This may take a while, so please go get yourself a beverage of choice! 

For a full example investigation performed by the Orca, check out the [Example Walkthrough](https://github.com/digitalshadows/orca/wiki/Example-walkthrough) on the Wiki.

## Installation - Manual

### Install Dependencies 

`sudo -H pip install -r requirements.txt`

### Setup Postgres

``` bash
➜  orca git:(master) ✗ sudo -i -u postgres
postgres@machine:~$ createuser orcauser -P --interactive
Enter password for new role: 
Enter it again: 
Shall the new role be a superuser? (y/n) n
Shall the new role be allowed to create databases? (y/n) y
Shall the new role be allowed to create more new roles? (y/n) n


(env) ➜  orca git:(master) ✗ sudo -u postgres psql
psql (10.9 (Ubuntu 10.9-0ubuntu0.18.04.1))
Type "help" for help.

postgres=# grant all privileges on database orcadata to orcauser;
GRANT
```

Update your settings.py file to reflect the above configuration. 


### Install IP4R - IPv4/v6 and IPv4/v6 range index type for PostgreSQL

``` bash
sudo apt install postgresql-10-ip4r
sudo -u postgres psql -c "CREATE EXTENSION ip4r" orcadata
```

### CVE-Search
Install CVE Search via docker from our repository (https://github.com/digitalshadows/docker-cve-search) by cloning it to your local filesystem:
```
git clone https://github.com/digitalshadows/docker-cve-search.git
```
and then you can build and run the container in the following way:
```
sudo docker build -t cve-orca .
sudo docker run -d -p 5000:5000 --name cve cve-orca
sudo docker exec -it cve /bin/bash
cd /opt/cve/
./sbin/db_mgmt_json.py -p
./sbin/db_mgmt_cpe_dictionary.py
./sbin/db_updater.py -c
./sbin/db_mgmt_ref.py
```
The API is not ready to use until you see:
```
==================== Starting web app ====================
 * Running on http://0.0.0.0:5000/ (Press CTRL+C to quit)
 ```
in the logs via `sudo docker logs cve`

Once CVE Search is up-and-running, you can use it to populate your database with the exploits which are available for the CVEs that have been detected:
`orca-recon enum exploits_db <title>`

## Issues
### Locale error
If you get an error from Click similar to:
```
Cannot set LC_ALL to default locale: No such file or directory
```
Follow the instructions for generating locales [here](https://cliexperiences.wordpress.com/2016/11/26/glances-locale-error-unsupported-locale-setting/).

## License
Please see the LICENSE file.
