#!/bin/bash

###run as sudo
###only tested on a fresh Ubuntu 18.04 LTS install
###add shodan api key as an environmental variable prior to running

echo 'Updating packages...'
sudo apt update -y

echo 'Upgrading packages...'
sudo apt full-upgrade -y

echo 'Installing packages...'
sudo apt install apt-transport-https ca-certificates curl software-properties-common build-essential python3-pip -y

echo 'Installing Docker...'
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
sudo add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu bionic stable"
sudo apt install docker-ce docker-compose -y
sudo systemctl enable docker

echo 'Installing Orca...'
git clone https://github.com/digitalshadows/orca.git
cd orca
sudo docker-compose up -d
sudo -H pip3 install .
orca-recon init $SHODAN_API_KEY
echo "$(_ORCA_RECON_COMPLETE=source orca-recon)" > ~/.orca/orca-recon-complete.sh
echo '. ~/.orca/orca-recon-complete.sh' >> ~/.bashrc
cd ..
source ~/.bashrc

echo 'Cleaning up...'
sudo apt autoclean -y
sudo apt autoremove -y

echo 'Finished!'
