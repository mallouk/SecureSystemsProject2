#!/bin/bash

sudo apt-get -y update
sudo apt-get -y upgrade

sudo apt-get -y install git gcc g++ make gedit nginx openssl
sudo apt-get -y install python python-virtualenv
sudo apt-get -y install python-dev
sudo apt-get -y install python-pip

pip install pycrypto
pip install flask

git clone https://github.com/mallouk/SecureSystemsProject2.git
echo ""
echo ""
echo ""
echo "gcc/g++/make...for general dev tools and if you ever want to enable VBoxGuestAdditions"
echo "gedit...for your developing purposes"
echo "python"
echo "python-virtualenv...used with flask"
echo "nginx...used as our server backend"
echo "openssl...certificate tools"
echo "python-pip and python-dev"
echo "pycrypto for hashing and encrypting"
echo ""
echo "I believe that is everything. Thanks!"
