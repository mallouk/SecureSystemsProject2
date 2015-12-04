#!/bin/bash

sudo apt-get update
sudo apt-get upgrade

sudo apt-get install git gcc g++ make gedit nginx openssl
sudo apt-get install python python-virtualenv
sudo apt-get install python-dev
sudo apt-get install python-pip
pip install pycrypto

git clone https://github.com/mallouk/SecureSystemsProject2.git
echo ""
echo ""
echo ""
echo "gcc/g++/make...for general dev tools and if you ever want to enable VBoxGuestAdditions"
echo "gedit...for your developing purposes"
echo "emacs...in case you ever want to get into a wonderful thing of emacs text editing"
echo "python...again obvious"
echo "python-virtualenv...used with flask"
echo "nginx...used as our server backend"
echo "openssl...cert things"
echo "python-pip and python-dev"
echo "install pycrypto"
echo ""
echo "I believe that is everything. Thanks!"
