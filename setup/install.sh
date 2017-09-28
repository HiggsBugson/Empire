#!/bin/bash


# functions

# Install Powershell on Linux
function install_powershell {
	if uname | grep -q "Darwin"; then
		brew install openssl
		brew install curl --with-openssl 
		brew tap caskroom/cask
		brew cask install powershell
	else
		if ! which powershell > /dev/null; then
			wget http://archive.ubuntu.com/ubuntu/pool/main/i/icu/libicu55_55.1-7_amd64.deb
			wget http://ftp.debian.org/debian/pool/main/o/openssl/libssl1.0.0_1.0.1t-1+deb8u6_amd64.deb
			wget https://github.com/PowerShell/PowerShell/releases/download/v6.0.0-alpha.16/powershell_6.0.0-alpha.16-1ubuntu1.16.04.1_amd64.deb
			apt-get install -y libunwind8
			dpkg -i libicu55_55.1-7_amd64.deb
			dpkg -i libssl1.0.0_1.0.1t-1+deb8u6_amd64.deb
			dpkg -i powershell_6.0.0-alpha.16-1ubuntu1.16.04.1_amd64.deb
			apt-get install -f -y
			rm libicu55_55.1-7_amd64.deb
			rm libssl1.0.0_1.0.1t-1+deb8u6_amd64.deb
			rm powershell_6.0.0-alpha.16-1ubuntu1.16.04.1_amd64.deb
		fi
	fi
	mkdir -p /usr/local/share/powershell/Modules
	cp -r ../lib/powershell/Invoke-Obfuscation /usr/local/share/powershell/Modules
}


# Ask for the administrator password upfront so sudo is no longer required at Installation. 
sudo -v

IFS='/' read -a array <<< pwd

if [[ "$(pwd)" != *setup ]]
then
    cd ./setup
fi

<<<<<<< HEAD
wget https://bootstrap.pypa.io/get-pip.py
python get-pip.py

version=$( lsb_release -r | grep -oP "[0-9]+" | head -1 )
if lsb_release -d | grep -q "Fedora"; then
	Release=Fedora
	dnf install -y make g++ python-devel m2crypto python-m2ext swig python-iptools python3-iptools libxml2-devel default-jdk openssl-devel libssl1.0.0 libssl-dev
	pip install --upgrade urllib3
	pip install setuptools
	pip install pycrypto
	pip install iptools
	pip install pydispatcher
	pip install flask
	pip install macholib
	pip install dropbox
	pip install pyOpenSSL
	pip install pyinstaller
	pip install zlib_wrapper
	pip install netifaces
	pip install PySocks
elif lsb_release -d | grep -q "Kali"; then
	Release=Kali
	apt-get install -y make g++ python-dev python-m2crypto swig python-pip libxml2-dev default-jdk libssl1.0.0 libssl-dev
	pip install --upgrade urllib3
	pip install setuptools
	pip install pycrypto
	pip install iptools
	pip install pydispatcher
	pip install flask
	pip install macholib
	pip install dropbox
	pip install pyOpenSSL
	pip install pyinstaller
	pip install zlib_wrapper
	pip install netifaces
	pip install PySocks
        if ! which powershell > /dev/null; then
            wget http://archive.ubuntu.com/ubuntu/pool/main/i/icu/libicu55_55.1-7_amd64.deb
            wget http://ftp.debian.org/debian/pool/main/o/openssl/libssl1.0.0_1.0.1t-1+deb8u6_amd64.deb
            wget https://github.com/PowerShell/PowerShell/releases/download/v6.0.0-alpha.16/powershell_6.0.0-alpha.16-1ubuntu1.16.04.1_amd64.deb
            apt-get install -y libunwind8
            dpkg -i libicu55_55.1-7_amd64.deb
            dpkg -i libssl1.0.0_1.0.1t-1+deb8u6_amd64.deb
            dpkg -i powershell_6.0.0-alpha.16-1ubuntu1.16.04.1_amd64.deb
            apt-get install -f -y
            rm libicu55_55.1-7_amd64.deb
            rm libssl1.0.0_1.0.1t-1+deb8u6_amd64.deb
            rm powershell_6.0.0-alpha.16-1ubuntu1.16.04.1_amd64.deb
        fi
        mkdir -p /usr/local/share/powershell/Modules
        cp -r ../lib/powershell/Invoke-Obfuscation /usr/local/share/powershell/Modules
elif lsb_release -d | grep -q "Ubuntu"; then
	Release=Ubuntu
	apt-get install -y make g++ python-dev python-m2crypto swig python-pip libxml2-dev default-jdk libssl1.0.0 libssl-dev
	pip install --upgrade urllib3
	pip install setuptools
	pip install pycrypto
	pip install iptools
	pip install pydispatcher
	pip install flask
	pip install pyOpenSSL
	pip install macholib
	pip install dropbox
	pip install pyopenssl
	pip install pyinstaller
	pip install zlib_wrapper
	pip install netifaces
	pip install PySocks
        if ! which powershell > /dev/null; then
            wget http://archive.ubuntu.com/ubuntu/pool/main/i/icu/libicu55_55.1-7_amd64.deb
            wget http://ftp.debian.org/debian/pool/main/o/openssl/libssl1.0.0_1.0.1t-1+deb8u6_amd64.deb
            wget https://github.com/PowerShell/PowerShell/releases/download/v6.0.0-alpha.16/powershell_6.0.0-alpha.16-1ubuntu1.16.04.1_amd64.deb
            apt-get install -y libunwind8
            dpkg -i libicu55_55.1-7_amd64.deb
            dpkg -i libssl1.0.0_1.0.1t-1+deb8u6_amd64.deb
            dpkg -i powershell_6.0.0-alpha.16-1ubuntu1.16.04.1_amd64.deb
            apt-get install -f -y
            rm libicu55_55.1-7_amd64.deb
            rm libssl1.0.0_1.0.1t-1+deb8u6_amd64.deb
            rm powershell_6.0.0-alpha.16-1ubuntu1.16.04.1_amd64.deb
        fi
        mkdir -p /usr/local/share/powershell/Modules
        cp -r ../lib/powershell/Invoke-Obfuscation /usr/local/share/powershell/Modules
else
	echo "Unknown distro - Debian/Ubuntu Fallback"
	 apt-get install -y make g++ python-dev python-m2crypto swig python-pip libxml2-dev default-jdk libffi-dev libssl1.0.0 libssl-dev
	 pip install --upgrade urllib3
	 pip install setuptools
	 pip install pycrypto
	 pip install iptools
	 pip install pydispatcher
	 pip install flask
	 pip install macholib
	 pip install dropbox
	 pip install cryptography
	 pip install pyOpenSSL
	 pip install pyinstaller
	 pip install zlib_wrapper
	 pip install netifaces
	 pip install PySocks
         if ! which powershell > /dev/null; then
            wget http://archive.ubuntu.com/ubuntu/pool/main/i/icu/libicu55_55.1-7_amd64.deb
            wget http://ftp.debian.org/debian/pool/main/o/openssl/libssl1.0.0_1.0.1t-1+deb8u6_amd64.deb
            wget https://github.com/PowerShell/PowerShell/releases/download/v6.0.0-alpha.16/powershell_6.0.0-alpha.16-1ubuntu1.16.04.1_amd64.deb
            apt-get install -y libunwind8
            dpkg -i libicu55_55.1-7_amd64.deb
            dpkg -i libssl1.0.0_1.0.1t-1+deb8u6_amd64.deb
            dpkg -i powershell_6.0.0-alpha.16-1ubuntu1.16.04.1_amd64.deb
            apt-get install -f -y
            rm libicu55_55.1-7_amd64.deb
            rm libssl1.0.0_1.0.1t-1+deb8u6_amd64.deb
            rm powershell_6.0.0-alpha.16-1ubuntu1.16.04.1_amd64.deb
         fi
         mkdir -p /usr/local/share/powershell/Modules
         cp -r ../lib/powershell/Invoke-Obfuscation /usr/local/share/powershell/Modules
=======
# Check for PIP otherwise install it
if ! which pip > /dev/null; then
	wget https://bootstrap.pypa.io/get-pip.py
	python get-pip.py
fi

if uname | grep -q "Darwin"; then
	install_powershell
	sudo pip install -r requirements.txt --global-option=build_ext \
		--global-option="-L/usr/local/opt/openssl/lib" \
		--global-option="-I/usr/local/opt/openssl/include"
	# In order to build dependencies these should be exproted. 
	export LDFLAGS=-L/usr/local/opt/openssl/lib
	export CPPFLAGS=-I/usr/local/opt/openssl/include
else

	version=$( lsb_release -r | grep -oP "[0-9]+" | head -1 )
	if lsb_release -d | grep -q "Fedora"; then
		Release=Fedora
		sudo dnf install -y make g++ python-devel m2crypto python-m2ext swig python-iptools python3-iptools libxml2-devel default-jdk openssl-devel libssl1.0.0 libssl-dev
		sudo pip install -r requirements.txt 
	elif lsb_release -d | grep -q "Kali"; then
		Release=Kali
		sudo apt-get install -y make g++ python-dev python-m2crypto swig python-pip libxml2-dev default-jdk libssl1.0.0 libssl-dev
		sudo pip install -r requirements.txt 
		install_powershell
	elif lsb_release -d | grep -q "Ubuntu"; then
		Release=Ubuntu
		sudo apt-get install -y make g++ python-dev python-m2crypto swig python-pip libxml2-dev default-jdk libssl1.0.0 libssl-dev
		sudo pip install -r requirements.txt 
		install_powershell
	else
		echo "Unknown distro - Debian/Ubuntu Fallback"
		sudo apt-get install -y make g++ python-dev python-m2crypto swig python-pip libxml2-dev default-jdk libffi-dev libssl1.0.0 libssl-dev
		sudo pip install -r requirements.txt 
		install_powershell
	fi
>>>>>>> pr642
fi

# Installing xar
tar -xvf ../data/misc/xar-1.5.2.tar.gz
(cd xar-1.5.2 && ./configure)
(cd xar-1.5.2 && make)
(cd xar-1.5.2 && sudo make install)

# Installing bomutils
git clone https://github.com/hogliux/bomutils.git
(cd bomutils && make)

# NIT: This fails on OSX. Leaving it only on Linux instances. 
if uname | grep -q "Linux"; then
	(cd bomutils && make install)
fi
chmod 755 bomutils/build/bin/mkbom && sudo cp bomutils/build/bin/mkbom /usr/local/bin/.


# set up the database schema
./setup_database.py

# generate a cert
./cert.sh

cd ..

echo -e '\n [*] Setup complete!\n'
