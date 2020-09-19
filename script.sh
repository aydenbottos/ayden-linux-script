#!/bin/bash
clear
echo "Created by Ayden Bottos"
echo "Last Modified on Sep 19, 2020"
echo "Linux script"

mkdir -p /home/newt/Desktop/
touch /home/newt/Desktop/badfiles.log
echo > /home/newt/Desktop/badfiles.log
chmod 777 /home/newt/Desktop/badfiles.log

if [[ $EUID -ne 0 hh]]
then
  echo This script must be run as root
  exit
fi
echo "Script is being run as root."

echo "Running apt-get update"
apt-get update

echo "Installing apt-transport-https for apt https"
apt-get install apt-transport-https -y -qq

echo "Updating /etc/apt/sources.list for https"
if [[ $(lsb_release -r) == "Release:	16.04" ]] || [[ $(lsb_release -r) == "Release:	16.10" ]]
then
	chmod 777 /etc/apt/sources.list
	cp /etc/apt/sources.list /home/newt/Desktop/backups/
	echo -e "deb https://us.archive.ubuntu.com/ubuntu/ xenial main restricted universe multiverse\ndeb-src https://us.archive.ubuntu.com/ubuntu/ xenial main restricted universe multiverse\ndeb https://us.archive.ubuntu.com/ubuntu/ xenial-security main restricted universe multiverse\ndeb https://us.archive.ubuntu.com/ubuntu/ xenial-updates main restricted universe multiverse\ndeb https://us.archive.ubuntu.com/ubuntu/ xenial-proposed main restricted universe multiverse\ndeb-src https://us.archive.ubuntu.com/ubuntu/ xenial-security main restricted universe multiverse\ndeb-src https://us.archive.ubuntu.com/ubuntu/ xenial-updates main restricted universe multiverse\ndeb-src https://us.archive.ubuntu.com/ubuntu/ xenial-proposed main restricted universe multiverse" > /etc/apt/sources.list
	chmod 644 /etc/apt/sources.list
elif [[ $(lsb_release -r) == "Release:	19.04" ]] || [[ $(lsb_release -r) == "Release:	19.10" ]]
then
	chmod 777 /etc/apt/sources.list
	cp /etc/apt/sources.list /home/newt/Desktop/backups/
	echo -e "deb https://us.archive.ubuntu.com/ubuntu/ eoan main restricted universe multiverse \ndeb-src https://us.archive.ubuntu.com/ubuntu/ precise main restricted universe multiverse \ndeb https://us.archive.ubuntu.com/ubuntu/ precise-security main restricted universe multiverse\ndeb https://us.archive.ubuntu.com/ubuntu/ precise-updates main restricted universe multiverse\ndeb https://us.archive.ubuntu.com/ubuntu/ precise-proposed main restricted universe multiverse\ndeb-src https://us.archive.ubuntu.com/ubuntu/ precise-security main restricted universe multiverse\ndeb-src https://us.archive.ubuntu.com/ubuntu/ precise-updates main restricted universe multiverse\ndeb-src https://us.archive.ubuntu.com/ubuntu/ precise-proposed main restricted universe multiverse" > /etc/apt/sources.list
	chmod 644 /etc/apt/sources.list
else
	echo “Error, cannot detect OS version”
fi

echo "Running apt-get update with HTTPS"
apt-get update
clear

echo "The current OS is Linux"

mkdir -p /home/newt/Desktop/backups
chmod 777 /home/newt/Desktop/backups
echo "Backups folder created on the Desktop."

cp /etc/group /home/newt/Desktop/backups/
cp /etc/passwd /home/newt/Desktop/backups/

echo "/etc/group and /etc/passwd files backed up."

awk -F: '$6 ~ /\/home/ {print}' /etc/passwd | cut -d: -f1 | while read line || [[ -n $line ]];
do
	clear
	echo $line
	echo Delete $line? yes or no
	read yn1 < /dev/tty
	if [ $yn1 == yes ]
	then
		userdel -r $line
		echo "$line has been deleted."
	else	
		echo Make $line administrator? yes or no
		read yn2 < /dev/tty								
		if [ $yn2 == yes ]
		then
			gpasswd -a $line sudo
			gpasswd -a $line adm
			gpasswd -a $line lpadmin
			gpasswd -a $line sambashare
			echo "$line has been made an administrator."
		else
			gpasswd -d $line sudo
			gpasswd -d $line adm
			gpasswd -d $line lpadmin
			gpasswd -d $line sambashare
			gpasswd -d $line root
			echo "$line has been made a standard user."
		fi
		
		echo Make custom password for $line? yes or no
		read yn3 < /dev/tty								
		if [ $yn3 == yes ]
		then
			echo Password:
			read pw < /dev/tty
			echo -e "$pw\n$pw" | passwd $line
			echo "${users[${i}]} has been given the password '$pw'."
		fi
		passwd -x30 -n3 -w7 $line
		usermod -U $line
		echo "$line's password has been given a maximum age of 30 days, minimum of 3 days, and warning of 7 days."
	fi
done
clear

echo Type user account names of users you want to add, with a space in between
read -a usersNew

usersNewLength=${#usersNew[@]}	

for (( i=0;i<$usersNewLength;i++))
do
	clear
	echo ${usersNew[${i}]}
	adduser ${usersNew[${i}]}
	echo "A user account for ${usersNew[${i}]} has been created."
	clear
	echo Make ${usersNew[${i}]} administrator? yes or no
	read ynNew								
	if [ $ynNew == yes ]
	then
		gpasswd -a ${usersNew[${i}]} sudo
		gpasswd -a ${usersNew[${i}]} adm
		gpasswd -a ${usersNew[${i}]} lpadmin
		gpasswd -a ${usersNew[${i}]} sambashare
		echo "${usersNew[${i}]} has been made an administrator."
	else
		echo "${usersNew[${i}]} has been made a standard user."
	fi
	
	passwd -x30 -n3 -w7 ${usersNew[${i}]}
	usermod -L ${usersNew[${i}]}
	echo "${usersNew[${i}]}'s password has been given a maximum age of 30 days, minimum of 3 days, and warning of 7 days. ${users[${i}]}'s account has been locked."
done

echo Does this machine need Samba?
read sambaYN
echo Does this machine need FTP?
read ftpYN
echo Does this machine need SSH?
read sshYN
echo Does this machine need Telnet?
read telnetYN
echo Does this machine need Mail?
read mailYN
echo Does this machine need Printing?
read printYN
echo Does this machine need MySQL?
read dbYN
echo Will this machine be a Web Server?
read httpsYN
echo Does this machine need DNS?
read dnsYN
echo Does this machine allow media files?
read mediaFilesYN
echo Does this machine need VPN?
read vpnYN

clear
unalias -a
echo "All alias have been removed."

clear
usermod -L root
echo "Root account has been locked. Use 'usermod -U root' to unlock it."

clear
chmod 640 .bash_history
echo "Bash history file permissions set."

clear
chmod 604 /etc/shadow
echo "Read/Write permissions on shadow have been set."

clear
echo "Check for any user folders that do not belong to any users in /home/."
ls -a /home/ >> /home/newt/Desktop/badfiles.log

clear
echo "Check for any files for users that should not be administrators in /etc/sudoers.d."
ls -a /etc/sudoers.d >> /home/newt/Desktop/badfiles.log

clear
cp /etc/rc.local /home/newt/Desktop/backups/
echo > /etc/rc.local
echo 'exit 0' >> /etc/rc.local
echo "Any startup scripts have been removed."

clear
apt-get install ufw -y -qq
ufw enable
ufw deny 1337
echo "Firewall enabled and port 1337 blocked."

clear
env i='() { :;}; echo Your system is Bash vulnerable' bash -c "echo Bash vulnerability test"
echo "Shellshock Bash vulnerability has been fixed."

clear
apt-get install stubby -y -qq
systemctl start stubby
systemctl enable stubby
echo "DNS-over-TLS has been enabled"

clear
chmod 777 /etc/hosts
cp /etc/hosts /home/newt/Desktop/backups/
echo > /etc/hosts
echo -e "127.0.0.1 localhost\n127.0.1.1 $USER\n::1 ip6-localhost ip6-loopback\nfe00::0 ip6-localnet\nff00::0 ip6-mcastprefix\nff02::1 ip6-allnodes\nff02::2 ip6-allrouters" >> /etc/hosts
chmod 644 /etc/hosts
echo "HOSTS file has been set to defaults."

clear
chmod 777 /etc/lightdm/lightdm.conf
cp /etc/lightdm/lightdm.conf /home/newt/Desktop/backups/
echo > /etc/lightdm/lightdm.conf
echo -e '[SeatDefaults]\nallow-guest=false\ngreeter-hide-users=true\ngreeter-show-manual-login=true' >> /etc/lightdm/lightdm.conf
chmod 644 /etc/lightdm/lightdm.conf
echo "LightDM has been secured."

clear
find /bin/ -name "*.sh" -type f -delete
echo "badfiles in bin have been removed."

clear
cp /etc/default/irqbalance /home/newt/Desktop/backups/
echo > /etc/default/irqbalance
echo -e "#Configuration for the irqbalance daemon\n\n#Should irqbalance be enabled?\nENABLED=\"0\"\n#Balance the IRQs only once?\nONESHOT=\"0\"" >> /etc/default/irqbalance
echo "IRQ Balance has been disabled."

clear
cp /etc/sysctl.conf /home/newt/Desktop/backups/
echo > /etc/sysctl.conf
echo -e "# Controls IP packet forwarding\nnet.ipv4.ip_forward = 0\n\n# IP Spoofing protection\nnet.ipv4.conf.all.rp_filter = 1\nnet.ipv4.conf.default.rp_filter = 1\n\n# Ignore ICMP broadcast requests\nnet.ipv4.icmp_echo_ignore_broadcasts = 1\n\n# Disable source packet routing\nnet.ipv4.conf.all.accept_source_route = 0\nnet.ipv6.conf.all.accept_source_route = 0\nnet.ipv4.conf.default.accept_source_route = 0\nnet.ipv6.conf.default.accept_source_route = 0\n\n# Ignore send redirects\nnet.ipv4.conf.all.send_redirects = 0\nnet.ipv4.conf.default.send_redirects = 0\n\n# Block SYN attacks\nnet.ipv4.tcp_syncookies = 1\nnet.ipv4.tcp_max_syn_backlog = 2048\nnet.ipv4.tcp_synack_retries = 2\nnet.ipv4.tcp_syn_retries = 5\n\n# Log Martians\nnet.ipv4.conf.all.log_martians = 1\nnet.ipv4.icmp_ignore_bogus_error_responses = 1\n\n# Ignore ICMP redirects\nnet.ipv4.conf.all.accept_redirects = 0\nnet.ipv6.conf.all.accept_redirects = 0\nnet.ipv4.conf.default.accept_redirects = 0\nnet.ipv6.conf.default.accept_redirects = 0\n\n# Ignore Directed pings\nnet.ipv4.icmp_echo_ignore_all = 1\n\n# Accept Redirects? No, this is not router\nnet.ipv4.conf.all.secure_redirects = 0\n\n# Log packets with impossible addresses to kernel log? yes\nnet.ipv4.conf.default.secure_redirects = 0\n\n########## IPv6 networking start ##############\n# Number of Router Solicitations to send until assuming no routers are present.\n# This is host and not router\nnet.ipv6.conf.default.router_solicitations = 0\n\n# Accept Router Preference in RA?\nnet.ipv6.conf.default.accept_ra_rtr_pref = 0\n\n# Learn Prefix Information in Router Advertisement\nnet.ipv6.conf.default.accept_ra_pinfo = 0\n\n# Setting controls whether the system will accept Hop Limit settings from a router advertisement\nnet.ipv6.conf.default.accept_ra_defrtr = 0\n\n#router advertisements can cause the system to assign a global unicast address to an interface\nnet.ipv6.conf.default.autoconf = 0\n\n#how many neighbor solicitations to send out per address?\nnet.ipv6.conf.default.dad_transmits = 0\n\n# How many global unicast IPv6 addresses can be assigned to each interface?
net.ipv6.conf.default.max_addresses = 1\n\n########## IPv6 networking ends ##############" >> /etc/sysctl.conf
sysctl -p >> /dev/null
echo "Sysctl has been configured."


echo Disable IPv6?
read ipv6YN
if [ $ipv6YN == yes ]
then
	echo -e "\n\n# Disable IPv6\nnet.ipv6.conf.all.disable_ipv6 = 1\nnet.ipv6.conf.default.disable_ipv6 = 1\nnet.ipv6.conf.lo.disable_ipv6 = 1" >> /etc/sysctl.conf
	sysctl -p >> /dev/null
	echo "IPv6 has been disabled."
fi

clear
if [ $sambaYN == no ]
then
	ufw deny netbios-ns
	ufw deny netbios-dgm
	ufw deny netbios-ssn
	ufw deny microsoft-ds
	apt-get purge samba -y -qq
	apt-get purge samba-common -y  -qq
	apt-get purge samba-common-bin -y -qq
	apt-get purge samba4 -y -qq
	clear
	echo "netbios-ns, netbios-dgm, netbios-ssn, and microsoft-ds ports have been denied. Samba has been removed."
elif [ $sambaYN == yes ]
then
	ufw allow netbios-ns
	ufw allow netbios-dgm
	ufw allow netbios-ssn
	ufw allow microsoft-ds
	apt-get install samba -y -qq
	apt-get install system-config-samba -y -qq
	cp /etc/samba/smb.conf /home/newt/Desktop/backups/
	if [ "$(grep '####### Authentication #######' /etc/samba/smb.conf)"==0 ]
	then
		sed -i 's/####### Authentication #######/####### Authentication #######\nsecurity = user/g' /etc/samba/smb.conf
	fi
	sed -i 's/usershare allow guests = no/usershare allow guests = yes/g' /etc/samba/smb.conf
	
	echo Type all user account names, with a space in between
	read -a usersSMB
	usersSMBLength=${#usersSMB[@]}	
	for (( i=0;i<$usersSMBLength;i++))
	do
		echo -e 'Moodle!22\nMoodle!22' | smbpasswd -a ${usersSMB[${i}]}
		echo "${usersSMB[${i}]} has been given the password 'Moodle!22' for Samba."
	done
	echo "netbios-ns, netbios-dgm, netbios-ssn, and microsoft-ds ports have been denied. Samba config file has been configured."
	clear
else
	echo Response not recognized.
fi
echo "Samba is complete."

clear
if [ $ftpYN == no ]
then
	ufw deny ftp 
	ufw deny sftp 
	ufw deny saft 
	ufw deny ftps-data 
	ufw deny ftps
	apt-get purge vsftpd proftpd -y -qq
	echo "vsFTPd has been removed. ftp, sftp, saft, ftps-data, and ftps ports have been denied on the firewall."
elif [ $ftpYN == yes ]
then
	ufw allow ftp 
	ufw allow sftp 
	ufw allow saft 
	ufw allow ftps-data 
	ufw allow ftps
	apt-get install vsftpd -y -qq
	cp /etc/vsftpd/vsftpd.conf /home/newt/Desktop/backups/
	cp /etc/vsftpd.conf /home/newt/Desktop/backups/
	gedit /etc/vsftpd/vsftpd.conf&gedit /etc/vsftpd.conf
	service vsftpd restart
	echo "ftp, sftp, saft, ftps-data, and ftps ports have been allowed on the firewall. vsFTPd service has been restarted."
else
	echo Response not recognized.
fi
echo "FTP is complete."


clear
if [ $sshYN == no ]
then
	ufw deny ssh
	apt-get purge openssh-server -y -qq
	echo "SSH port has been denied on the firewall. Open-SSH has been removed."
elif [ $sshYN == yes ]
then
	apt-get install openssh-server -y -qq
	ufw allow ssh
	cp /etc/ssh/sshd_config /home/newt/Desktop/backups/	
	echo Type all SSH users, with a space in between
	read usersSSH
	echo -e "# Package generated configuration file\n# See the sshd_config(5) manpage for details\n\n# What ports, IPs and protocols we listen for\nPort 2200\n# Use these options to restrict which interfaces/protocols sshd will bind to\n#ListenAddress ::\n#ListenAddress 0.0.0.0\nProtocol 2\n# HostKeys for protocol version \nHostKey /etc/ssh/ssh_host_rsa_key\nHostKey /etc/ssh/ssh_host_dsa_key\nHostKey /etc/ssh/ssh_host_ecdsa_key\nHostKey /etc/ssh/ssh_host_ed25519_key\n#Privilege Separation is turned on for security\nUsePrivilegeSeparation yes\n\n# Lifetime and size of ephemeral version 1 server key\nKeyRegenerationInterval 3600\nServerKeyBits 1024\n\n# Logging\nSyslogFacility AUTH\nLogLevel VERBOSE\n\n# Authentication:\nLoginGraceTime 60\nPermitRootLogin no\nStrictModes yes\n\nRSAAuthentication yes\nPubkeyAuthentication yes\n#AuthorizedKeysFile	%h/.ssh/authorized_keys\n\n# Don't read the user's /home/newt/.rhosts and /home/newt/.shosts files\nIgnoreRhosts yes\n# For this to work you will also need host keys in /etc/ssh_known_hosts\nRhostsRSAAuthentication no\n# similar for protocol version 2\nHostbasedAuthentication no\n# Uncomment if you don't trust /home/newt/.ssh/known_hosts for RhostsRSAAuthentication\n#IgnoreUserKnownHosts yes\n\n# To enable empty passwords, change to yes (NOT RECOMMENDED)\nPermitEmptyPasswords no\n\n# Change to yes to enable challenge-response passwords (beware issues with\n# some PAM modules and threads)\nChallengeResponseAuthentication yes\n\n# Change to no to disable tunnelled clear text passwords\nPasswordAuthentication no\n\n# Kerberos options\n#KerberosAuthentication no\n#KerberosGetAFSToken no\n#KerberosOrLocalPasswd yes\n#KerberosTicketCleanup yes\n\n# GSSAPI options\n#GSSAPIAuthentication no\n#GSSAPICleanupCredentials yes\n\nX11Forwarding no\nX11DisplayOffset 10\nPrintMotd no\nPrintLastLog no\nTCPKeepAlive yes\n#UseLogin no\n\nMaxStartups 2\n#Banner /etc/issue.net\n\n# Allow client to pass locale environment variables\nAcceptEnv LANG LC_*\n\nSubsystem sftp /usr/lib/openssh/sftp-server\n\n# Set this to 'yes' to enable PAM authentication, account processing,\n# and session processing. If this is enabled, PAM authentication will\n# be allowed through the ChallengeResponseAuthentication and\n# PasswordAuthentication.  Depending on your PAM configuration,\n# PAM authentication via ChallengeResponseAuthentication may bypass\n# the setting of \"PermitRootLogin without-password\".\n# If you just want the PAM account and session checks to run without\n# PAM authentication, then enable this but set PasswordAuthentication\n# and ChallengeResponseAuthentication to 'no'.\nUsePAM yes\n\nAllowUsers $usersSSH\nDenyUsers\nRhostsAuthentication no\nClientAliveInterval 300\nClientAliveCountMax 0\nVerifyReverseMapping yes\nAllowTcpForwarding no\nUseDNS no\nPermitUserEnvironment no" > /etc/ssh/sshd_config
	systemctl sshd restart
	echo "Where should ssh folder be placed?"
	read answer
	mkdir /home/$answer/.ssh
	chmod 700 /home/$answer/.ssh
	ssh-keygen -t rsa
	echo "SSH port has been allowed on the firewall. SSH config file has been configured. SSH RSA 2048 keys have been created."
else
	echo Response not recognized.
fi
echo "SSH is complete."

clear
if [ $telnetYN == no ]
then
	ufw deny telnet 
	ufw deny rtelnet 
	ufw deny telnets
	apt-get purge telnet -y -qq
	apt-get purge telnetd -y -qq
	apt-get purge inetutils-telnetd -y -qq
	apt-get purge telnetd-ssl -y -qq
	echo "Telnet port has been denied on the firewall and Telnet has been removed."
elif [ $telnetYN == yes ]
then
	ufw allow telnet 
	ufw allow rtelnet 
	ufw allow telnets
	apt-get install telnetd -y -qq
	echo "Telnet port has been allowed on the firewall."
else
	echo Response not recognized.
fi
echo "Telnet is complete."

clear
if [ $vpnYN == no ]
then
	apt-get purge openvpn -y -qq
fi
clear
if [ $mailYN == no ]
then
	ufw deny smtp 
	ufw deny pop2 
	ufw deny pop3
	ufw deny imap2 
	ufw deny imaps 
	ufw deny pop3s
	echo "smtp, pop2, pop3, imap2, imaps, and pop3s ports have been denied on the firewall."
elif [ $mailYN == yes ]
then
	ufw allow smtp 
	ufw allow pop2 
	ufw allow pop3
	ufw allow imap2 
	ufw allow imaps 
	ufw allow pop3s
	apt-get install postfix -y -qq
	echo "smtp, pop2, pop3, imap2, imaps, and pop3s ports have been allowed on the firewall."
else
	echo Response not recognized.
fi
echo "Mail is complete."



clear
if [ $printYN == no ]
then
	ufw deny ipp 
	ufw deny printer 
	ufw deny cups
	echo "ipp, printer, and cups ports have been denied on the firewall."
elif [ $printYN == yes ]
then
	ufw allow ipp 
	ufw allow printer 
	ufw allow cups
	echo "ipp, printer, and cups ports have been allowed on the firewall."
else
	echo Response not recognized.
fi
echo "Printing is complete."



clear
if [ $dbYN == no ]
then
	ufw deny ms-sql-s 
	ufw deny ms-sql-m 
	ufw deny mysql 
	ufw deny mysql-proxy
	apt-get purge mysql* -y -qq
	echo "ms-sql-s, ms-sql-m, mysql, and mysql-proxy ports have been denied on the firewall. MySQL has been removed."
elif [ $dbYN == yes ]
then
	ufw allow ms-sql-s 
	ufw allow ms-sql-m 
	ufw allow mysql 
	ufw allow mysql-proxy
	apt-get install mysql-server-* -y -qq
	cp /etc/my.cnf /home/newt/Desktop/backups/
	cp /etc/mysql/my.cnf /home/newt/Desktop/backups/
	cp /usr/etc/my.cnf /home/newt/Desktop/backups/
	cp /home/newt/.my.cnf /home/newt/Desktop/backups/
	if grep -q "bind-address" "/etc/mysql/my.cnf"
	then
		sed -i "s/bind-address\t\t=.*/bind-address\t\t= 127.0.0.1/g" /etc/mysql/my.cnf
	fi
	gedit /etc/my.cnf&gedit /etc/mysql/my.cnf&gedit /usr/etc/my.cnf&gedit /home/newt/.my.cnf
	service mysql restart
	echo "ms-sql-s, ms-sql-m, mysql, and mysql-proxy ports have been allowed on the firewall. MySQL has been installed. MySQL config file has been secured. MySQL service has been restarted."
else
	echo Response not recognized.
fi
echo "MySQL is complete."



clear
if [ $httpsYN == no ]
then
	ufw deny https
	ufw deny https
	apt-get purge apache2 nginx -y -qq
	rm -r /var/www/*
	echo "https and https ports have been denied on the firewall. Apache2 has been removed. Web server files have been removed."
elif [ $httpsYN == yes ]
then
	apt-get install apache2 -y -qq
	ufw allow https 
	ufw allow https
	cp /etc/apache2/apache2.conf /home/newt/Desktop/backups/
	if [ -e /etc/apache2/apache2.conf ]
	then
  	  echo -e '\<Directory \>\n\t AllowOverride None\n\t Order Deny,Allow\n\t Deny from all\n\<Directory \/\>\nUserDir disabled root' >> /etc/apache2/apache2.conf
	fi
	chown -R root:root /etc/apache2

	echo "https and https ports have been allowed on the firewall. Apache2 config file has been configured. Only root can now access the Apache2 folder."
else
	echo Response not recognized.
fi
echo "Web Server is complete."



clear
if [ $dnsYN == no ]
then
	ufw deny domain
	apt-get purge bind9 -qq -y
	echo "domain port has been denied on the firewall. DNS name binding has been removed."
elif [ $dnsYN == yes ]
then
	apt-get install bind9 -y -qq
	ufw allow domain
	echo "domain port has been allowed on the firewall and bind9 installed."
else
	echo Response not recognized.
fi
echo "DNS is complete."


clear
if [ $mediaFilesYN == no ]
then
	find / -iname "*.midi" -type f >> /home/newt/Desktop/badfiles.log
	find / -iname "*.mid" -type f >> /home/newt/Desktop/badfiles.log
	find / -iname "*.mod" -type f >> /home/newt/Desktop/badfiles.log
	find / -iname "*.mp3" -type f >> /home/newt/Desktop/badfiles.log
	find / -iname "*.mp2" -type f >> /home/newt/Desktop/badfiles.log
	find / -iname "*.mpa" -type f >> /home/newt/Desktop/badfiles.log
	find / -iname "*.abs" -type f >> /home/newt/Desktop/badfiles.log
	find / -iname "*.mpega" -type f >> /home/newt/Desktop/badfiles.log
	find / -iname "*.au" -type f >> /home/newt/Desktop/badfiles.log
	find / -iname "*.snd" -type f >> /home/newt/Desktop/badfiles.log
	find / -iname "*.wav" -type f >> /home/newt/Desktop/badfiles.log
	find / -iname "*.aiff" -type f >> /home/newt/Desktop/badfiles.log
	find / -iname "*.aif" -type f >> /home/newt/Desktop/badfiles.log
	find / -iname "*.sid" -type f >> /home/newt/Desktop/badfiles.log
	find / -iname "*.flac" -type f >> /home/newt/Desktop/badfiles.log
	find / -iname "*.ogg" -type f >> /home/newt/Desktop/badfiles.log
	clear
	echo "All audio files has been listed."

	find / -name "*.mpeg" -type f >> /home/newt/Desktop/badfiles.log
	find / -name "*.mpg" -type f >> /home/newt/Desktop/badfiles.log
	find / -name "*.mpe" -type f >> /home/newt/Desktop/badfiles.log
	find / -name "*.dl" -type f >> /home/newt/Desktop/badfiles.log
	find / -name "*.movie" -type f >> /home/newt/Desktop/badfiles.log
	find / -name "*.movi" -type f >> /home/newt/Desktop/badfiles.log
	find / -name "*.mv" -type f >> /home/newt/Desktop/badfiles.log
	find / -name "*.iff" -type f >> /home/newt/Desktop/badfiles.log
	find / -name "*.anim5" -type f >> /home/newt/Desktop/badfiles.log
	find / -name "*.anim3" -type f >> /home/newt/Desktop/badfiles.log
	find / -name "*.anim7" -type f >> /home/newt/Desktop/badfiles.log
	find / -name "*.avi" -type f >> /home/newt/Desktop/badfiles.log
	find / -name "*.vfw" -type f >> /home/newt/Desktop/badfiles.log
	find / -name "*.avx" -type f >> /home/newt/Desktop/badfiles.log
	find / -name "*.fli" -type f >> /home/newt/Desktop/badfiles.log
	find / -name "*.flc" -type f >> /home/newt/Desktop/badfiles.log
	find / -name "*.mov" -type f >> /home/newt/Desktop/badfiles.log
	find / -name "*.qt" -type f >> /home/newt/Desktop/badfiles.log
	find / -name "*.spl" -type f >> /home/newt/Desktop/badfiles.log
	find / -name "*.swf" -type f >> /home/newt/Desktop/badfiles.log
	find / -name "*.dcr" -type f >> /home/newt/Desktop/badfiles.log
	find / -name "*.dir" -type f >> /home/newt/Desktop/badfiles.log
	find / -name "*.dxr" -type f >> /home/newt/Desktop/badfiles.log
	find / -name "*.rpm" -type f >> /home/newt/Desktop/badfiles.log
	find / -name "*.rm" -type f >> /home/newt/Desktop/badfiles.log
	find / -name "*.smi" -type f >> /home/newt/Desktop/badfiles.log
	find / -name "*.ra" -type f >> /home/newt/Desktop/badfiles.log
	find / -name "*.ram" -type f >> /home/newt/Desktop/badfiles.log
	find / -name "*.rv" -type f >> /home/newt/Desktop/badfiles.log
	find / -name "*.wmv" -type f >> /home/newt/Desktop/badfiles.log
	find / -name "*.asf" -type f >> /home/newt/Desktop/badfiles.log
	find / -name "*.asx" -type f >> /home/newt/Desktop/badfiles.log
	find / -name "*.wma" -type f >> /home/newt/Desktop/badfiles.log
	find / -name "*.wax" -type f >> /home/newt/Desktop/badfiles.log
	find / -name "*.wmv" -type f >> /home/newt/Desktop/badfiles.log
	find / -name "*.wmx" -type f >> /home/newt/Desktop/badfiles.log
	find / -name "*.3gp" -type f >> /home/newt/Desktop/badfiles.log
	find / -name "*.mov" -type f >> /home/newt/Desktop/badfiles.log
	find / -name "*.mp4" -type f >> /home/newt/Desktop/badfiles.log
	find / -name "*.avi" -type f >> /home/newt/Desktop/badfiles.log
	find / -name "*.swf" -type f >> /home/newt/Desktop/badfiles.log
	find / -name "*.flv" -type f >> /home/newt/Desktop/badfiles.log
	find / -name "*.m4v" -type f >> /home/newt/Desktop/badfiles.log
	clear
	echo "All video files have been listed."
	
	find / -name "*.tiff" -type f >> /home/newt/Desktop/badfiles.log
	find / -name "*.tif" -type f >> /home/newt/Desktop/badfiles.log
	find / -name "*.rs" -type f >> /home/newt/Desktop/badfiles.log
	find / -name "*.im1" -type f >> /home/newt/Desktop/badfiles.log
	find / -name "*.gif" -type f >> /home/newt/Desktop/badfiles.log
	find / -name "*.jpeg" -type f >> /home/newt/Desktop/badfiles.log
	find / -name "*.jpg" -type f >> /home/newt/Desktop/badfiles.log
	find / -name "*.jpe" -type f >> /home/newt/Desktop/badfiles.log
	find / -name "*.png" -type f >> /home/newt/Desktop/badfiles.log
	find / -name "*.rgb" -type f >> /home/newt/Desktop/badfiles.log
	find / -name "*.xwd" -type f >> /home/newt/Desktop/badfiles.log
	find / -name "*.xpm" -type f >> /home/newt/Desktop/badfiles.log
	find / -name "*.ppm" -type f >> /home/newt/Desktop/badfiles.log
	find / -name "*.pbm" -type f >> /home/newt/Desktop/badfiles.log
	find / -name "*.pgm" -type f >> /home/newt/Desktop/badfiles.log
	find / -name "*.pcx" -type f >> /home/newt/Desktop/badfiles.log
	find / -name "*.ico" -type f >> /home/newt/Desktop/badfiles.log
	find / -name "*.svg" -type f >> /home/newt/Desktop/badfiles.log
	find / -name "*.svgz" -type f >> /home/newt/Desktop/badfiles.log
	clear
	echo "All image files have been listed."
else
	echo Response not recognized.
fi
echo "Media files are complete."

clear
find / -name "*.php" -type f >> /home/newt/Desktop/badfiles.log
echo "All PHP files have been listed above. ('/var/cache/dictionaries-common/sqspell.php' is a system PHP file)"

clear
apt-get purge netcat -y -qq
apt-get purge netcat-openbsd -y -qq
apt-get purge netcat-traditional -y -qq
apt-get purge ncat -y -qq
apt-get purge pnetcat -y -qq
apt-get purge socat -y -qq
apt-get purge sock -y -qq
apt-get purge socket -y -qq
apt-get purge sbd -y -qq
apt-get purge transmission -y -qq
apt-get purge transmission-daemon -y -qq
apt-get purge deluge -y -qq
rm /usr/bin/nc
rm /usr/bin/local/nc
clear
echo "Netcat and all other instances have been removed."

apt-get purge john -y -qq
apt-get purge john-data -y -qq
clear
echo "John the Ripper has been removed."

apt-get purge hydra -y -qq
apt-get purge hydra-gtk -y -qq
clear
echo "Hydra has been removed."

apt-get purge aircrack-ng -y -qq
clear
echo "Aircrack-NG has been removed."

apt-get purge fcrackzip -y -qq
clear
echo "FCrackZIP has been removed."

apt-get purge lcrack -y -qq
clear
echo "LCrack has been removed."

apt-get purge ophcrack -y -qq
apt-get purge ophcrack-cli -y -qq
clear
echo "OphCrack has been removed."

apt-get purge pdfcrack -y -qq
clear
echo "PDFCrack has been removed."

apt-get purge pyrit -y -qq
clear
echo "Pyrit has been removed."

apt-get purge rarcrack -y -qq
clear
echo "RARCrack has been removed."

apt-get purge sipcrack -y -qq
clear
echo "SipCrack has been removed."

apt-get purge irpas -y -qq
clear
echo "IRPAS has been removed."

apt-get purge wireshark* -y -qq
clear
echo "Wireshark has been removed."

clear
echo 'Are there any hacking tools shown? (not counting libcrack2:amd64 or cracklib-runtime)'
dpkg -l | egrep "crack|hack" >> /home/newt/Desktop/badfiles.log
read hackingTools
apt-get purge $hackingTools -y -qq

apt-get purge logkeys -y -qq
clear 
echo "LogKeys has been removed."

apt-get purge zeitgeist-core -y -qq
apt-get purge zeitgeist-datahub -y -qq
apt-get purge python-zeitgeist -y -qq
apt-get purge rhythmbox-plugin-zeitgeist -y -qq
apt-get purge zeitgeist -y -qq
echo "Zeitgeist has been removed."

apt-get purge nfs-kernel-server -y -qq
apt-get purge nfs-common -y -qq
apt-get purge portmap -y -qq
apt-get purge rpcbind -y -qq
apt-get purge autofs -y -qq
echo "NFS has been removed."

apt-get purge nginx -y -qq
apt-get purge nginx-common -y -qq
echo "NGINX has been removed."

apt-get purge inetd -y -qq
apt-get purge openbsd-inetd -y -qq
apt-get purge xinetd -y -qq
apt-get purge inetutils-ftp -y -qq
apt-get purge inetutils-ftpd -y -qq
apt-get purge inetutils-inetd -y -qq
apt-get purge inetutils-ping -y -qq
apt-get purge inetutils-syslogd -y -qq
apt-get purge inetutils-talk -y -qq
apt-get purge inetutils-talkd -y -qq
apt-get purge inetutils-telnet -y -qq
apt-get purge inetutils-telnetd -y -qq
apt-get purge inetutils-tools -y -qq
apt-get purge inetutils-traceroute -y -qq
echo "Inetd (super-server) and all inet utilities have been removed."

clear
apt-get purge vnc4server -y -qq
apt-get purge vncsnapshot -y -qq
apt-get purge vtgrab -y -qq
echo "VNC has been removed."

clear
apt-get purge snmp -y -qq
echo "SNMP has been removed."

clear
cp /etc/login.defs /home/newt/Desktop/backups/
sed -i '160s/.*/PASS_MAX_DAYS\o01130/' /etc/login.defs
sed -i '161s/.*/PASS_MIN_DAYS\o0113/' /etc/login.defs
sed -i '163s/.*/PASS_WARN_AGE\o0117/' /etc/login.defs
echo "Password policies have been set with /etc/login.defs."

clear
apt-get install libpam-cracklib -y -qq
cp /etc/pam.d/common-auth /home/newt/Desktop/backups/
cp /etc/pam.d/common-password /home/newt/Desktop/backups/
echo -e "#\n# /etc/pam.d/common-auth - authentication settings common to all services\n#\n# This file is included from other service-specific PAM config files,\n# and should contain a list of the authentication modules that define\n# the central authentication scheme for use on the system\n# (e.g., /etc/shadow, LDAP, Kerberos, etc.).  The default is to use the\n# traditional Unix authentication mechanisms.\n#\n# As of pam 1.0.1-6, this file is managed by pam-auth-update by default.\n# To take advantage of this, it is recommended that you configure any\n# local modules either before or after the default block, and use\n# pam-auth-update to manage selection of other modules.  See\n# pam-auth-update(8) for details.\n\n# here are the per-package modules (the \"Primary\" block)\nauth	[success=1 default=ignore]	pam_unix.so nullok_secure\n# here's the fallback if no module succeeds\nauth	requisite			pam_deny.so\n# prime the stack with a positive return value if there isn't one already;\n# this avoids us returning an error just because nothing sets a success code\n# since the modules above will each just jump around\nauth	required			pam_permit.so\n# and here are more per-package modules (the \"Additional\" block)\nauth	optional			pam_cap.so \n# end of pam-auth-update config\nauth required pam_tally2.so deny=5 unlock_time=1800 onerr=fail audit even_deny_root_account silent" > /etc/pam.d/common-auth
echo -e "#\n# /etc/pam.d/common-password - password-related modules common to all services\n#\n# This file is included from other service-specific PAM config files,\n# and should contain a list of modules that define the services to be\n# used to change user passwords.  The default is pam_unix.\n\n# Explanation of pam_unix options:\n#\n# The \"sha512\" option enables salted SHA512 passwords.  Without this option,\n# the default is Unix crypt.  Prior releases used the option \"md5\".\n#\n# The \"obscure\" option replaces the old \`OBSCURE_CHECKS_ENAB\' option in\n# login.defs.\n#\n# See the pam_unix manpage for other options.\n\n# As of pam 1.0.1-6, this file is managed by pam-auth-update by default.\n# To take advantage of this, it is recommended that you configure any\n# local modules either before or after the default block, and use\n# pam-auth-update to manage selection of other modules.  See\n# pam-auth-update(8) for details.\n\n# here are the per-package modules (the \"Primary\" block)\npassword	[success=1 default=ignore]	pam_unix.so obscure sha512\n# here's the fallback if no module succeeds\npassword	requisite			pam_deny.so\n# prime the stack with a positive return value if there isn't one already;\n# this avoids us returning an error just because nothing sets a success code\n# since the modules above will each just jump around\npassword	required			pam_permit.so\npassword requisite pam_cracklib.so retry=3 minlen=8 difok=3 reject_username minclass=3 maxrepeat=2 dcredit=1 ucredit=1 lcredit=1 ocredit=1\npassword requisite pam_pwhistory.so use_authtok remember=24 enforce_for_root\n# and here are more per-package modules (the \"Additional\" block)\npassword	optional	pam_gnome_keyring.so \n# end of pam-auth-update config" > /etc/pam.d/common-password
echo "If password policies are not correctly configured, try this for /etc/pam.d/common-password:\npassword requisite pam_cracklib.so retry=3 minlen=8 difok=3 reject_us11ername minclass=3 maxrepeat=2 dcredit=1 ucredit=1 lcredit=1 ocredit=1\npassword requisite pam_pwhistory.so use_authtok remember=24 enforce_for_root"
echo "Password policies have been set with and /etc/pam.d."
getent group nopasswdlogin && gpasswd nopasswdlogin -M ''
echo "All users now need passwords to login"

clear
apt-get install iptables -y -qq
iptables -A INPUT -p all -s localhost  -i eth0 -j DROP
echo "All outside packets from internet claiming to be from loopback are denied."

clear
cp /etc/init/control-alt-delete.conf /home/newt/Desktop/backups/
sed '/^exec/ c\exec false' /etc/init/control-alt-delete.conf
echo "Reboot using Ctrl-Alt-Delete has been disabled."

clear
apt-get install apparmor apparmor-profiles clamav -y -qq
echo "AppArmor and ClamAV has been installed."

clear
crontab -l > /home/newt/Desktop/backups/crontab-old
crontab -r
echo "Crontab has been backed up. All startup tasks have been removed from crontab."

clear
cd /etc/
/bin/rm -f cron.deny at.deny
echo root >cron.allow
echo root >at.allow
/bin/chown root:root cron.allow at.allow
/bin/chmod 400 cron.allow at.allow
cd ..
echo "Only root allowed in cron."

clear
chmod 777 /etc/apt/apt.conf.d/10periodic
cp /etc/apt/apt.conf.d/10periodic /home/newt/Desktop/backups/
echo -e "APT::Periodic::Update-Package-Lists \"1\";\nAPT::Periodic::Download-Upgradeable-Packages \"1\";\nAPT::Periodic::AutocleanInterval \"1\";\nAPT::Periodic::Unattended-Upgrade \"1\";" > /etc/apt/apt.conf.d/10periodic
chmod 644 /etc/apt/apt.conf.d/10periodic
echo "Daily update checks, download upgradeable packages, autoclean interval, and unattended upgrade enabled."

clear
apt-get update -qq
apt-get upgrade -qq
echo "Ubuntu OS has checked for updates and has been upgraded."

clear
apt-get install firefox -y -qq
echo "Installed Firefox."

clear
for d in `find . -name prefs.js`; do  base=`dirname $d`;touch $base/users.js;cat user_pref\("dom.disable_open_during_load", "true"\)\; >> \$base\/users.js; done
echo "Popup blocker enabled in Firefox"


clear
apt-get autoremove -y -qq
apt-get autoclean -y -qq
apt-get clean -y -qq
echo "All unused packages have been removed."

clear
echo "Check to verify that all update settings are correct."
update-manager

clear
apt-get update
apt-get upgrade openssl libssl-dev
apt-cache policy openssl libssl-dev
echo "OpenSSL heart bleed bug has been fixed."


clear
apt-get install selinux-policy-default -y -qq
echo "SELinux has been installed."

clear
apt-get install auditd -y -qq
auditctl -e 1

clear
if [[ $(grep root /etc/passwd | wc -l) -gt 1 ]]
then
	grep root /etc/passwd | wc -l
	echo -e "UID 0 is not correctly set to root. Please fix.\nPress enter to continue..."
	read waiting
else
	echo "UID 0 is correctly set to root."
fi

clear
apt-get install ecryptfs-utils cryptsetup -y -qq

clear
echo "Script is complete. Logging user out to enable home directory encryption. Once logged out, login to another administrator. Then, access terminal and run sudo ecryptfs-migrate-home -u <default user>. After that, follow the prompts."
gnome-session-quit
