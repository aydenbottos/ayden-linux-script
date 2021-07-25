#!/bin/bash
clear
echo "Created by Ayden Bottos"
echo "Last Modified on Sep 19, 2020"
echo "Linux script"
echo "The password used is CyberTaipan123!"
pw=CyberTaipan123!

mkdir -p /home/newt/Desktop/
mkdir /quarantine
touch /home/newt/Desktop/badfiles.log
echo > /home/newt/Desktop/badfiles.log
chmod 777 /home/newt/Desktop/badfiles.log
echo -e "deb [arch=amd64] http://ftp.au.debian.org/debian/ jessie main contrib non-free\ndeb [arch=amd64] http://ftp.au.debian.org/debian/ jessie-updates main contrib non-free\ndeb [arch=amd64] http://security.debian.org/ jessie/updates main contrib non-free" > /etc/apt/sources.list
if [[ $EUID -ne 0 ]]
then
  echo This script must be run as root.
  exit
fi
echo "Script is being run as root."

chmod 777 /etc/apt/sources.list
cp /etc/apt/sources.list /home/newt/Desktop/backups/

chmod 644 /etc/apt/sources.list

echo "Running apt-get update"
apt-get update

echo "Installing apt-transport-https for apt https"
apt-get install apt-transport-https -y -qq

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

find $(pwd) -iname '*readme*.*' | xargs grep -oE "https:\/\/(.*).aspx" | xargs wget -o readme.aspx

awk -F: '$6 ~ /\/home/ {print}' /etc/passwd | cut -d: -f1 | while read line || [[ -n $line ]];
do
	if grep -q readme.aspx "$line"; then
		echo -e "$pw\n$pw" | passwd "$line"
		echo "$line has been given the password '$pw'."
		passwd -x30 -n3 -w7 $line
		usermod -U $line
		echo "$line's password has been given a maximum age of 30 days, minimum of 3 days, and warning of 7 days."	
	else
		deluser -r $line
		echo "Deleted unauthorised user $line."
	fi
done
clear

readmeusers="$(sed -n '/<pre>/,/<\/pre>/p' readme.aspx | sed -e "/password:/d" | sed -e "/<pre>/d" | sed -e "/<\/pre>/d" | sed -e "/<b>/d" | sed -e "s/ //g" | sed -e "s/[[:blank:]]//g" | sed -e 's/[[:space:]]//g' | sed -e '/^$/d' | sed -e 's/(you)//g' | cat)"
	
echo "$readmeusers" | while read readmeusersfor || [[ -n $line ]];
do
	useradd $readmeusersfor
	echo Created missing user from ReadMe.
	passwd -x30 -n3 -w7 $readmeusersfor
	usermod -U $readmeusersfor
	echo "$readmeusersfor's password has been given a maximum age of 30 days, minimum of 3 days, and warning of 7 days. ${users[${i}]}'s account has been locked."
done

readmeusers2="$(sed -n '/<pre>/,/<\/pre>/p' readme.aspx | sed -e "/password:/d" | sed -e "/<pre>/d" | sed -e "/<\/pre>/d" | sed -e "s/ //g" | sed -e "s/[[:blank:]]//g" | sed -e 's/[[:space:]]//g' | sed -e '/^$/d' | sed -e 's/(you)//g' | awk -vN=2 '/<\/b>/{++n} n>=N' - | sed -e "/<b>/d" | cat)"

awk -F: '$6 ~ /\/home/ {print}' /etc/passwd | cut -d: -f1 | while read line || [[ -n $line ]];
do
	if echo "$readmeusers2" | grep -qi "$line"; then
		gpasswd -d $line sudo
		gpasswd -d $line adm
		gpasswd -d $line lpadmin
		gpasswd -d $line sambashare
		gpasswd -d $line root
		echo "$line has been made a standard user."
	else
		gpasswd -a $line sudo
		gpasswd -a $line adm
		gpasswd -a $line lpadmin
		gpasswd -a $line sambashare
		echo "$line has been made an administrator."
	fi
done

sambaYN=no
ftpYN=no
sshYN=no
telnetYN=no
mailYN=no
printYN=no
dbYN=no
httpsYN=no
dnsYN=no
mediaFilesYN=no
vpnYN=no

services=$(cat readme.aspx | sed -e '/<ul>/,/<\/ul>/!d;/<\/ul>/q' | sed -e "/<ul>/d" | sed -e "/<\/ul>/d" |  sed -e "s/ //g" | sed -e "s/[[:blank:]]//g" | sed -e 's/[[:space:]]//g' | sed -e '/^$/d' | sed -e "s/<li>//g" | sed -e "s/<\/li>//g" | cat)
echo "$services" >> services
services=services

if grep -qi 'smb\|samba' "$services"; then
	sambaYN=yes
fi
if grep -qi ftp "$services"; then
	ftpYN=yes
fi
if grep -qi ssh "$services"; then
	sshYN=yes
fi
if grep -qi telnet "$services"; then
	telnetYN=yes
fi
if grep -qi mail "$services"; then
	mailYN=yes
fi
if grep -qi print "$services"; then
	printYN=yes
fi
if grep -qi 'db\|sql' "$services"; then
	dbYN=yes
fi
if grep -qi 'web\|apache\|http' "$services"; then
	httpsYN=yes
fi
if grep -qi 'bind9\|dns' "$services"; then
	dnsYN=yes
fi

clear
unalias -a
echo "All alias have been removed."

clear
echo "Functions:" > FunctionsAndVariables.txt
declare -F >> FunctionsAndVariables.txt
echo "Saved functions"

clear
echo "" >> FunctionsAndVariables.txt
echo "Variables:" >> FunctionsAndVariables.txt
printenv >> FunctionsAndVariables.txt
echo "Saved environment variables."

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
ufw default deny incoming
echo "Firewall enabled and all ports blocked."

clear
env i='() { :;}; echo vulnerable >> test' bash -c "echo this is a test"
if test -f "test"; then
	apt-get install --only-upgrade bash
fi
echo "Shellshock Bash vulnerability has been fixed."

clear
apt-get install stubby -y -qq
systemctl start stubby
systemctl enable stubby
echo "DNS-over-TLS has been enabled"

echo "netcat backdoors:" > backdoors.txt
netstat -ntlup | grep -e "netcat" -e "nc" -e "ncat" >> backdoors.txt

#goes and grabs the PID of the first process that has the name netcat. Kills the executable, doesn’t go and kill the item in one of the crons. Will go through until it has removed all netcats.
a=0;
for i in $(netstat -ntlup | grep -e "netcat" -e "nc" -e "ncat"); do
	if [[ $(echo $i | grep -c -e "/") -ne 0  ]]; then
		badPID=$(ps -ef | pgrep $( echo $i  | cut -f2 -d'/'));
		realPath=$(ls -la /proc/$badPID/exe | cut -f2 -d'>' | cut -f2 -d' ');
		cp $realPath $a
		echo "$realPath $a" >> backdoors.txt;
		a=$((a+1));
		rm $realPath;
		kill $badPID;
	fi
done
echo "" >> backdoors.txt
echo "Finished looking for netcat backdoors."

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
net.ipv6.conf.default.max_addresses = 1\n\n########## IPv6 networking ends ##############\n\nkernel.sysrq=0" > /etc/sysctl.conf
sysctl -p >> /dev/null
echo "Sysctl has been configured."

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
	
	usersSMB=$readmeusers
	usersSMBLength=${#usersSMB[@]}	
	for (( i=0;i<$usersSMBLength;i++))
	do
		echo -e "$pw\n$pw" | smbpasswd -a "${usersSMB[${i}]}"
		echo "${usersSMB[${i}]} has been given the default password for Samba."
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
	systemctl restart vsftpd
	echo "ftp, sftp, saft, ftps-data, and ftps ports have been allowed on the firewall. vsFTPd systemctl has been restarted."
else
	echo Response not recognized.
fi
echo "FTP is complete."


clear
if [ $sshYN == no ]
then
	echo "SSH port has been denied on the firewall. Open-SSH has been removed."
elif [ $sshYN == yes ]
then
	apt-get install openssh-server -y -qq
	ufw allow ssh
	cp /etc/ssh/sshd_config /home/newt/Desktop/backups/	
	usersSSH=$readmeusers
	echo -e "# Package generated configuration file\n# See the sshd_config(5) manpage for details\n\n# What ports, IPs and protocols we listen for\nPort 2200\n# Use these options to restrict which interfaces/protocols sshd will bind to\n#ListenAddress ::\n#ListenAddress 0.0.0.0\nProtocol 2\n# HostKeys for protocol version \nHostKey /etc/ssh/ssh_host_rsa_key\nHostKey /etc/ssh/ssh_host_dsa_key\nHostKey /etc/ssh/ssh_host_ecdsa_key\nHostKey /etc/ssh/ssh_host_ed25519_key\n#Privilege Separation is turned on for security\nUsePrivilegeSeparation yes\n\n# Lifetime and size of ephemeral version 1 server key\nKeyRegenerationInterval 3600\nServerKeyBits 1024\n\n# Logging\nSyslogFacility AUTH\nLogLevel VERBOSE\n\n# Authentication:\nLoginGraceTime 60\nPermitRootLogin no\nStrictModes yes\n\nRSAAuthentication yes\nPubkeyAuthentication yes\n#AuthorizedKeysFile	%h/.ssh/authorized_keys\n\n# Don't read the user's /home/newt/.rhosts and /home/newt/.shosts files\nIgnoreRhosts yes\n# For this to work you will also need host keys in /etc/ssh_known_hosts\nRhostsRSAAuthentication no\n# similar for protocol version 2\nHostbasedAuthentication no\n# Uncomment if you don't trust /home/newt/.ssh/known_hosts for RhostsRSAAuthentication\n#IgnoreUserKnownHosts yes\n\n# To enable empty passwords, change to yes (NOT RECOMMENDED)\nPermitEmptyPasswords no\n\n# Change to yes to enable challenge-response passwords (beware issues with\n# some PAM modules and threads)\nChallengeResponseAuthentication yes\n\n# Change to no to disable tunnelled clear text passwords\nPasswordAuthentication no\n\n# Kerberos options\n#KerberosAuthentication no\n#KerberosGetAFSToken no\n#KerberosOrLocalPasswd yes\n#KerberosTicketCleanup yes\n\n# GSSAPI options\n#GSSAPIAuthentication no\n#GSSAPICleanupCredentials yes\n\nX11Forwarding no\nX11DisplayOffset 10\nPrintMotd no\nPrintLastLog no\nTCPKeepAlive yes\n#UseLogin no\n\nMaxStartups 2\n#Banner /etc/issue.net\n\n# Allow client to pass locale environment variables\nAcceptEnv LANG LC_*\n\nSubsystem sftp /usr/lib/openssh/sftp-server\n\n# Set this to 'yes' to enable PAM authentication, account processing,\n# and session processing. If this is enabled, PAM authentication will\n# be allowed through the ChallengeResponseAuthentication and\n# PasswordAuthentication.  Depending on your PAM configuration,\n# PAM authentication via ChallengeResponseAuthentication may bypass\n# the setting of \"PermitRootLogin without-password\".\n# If you just want the PAM account and session checks to run without\n# PAM authentication, then enable this but set PasswordAuthentication\n# and ChallengeResponseAuthentication to 'no'.\nUsePAM yes\n\nAllowUsers $usersSSH\nDenyUsers\nRhostsAuthentication no\nClientAliveInterval 300\nClientAliveCountMax 0\nVerifyReverseMapping yes\nAllowTcpForwarding no\nUseDNS no\nPermitUserEnvironment no" > /etc/ssh/sshd_config
	systemctl restart sshd
	mkdir /home/$(whoami)/.ssh
	chmod 700 /home/$(whoami)/.ssh
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
	apt-get purge mariadb* -y -qq
	apt-get purge postgresql*
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
	systemctl restart mysql
	echo "ms-sql-s, ms-sql-m, mysql, and mysql-proxy ports have been allowed on the firewall. MySQL has been installed. MySQL config file has been secured. MySQL systemctl has been restarted."
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
	find /home -iname "*.midi" -type f >> /home/newt/Desktop/badfiles.log
	find /home -iname "*.mid" -type f >> /home/newt/Desktop/badfiles.log
	find /home -iname "*.mod" -type f >> /home/newt/Desktop/badfiles.log
	find /home -iname "*.mp3" -type f >> /home/newt/Desktop/badfiles.log
	find /home -iname "*.mp2" -type f >> /home/newt/Desktop/badfiles.log
	find /home -iname "*.mpa" -type f >> /home/newt/Desktop/badfiles.log
	find /home -iname "*.abs" -type f >> /home/newt/Desktop/badfiles.log
	find /home -iname "*.mpega" -type f >> /home/newt/Desktop/badfiles.log
	find /home -iname "*.au" -type f >> /home/newt/Desktop/badfiles.log
	find /home -iname "*.snd" -type f >> /home/newt/Desktop/badfiles.log
	find /home -iname "*.wav" -type f >> /home/newt/Desktop/badfiles.log
	find /home -iname "*.aiff" -type f >> /home/newt/Desktop/badfiles.log
	find /home -iname "*.aif" -type f >> /home/newt/Desktop/badfiles.log
	find /home -iname "*.sid" -type f >> /home/newt/Desktop/badfiles.log
	find /home -iname "*.flac" -type f >> /home/newt/Desktop/badfiles.log
	find /home -iname "*.ogg" -type f >> /home/newt/Desktop/badfiles.log
	clear
	echo "All audio files has been listed."

	find /home -iname "*.mpeg" -type f >> /home/newt/Desktop/badfiles.log
	find /home -iname "*.mpg" -type f >> /home/newt/Desktop/badfiles.log
	find /home -iname "*.mpe" -type f >> /home/newt/Desktop/badfiles.log
	find /home -iname "*.dl" -type f >> /home/newt/Desktop/badfiles.log
	find /home -iname "*.movie" -type f >> /home/newt/Desktop/badfiles.log
	find /home -iname "*.movi" -type f >> /home/newt/Desktop/badfiles.log
	find /home -iname "*.mv" -type f >> /home/newt/Desktop/badfiles.log
	find /home -iname "*.iff" -type f >> /home/newt/Desktop/badfiles.log
	find /home -iname "*.anim5" -type f >> /home/newt/Desktop/badfiles.log
	find /home -iname "*.anim3" -type f >> /home/newt/Desktop/badfiles.log
	find /home -iname "*.anim7" -type f >> /home/newt/Desktop/badfiles.log
	find /home -iname "*.avi" -type f >> /home/newt/Desktop/badfiles.log
	find /home -iname "*.vfw" -type f >> /home/newt/Desktop/badfiles.log
	find /home -iname "*.avx" -type f >> /home/newt/Desktop/badfiles.log
	find /home -iname "*.fli" -type f >> /home/newt/Desktop/badfiles.log
	find /home -iname "*.flc" -type f >> /home/newt/Desktop/badfiles.log
	find /home -iname "*.mov" -type f >> /home/newt/Desktop/badfiles.log
	find /home -iname "*.qt" -type f >> /home/newt/Desktop/badfiles.log
	find /home -iname "*.spl" -type f >> /home/newt/Desktop/badfiles.log
	find /home -iname "*.swf" -type f >> /home/newt/Desktop/badfiles.log
	find /home -iname "*.dcr" -type f >> /home/newt/Desktop/badfiles.log
	find /home -iname "*.dir" -type f >> /home/newt/Desktop/badfiles.log
	find /home -iname "*.dxr" -type f >> /home/newt/Desktop/badfiles.log
	find /home -iname "*.rpm" -type f >> /home/newt/Desktop/badfiles.log
	find /home -iname "*.rm" -type f >> /home/newt/Desktop/badfiles.log
	find /home -iname "*.smi" -type f >> /home/newt/Desktop/badfiles.log
	find /home -iname "*.ra" -type f >> /home/newt/Desktop/badfiles.log
	find /home -iname "*.ram" -type f >> /home/newt/Desktop/badfiles.log
	find /home -iname "*.rv" -type f >> /home/newt/Desktop/badfiles.log
	find /home -iname "*.wmv" -type f >> /home/newt/Desktop/badfiles.log
	find /home -iname "*.asf" -type f >> /home/newt/Desktop/badfiles.log
	find /home -iname "*.asx" -type f >> /home/newt/Desktop/badfiles.log
	find /home -iname "*.wma" -type f >> /home/newt/Desktop/badfiles.log
	find /home -iname "*.wax" -type f >> /home/newt/Desktop/badfiles.log
	find /home -iname "*.wmv" -type f >> /home/newt/Desktop/badfiles.log
	find /home -iname "*.wmx" -type f >> /home/newt/Desktop/badfiles.log
	find /home -iname "*.3gp" -type f >> /home/newt/Desktop/badfiles.log
	find /home -iname "*.mov" -type f >> /home/newt/Desktop/badfiles.log
	find /home -iname "*.mp4" -type f >> /home/newt/Desktop/badfiles.log
	find /home -iname "*.avi" -type f >> /home/newt/Desktop/badfiles.log
	find /home -iname "*.swf" -type f >> /home/newt/Desktop/badfiles.log
	find /home -iname "*.flv" -type f >> /home/newt/Desktop/badfiles.log
	find /home -iname "*.m4v" -type f >> /home/newt/Desktop/badfiles.log
	clear
	echo "All video files have been listed."
	
	find /home -iname "*.tiff" -type f >> /home/newt/Desktop/badfiles.log
	find /home -iname "*.tif" -type f >> /home/newt/Desktop/badfiles.log
	find /home -iname "*.rs" -type f >> /home/newt/Desktop/badfiles.log
	find /home -iname "*.im1" -type f >> /home/newt/Desktop/badfiles.log
	find /home -iname "*.gif" -type f >> /home/newt/Desktop/badfiles.log
	find /home -iname "*.jpeg" -type f >> /home/newt/Desktop/badfiles.log
	find /home -iname "*.jpg" -type f >> /home/newt/Desktop/badfiles.log
	find /home -iname "*.jpe" -type f >> /home/newt/Desktop/badfiles.log
	find /home -iname "*.png" -type f >> /home/newt/Desktop/badfiles.log
	find /home -iname "*.rgb" -type f >> /home/newt/Desktop/badfiles.log
	find /home -iname "*.xwd" -type f >> /home/newt/Desktop/badfiles.log
	find /home -iname "*.xpm" -type f >> /home/newt/Desktop/badfiles.log
	find /home -iname "*.ppm" -type f >> /home/newt/Desktop/badfiles.log
	find /home -iname "*.pbm" -type f >> /home/newt/Desktop/badfiles.log
	find /home -iname "*.pgm" -type f >> /home/newt/Desktop/badfiles.log
	find /home -iname "*.pcx" -type f >> /home/newt/Desktop/badfiles.log
	find /home -iname "*.ico" -type f >> /home/newt/Desktop/badfiles.log
	find /home -iname "*.svg" -type f >> /home/newt/Desktop/badfiles.log
	find /home -iname "*.svgz" -type f >> /home/newt/Desktop/badfiles.log
	clear
	echo "All image files have been listed."
else
	echo Response not recognized.
fi
echo "Media files are complete."

find / -type f -perm 777 >> /home/newt/Desktop/badfiles.log
find / -type f -perm 776 >> /home/newt/Desktop/badfiles.log
find / -type f -perm 775 >> /home/newt/Desktop/badfiles.log
find / -type f -perm 774 >> /home/newt/Desktop/badfiles.log
find / -type f -perm 773 >> /home/newt/Desktop/badfiles.log
find / -type f -perm 772 >> /home/newt/Desktop/badfiles.log
find / -type f -perm 771 >> /home/newt/Desktop/badfiles.log
find / -type f -perm 770 >> /home/newt/Desktop/badfiles.log
find / -type f -perm 767 >> /home/newt/Desktop/badfiles.log
find / -type f -perm 766 >> /home/newt/Desktop/badfiles.log
find / -type f -perm 765 >> /home/newt/Desktop/badfiles.log
find / -type f -perm 764 >> /home/newt/Desktop/badfiles.log
find / -type f -perm 763 >> /home/newt/Desktop/badfiles.log
find / -type f -perm 762 >> /home/newt/Desktop/badfiles.log
find / -type f -perm 761 >> /home/newt/Desktop/badfiles.log
find / -type f -perm 760 >> /home/newt/Desktop/badfiles.log
find / -type f -perm 757 >> /home/newt/Desktop/badfiles.log
find / -type f -perm 756 >> /home/newt/Desktop/badfiles.log
find / -type f -perm 755 >> /home/newt/Desktop/badfiles.log
find / -type f -perm 754 >> /home/newt/Desktop/badfiles.log
find / -type f -perm 753 >> /home/newt/Desktop/badfiles.log
find / -type f -perm 752 >> /home/newt/Desktop/badfiles.log
find / -type f -perm 751 >> /home/newt/Desktop/badfiles.log
find / -type f -perm 750 >> /home/newt/Desktop/badfiles.log
find / -type f -perm 747 >> /home/newt/Desktop/badfiles.log
find / -type f -perm 746 >> /home/newt/Desktop/badfiles.log
find / -type f -perm 745 >> /home/newt/Desktop/badfiles.log
find / -type f -perm 744 >> /home/newt/Desktop/badfiles.log
find / -type f -perm 743 >> /home/newt/Desktop/badfiles.log
find / -type f -perm 742 >> /home/newt/Desktop/badfiles.log
find / -type f -perm 741 >> /home/newt/Desktop/badfiles.log
find / -type f -perm 740 >> /home/newt/Desktop/badfiles.log
find / -type f -perm 737 >> /home/newt/Desktop/badfiles.log
find / -type f -perm 736 >> /home/newt/Desktop/badfiles.log
find / -type f -perm 735 >> /home/newt/Desktop/badfiles.log
find / -type f -perm 734 >> /home/newt/Desktop/badfiles.log
find / -type f -perm 733 >> /home/newt/Desktop/badfiles.log
find / -type f -perm 732 >> /home/newt/Desktop/badfiles.log
find / -type f -perm 731 >> /home/newt/Desktop/badfiles.log
find / -type f -perm 730 >> /home/newt/Desktop/badfiles.log
find / -type f -perm 727 >> /home/newt/Desktop/badfiles.log
find / -type f -perm 726 >> /home/newt/Desktop/badfiles.log
find / -type f -perm 725 >> /home/newt/Desktop/badfiles.log
find / -type f -perm 724 >> /home/newt/Desktop/badfiles.log
find / -type f -perm 723 >> /home/newt/Desktop/badfiles.log
find / -type f -perm 722 >> /home/newt/Desktop/badfiles.log
find / -type f -perm 721 >> /home/newt/Desktop/badfiles.log
find / -type f -perm 720 >> /home/newt/Desktop/badfiles.log
find / -type f -perm 717 >> /home/newt/Desktop/badfiles.log
find / -type f -perm 716 >> /home/newt/Desktop/badfiles.log
find / -type f -perm 715 >> /home/newt/Desktop/badfiles.log
find / -type f -perm 714 >> /home/newt/Desktop/badfiles.log
find / -type f -perm 713 >> /home/newt/Desktop/badfiles.log
find / -type f -perm 712 >> /home/newt/Desktop/badfiles.log
find / -type f -perm 711 >> /home/newt/Desktop/badfiles.log
find / -type f -perm 710 >> /home/newt/Desktop/badfiles.log
find / -type f -perm 707 >> /home/newt/Desktop/badfiles.log
find / -type f -perm 706 >> /home/newt/Desktop/badfiles.log
find / -type f -perm 705 >> /home/newt/Desktop/badfiles.log
find / -type f -perm 704 >> /home/newt/Desktop/badfiles.log
find / -type f -perm 703 >> /home/newt/Desktop/badfiles.log
find / -type f -perm 702 >> /home/newt/Desktop/badfiles.log
find / -type f -perm 701 >> /home/newt/Desktop/badfiles.log
find / -type f -perm 700 >> /home/newt/Desktop/badfiles.log
echo "All files with perms 700-777 have been logged."

clear
find / -iname "*.php" -type f >> /home/newt/Desktop/badfiles.log
echo "All PHP files have been listed above. ('/var/cache/dictionaries-common/sqspell.php' is a system PHP file)"

clear
find / -perm -4000 >> /home/newt/Desktop/badfiles.log
find / -perm -2000 >> /home/newt/Desktop/badfiles.log

clear
apt-get purge netcat -y -qq
apt-get purge netcat-openbsd -y -qq
apt-get purge netcat-traditional -y -qq
apt-get purge gcc g++ -y -qq
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

apt-get purge wireshark* tshark kismet -y -qq
clear
echo "Wireshark, TShark and Kismet have been removed."

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
apt-get install lynis -y -qq
( lynis -c -Q >> LynisOutput.txt; echo "Finished Lynis" ) &
disown; sleep 2;
echo "Running Lynis."

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
echo -e "#\n# /etc/pam.d/common-auth - authentication settings common to all systemctls\n#\n# This file is included from other systemctl-specific PAM config files,\n# and should contain a list of the authentication modules that define\n# the central authentication scheme for use on the system\n# (e.g., /etc/shadow, LDAP, Kerberos, etc.).  The default is to use the\n# traditional Unix authentication mechanisms.\n#\n# As of pam 1.0.1-6, this file is managed by pam-auth-update by default.\n# To take advantage of this, it is recommended that you configure any\n# local modules either before or after the default block, and use\n# pam-auth-update to manage selection of other modules.  See\n# pam-auth-update(8) for details.\n\n# here are the per-package modules (the \"Primary\" block)\nauth	[success=1 default=ignore]	pam_unix.so nullok_secure\n# here's the fallback if no module succeeds\nauth	requisite			pam_deny.so\n# prime the stack with a positive return value if there isn't one already; >> /dev/null\n# this avoids us returning an error just because nothing sets a success code\n# since the modules above will each just jump around\nauth	required			pam_permit.so\n# and here are more per-package modules (the \"Additional\" block)\nauth	optional			pam_cap.so \n# end of pam-auth-update config\nauth required pam_tally2.so deny=5 unlock_time=1800 onerr=fail audit even_deny_root_account silent" > /etc/pam.d/common-auth
echo -e "#\n# /etc/pam.d/common-password - password-related modules common to all systemctls\n#\n# This file is included from other systemctl-specific PAM config files,\n# and should contain a list of modules that define the systemctls to be\n# used to change user passwords.  The default is pam_unix.\n\n# Explanation of pam_unix options:\n#\n# The \"sha512\" option enables salted SHA512 passwords.  Without this option,\n# the default is Unix crypt.  Prior releases used the option \"md5\".\n#\n# The \"obscure\" option replaces the old \`OBSCURE_CHECKS_ENAB\' option in\n# login.defs.\n#\n# See the pam_unix manpage for other options.\n\n# As of pam 1.0.1-6, this file is managed by pam-auth-update by default.\n# To take advantage of this, it is recommended that you configure any\n# local modules either before or after the default block, and use\n# pam-auth-update to manage selection of other modules.  See\n# pam-auth-update(8) for details.\n\n# here are the per-package modules (the \"Primary\" block)\npassword	[success=1 default=ignore]	pam_unix.so obscure sha512\n# here's the fallback if no module succeeds\npassword	requisite			pam_deny.so\n# prime the stack with a positive return value if there isn't one already; >> /dev/null\n# this avoids us returning an error just because nothing sets a success code\n# since the modules above will each just jump around\npassword	required			pam_permit.so\npassword requisite pam_cracklib.so retry=3 minlen=8 difok=3 reject_username minclass=3 maxrepeat=2 dcredit=1 ucredit=1 lcredit=1 ocredit=1\npassword requisite pam_pwhistory.so use_authtok remember=24 enforce_for_root\n# and here are more per-package modules (the \"Additional\" block)\npassword	optional	pam_gnome_keyring.so \n# end of pam-auth-update config" > /etc/pam.d/common-password
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
for d in $(find /home/$(whoami)/.mozilla/firefox -name prefs.js); do base=$(dirname $d);touch $base/users.js;echo "user_pref(\"dom.disable_open_during_load\", \"true\");" >> $base/users.js; done
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

PATH=$(getconf PATH)
echo "PATH reset to normal."

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
	echo -e "UID 0 is not correctly set to root. Please fix."
else
	echo "UID 0 is correctly set to root."
fi

clear
apt-get install ecryptfs-utils cryptsetup -y -qq

clear
echo "Script is complete. Logging user out to enable home directory encryption. Once logged out, login to another administrator. Then, access terminal and run sudo ecryptfs-migrate-home -u <default user>. After that, follow the prompts."
gnome-session-quit && xfce4-session-logout
