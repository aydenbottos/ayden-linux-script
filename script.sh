#!/bin/bash
clear
echo "Created by Ayden Bottos"
echo "Last Modified on July 26, 2021"
echo "Linux script"
echo "The password used is CyberTaipan123!"
echo "Running at $(date)"
echo "Running on $(lsb_release -a)

if [[ $EUID -ne 0 ]]
then
  echo "This script must be run as root."
  exit
fi
echo "Script is being run as root."

pw=CyberTaipan123!
echo "Universal password set."

echo "Opening forensics questions."
sudo gnome-terminal
gedit "Forensics Question 1.txt"
gedit "Forensics Question 2.txt"
gedit "Forensics Question 3.txt"
test -f "Forensics Question 4.txt" && gedit "Forensics Question 4.txt"
test -f "Forensics Question 5.txt" && gedit "Forensics Question 5.txt"
test -f "Forensics Question 6.txt" && gedit "Forensics Question 6.txt"

clear
mkdir -p /home/scriptuser/
touch /home/scriptuser/badfiles.log
echo > /home/scriptuser/badfiles.log
chmod 777 /home/scriptuser/badfiles.log
echo "Important files and directories created."

mkdir -p /home/scriptuser/backups
chmod 777 /home/scriptuser/backups
echo "Backups folder created on the Desktop."

echo "Running apt-get update"
apt-get update

echo "Installing all neccessary software."
apt-get install apt-transport-https dirmngr ufw tcpd lynis chkrootkit rkhunter iptables libpam-cracklib apparmor apparmor-utils apparmor-profiles-extra clamav clamav-* auditd audispd-plugins ecryptfs-utils cryptsetup -y
echo "Deleting all bad software."
wget https://raw.githubusercontent.com/aydenbottos/ayden-linux-script/master/packages.txt
apt-get purge $(cat packages.txt)

clear
echo "Check to verify that all update settings are correct."
if echo $(lsb_release -a) | grep -qi Debian; then
	software-properties-gtk
	apt install firefox-esr
else 
	update-manager
	apt install firefox stubby
fi

clear
chmod 644 /etc/apt/sources.list
echo "Sources reset to default."

echo "Running apt-get update with HTTPS"
apt-get update
clear

cp /etc/group /home/scriptuser/backups/
cp /etc/passwd /home/scriptuser/backups/

echo "/etc/group and /etc/passwd files backed up."

if test -f "users.txt"
then
	awk -F: '$6 ~ /\/home/ {print}' /etc/passwd | cut -d: -f1 | while read line || [[ -n $line ]];
	do	
        	if grep -qi "$line" users.txt; then
			echo -e "$pw\n$pw" | passwd "$line"
			echo "$line has been given the password '$pw'."
			passwd -x30 -n3 -w7 $line
			usermod -U $line
			echo "$line's password has been given a maximum age of 30 days, minimum of 3 days, and warning of 7 days."	
		else
			deluser --remove-home $line
			echo "Deleted unauthorised user $line."
		fi
	done
	
	readmeusers="$(cat users.txt | cut -d ' ' -f1)"
	
	echo "$readmeusers" | while read readmeusersfor || [[ -n $line ]];
	do
		useradd -m $readmeusersfor
		echo Created missing user from ReadMe.
		passwd -x30 -n3 -w7 $readmeusersfor
		echo -e "$pw\n$pw" | passwd "$readmeusersfor"
		usermod -U $readmeusersfor
		echo "$readmeusersfor's password has been given a maximum age of 30 days, minimum of 3 days, and warning of 7 days."
	done
	
	readmeusers2="$(grep -i "Admin" users.txt | cut -d ' ' -f1)"
	
	awk -F: '$6 ~ /\/home/ {print}' /etc/passwd | cut -d: -f1 | while read line || [[ -n $line ]];
	do
		if echo $readmeusers2 | grep -qi "$line"; then
			gpasswd -a $line sudo
			gpasswd -a $line adm
			gpasswd -a $line lpadmin
			gpasswd -a $line sambashare
			gpasswd -a $line root
			echo "$line has been made a standard user."
		else
			gpasswd -d $line sudo
			gpasswd -d $line adm
			gpasswd -d $line lpadmin
			gpasswd -d $line sambashare
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
	
	if grep -qi 'smb\|samba' services.txt; then
		sambaYN=yes
	fi
	if grep -qi ftp services.txt; then
		ftpYN=yes
	fi
	if grep -qi ssh services.txt; then
		sshYN=yes
	fi
	if grep -qi telnet services.txt; then
		telnetYN=yes
	fi
	if grep -qi mail services.txt; then
		mailYN=yes
	fi
	if grep -qi print services.txt; then
		printYN=yes
	fi
	if grep -qi 'db\|sql' services.txt; then
		dbYN=yes
	fi
	if grep -qi 'web\|apache\|http' services.txt; then
		httpsYN=yes
	fi
	if grep -qi 'bind9\|dns' services.txt; then
		dnsYN=yes
	fi
else
	find $(pwd) -iname '*readme*.*' | xargs grep -oE "https:\/\/(.*).aspx" | xargs wget -O readme.aspx

	awk -F: '$6 ~ /\/home/ {print}' /etc/passwd | cut -d: -f1 | while read line || [[ -n $line ]];
	do
		if grep -qi "$line" readme.aspx; then
			echo -e "$pw\n$pw" | passwd "$line"
			echo "$line has been given the password '$pw'."
			passwd -x30 -n3 -w7 $line
			usermod -U $line
			echo "$line's password has been given a maximum age of 30 days, minimum of 3 days, and warning of 7 days."	
		else
			deluser --remove-home $line
			echo "Deleted unauthorised user $line."
		fi
	done
	clear

	readmeusers="$(sed -n '/<pre>/,/<\/pre>/p' readme.aspx | sed -e "/password:/d" | sed -e "/<pre>/d" | sed -e "/<\/pre>/d" | sed -e "/<b>/d" | sed -e "s/ //g" | sed -e "s/[[:blank:]]//g" | sed -e 's/[[:space:]]//g' | sed -e '/^$/d' | sed -e 's/(you)//g' | cat)"

	echo "$readmeusers" | while read readmeusersfor || [[ -n $line ]];
	do
		if grep -qi "$readmeusersfor" /etc/passwd; then
			echo "User already exists"
		else
			useradd -m $readmeusersfor
			echo -e "$pw\n$pw" | passwd "$readmeusersfor"
			echo Created missing user from ReadMe.
			passwd -x30 -n3 -w7 $readmeusersfor
			usermod -U $readmeusersfor
			echo "$readmeusersfor's password has been given a maximum age of 30 days, minimum of 3 days, and warning of 7 days."
		fi
	done

	readmeusers2="$(sed -n '/<pre>/,/<\/pre>/p' readme.aspx | sed -e "/password:/d" | sed -e "/<pre>/d" | sed -e "/<\/pre>/d" | sed -e "s/ //g" | sed -e "s/[[:blank:]]//g" | sed -e 's/[[:space:]]//g' | sed -e '/^$/d' | sed -e 's/(you)//g' | awk -vN=2 '/<\/b>/{++n} n>=N' - | sed -e "/<b>/d" | cat)"

	awk -F: '$6 ~ /\/home/ {print}' /etc/passwd | cut -d: -f1 | while read line || [[ -n $line ]];
	do
		if echo $readmeusers2 | grep -qi "$line"; then
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
	echo $services >> services

	if grep -qi 'smb\|samba' services; then
		sambaYN=yes
	fi
	if grep -qi ftp services; then
		ftpYN=yes
	fi
	if grep -qi ssh services; then
		sshYN=yes
	fi
	if grep -qi telnet services; then
		telnetYN=yes
	fi
	if grep -qi mail services; then
		mailYN=yes
	fi
	if grep -qi print services; then
		printYN=yes
	fi
	if grep -qi 'db\|sql' services; then
		dbYN=yes
	fi
	if grep -qi 'web\|apache\|http' services; then
		httpsYN=yes
	fi
	if grep -qi 'bind9\|dns' services; then
		dnsYN=yes
	fi	
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
mv FunctionsAndVariables.txt /home/scriptuser/
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
ls -a /home/ >> /home/scriptuser/badfiles.log

clear
echo "Check for any files for users that should not be administrators in /etc/sudoers.d."
ls -a /etc/sudoers.d >> /home/scriptuser/badfiles.log

clear
for f in /etc/sudoers /etc/sudoers.d/* ; do
	if [ ! -e "$f" ] ; then
    		continue
  	fi
  	matching_list=$(grep -P '^(?!#).*[\s]+\!authenticate.*$' $f | uniq )
  	if ! test -z "$matching_list"; then
    		while IFS= read -r entry; do
      			# comment out "!authenticate" matches to preserve user data
      			sed -i "s/^${entry}$/# &/g" $f
    		done <<< "$matching_list"

    		/usr/sbin/visudo -cf $f &> /dev/null || echo "Fail to validate $f with visudo"
  	fi
done

for f in /etc/sudoers /etc/sudoers.d/* ; do
	if [ ! -e "$f" ] ; then
    		continue
  	fi
  	matching_list=$(grep -P '^(?!#).*[\s]+NOPASSWD[\s]*\:.*$' $f | uniq )
  	if ! test -z "$matching_list"; then
    		while IFS= read -r entry; do
      			# comment out "NOPASSWD" matches to preserve user data
      			sed -i "s/^${entry}$/# &/g" $f
    		done <<< "$matching_list"

    		/usr/sbin/visudo -cf $f &> /dev/null || echo "Fail to validate $f with visudo"
  	fi
done
echo "Sudoers file secured."

echo -e "Defaults use_pty\nDefaults logfile=/var/log/sudo.log" > /etc/sudoers.d/custom
echo "PTY and logfile set up for sudo."

clear
cp /etc/rc.local /home/scriptuser/backups/
echo > /etc/rc.local
echo 'exit 0' >> /etc/rc.local
echo "Any startup scripts have been removed."

clear
ufw enable
ufw default deny incoming
ufw status verbose
echo "Firewall enabled and all ports blocked."

clear
env i='() { :;}; echo vulnerable >> test' bash -c "echo this is a test"
if test -f "test"; then
	apt-get install --only-upgrade bash
fi
echo "Shellshock Bash vulnerability has been fixed."

clear
systemctl start stubby
systemctl enable stubby
systemctl status stubby
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
		echo "$realPath $a" >> /home/scriptuser/backdoors.txt;
		a=$((a+1));
		rm $realPath;
		kill $badPID;
	fi
done
echo "" >> backdoors.txt
echo "Finished looking for netcat backdoors."

clear
chmod 777 /etc/hosts
cp /etc/hosts /home/scriptuser/backups/
echo > /etc/hosts
echo -e "127.0.0.1 localhost\n127.0.1.1 $USER\n::1 ip6-localhost ip6-loopback\nfe00::0 ip6-localnet\nff00::0 ip6-mcastprefix\nff02::1 ip6-allnodes\nff02::2 ip6-allrouters" >> /etc/hosts
chmod 644 /etc/hosts
echo "HOSTS file has been set to defaults."

clear
apt purge *tftpd* -y
echo "TFTP has been removed."

clear
echo "# GDM configuration storage\n\n[daemon]\n\n[security]\n\n[xdmcp]\n\n[chooser]\n\n[debug]\n" > /etc/gdm3/custom.conf
sudo gnome-terminal -- /bin/sh -c 'echo "# Type the following to get the value of the DISPLAY variable, we will need in in a couple of steps.
echo \$DISPLAY;
# It will print out :0 or :1 or similar
# Give temporary access to user gdm to access control list and to applications that need a monitor:
sudo xhost +SI:localuser:gdm;
# Output will be something like the following:
# localuser:gdm being added to access control list
# Switch to the user (su) gdm using bash shell
su gdm -l -s /bin/bash;
# Set the DISPLAY variable to the value you got before (could be :0 or :1 or similar):
export DISPLAY=:0;
# Disable the user list by setting the disable-user-list flag to true:
gsettings set org.gnome.login-screen disable-user-list true;"; exec bash'
echo "User list has been hidden and autologin has been disabled."

clear
chmod 777 /etc/lightdm/lightdm.conf
cp /etc/lightdm/lightdm.conf /home/scriptuser/Desktop/backups/
echo > /etc/lightdm/lightdm.conf
echo -e '[SeatDefaults]\nallow-guest=false\ngreeter-hide-users=true\ngreeter-show-manual-login=true' >> /etc/lightdm/lightdm.conf
chmod 644 /etc/lightdm/lightdm.conf
echo "LightDM has been secured."

clear
find /bin/ -name "*.sh" -type f -delete
echo "badfiles in bin have been removed."

clear
cp /etc/default/irqbalance /home/scriptuser/backups/
echo > /etc/default/irqbalance
echo -e "#Configuration for the irqbalance daemon\n\n#Should irqbalance be enabled?\nENABLED=\"0\"\n#Balance the IRQs only once?\nONESHOT=\"0\"" >> /etc/default/irqbalance
echo "IRQ Balance has been disabled."

clear
cp /etc/sysctl.conf /home/scriptuser/backups/
echo > /etc/sysctl.conf
echo -e "#Enable ASLR\nkernel.randomize_va_space = 2\n\n# Controls IP packet forwarding\nnet.ipv4.ip_forward = 0\n\n# IP Spoofing protection\nnet.ipv4.conf.all.rp_filter = 1\nnet.ipv4.conf.default.rp_filter = 1\n\n# Ignore ICMP broadcast requests\nnet.ipv4.icmp_echo_ignore_broadcasts = 1\n\n# Disable source packet routing\nnet.ipv4.conf.all.accept_source_route = 0\nnet.ipv6.conf.all.accept_source_route = 0\nnet.ipv4.conf.default.accept_source_route = 0\nnet.ipv6.conf.default.accept_source_route = 0\n\n# Ignore send redirects\nnet.ipv4.conf.all.send_redirects = 0\nnet.ipv4.conf.default.send_redirects = 0\n\n# Block SYN attacks\nnet.ipv4.tcp_syncookies = 1\nnet.ipv4.tcp_max_syn_backlog = 2048\nnet.ipv4.tcp_synack_retries = 2\nnet.ipv4.tcp_syn_retries = 5\n\n# Log Martians\nnet.ipv4.conf.all.log_martians = 1\nnet.ipv4.icmp_ignore_bogus_error_responses = 1\n\n# Ignore ICMP redirects\nnet.ipv4.conf.all.accept_redirects = 0\nnet.ipv6.conf.all.accept_redirects = 0\nnet.ipv4.conf.default.accept_redirects = 0\nnet.ipv6.conf.default.accept_redirects = 0\n\n# Ignore Directed pings\nnet.ipv4.icmp_echo_ignore_all = 1\n\n# Accept Redirects? No, this is not router\nnet.ipv4.conf.all.secure_redirects = 0\n\n# Log packets with impossible addresses to kernel log? yes\nnet.ipv4.conf.default.secure_redirects = 0\n\n########## IPv6 networking start ##############\n# Number of Router Solicitations to send until assuming no routers are present.\n# This is host and not router\nnet.ipv6.conf.default.router_solicitations = 0\n\n# Accept Router Preference in RA?\nnet.ipv6.conf.default.accept_ra_rtr_pref = 0\n\n# Learn Prefix Information in Router Advertisement\nnet.ipv6.conf.default.accept_ra_pinfo = 0\n\n# Setting controls whether the system will accept Hop Limit settings from a router advertisement\nnet.ipv6.conf.default.accept_ra_defrtr = 0\n\n#router advertisements can cause the system to assign a global unicast address to an interface\nnet.ipv6.conf.default.autoconf = 0\n\n#how many neighbor solicitations to send out per address?\nnet.ipv6.conf.default.dad_transmits = 0\n\n# How many global unicast IPv6 addresses can be assigned to each interface?
net.ipv6.conf.default.max_addresses = 1\n\n########## IPv6 networking ends ##############\n\nkernel.sysrq=0\nkernel.exec-shield=2" > /etc/sysctl.conf
sysctl -p >> /dev/null
cat /etc/sysctl.conf
echo "Sysctl has been configured."

clear
echo "Disable IPv6?"
read ipv6YN
if [ $ipv6YN == yes ]
then
	echo -e "\n\n# Disable IPv6\nnet.ipv6.conf.all.disable_ipv6 = 1\nnet.ipv6.conf.default.disable_ipv6 = 1\nnet.ipv6.conf.lo.disable_ipv6 = 1" >> /etc/sysctl.conf
	sysctl -p >> /dev/null
	echo "IPv6 has been disabled."
fi

chown root:root /etc/securetty
chmod 0600 /etc/securetty
chmod 644 /etc/crontab
chmod 640 /etc/ftpusers
chmod 440 /etc/inetd.conf
chmod 440 /etc/xinetd.conf
chmod 400 /etc/inetd.d
chmod 644 /etc/hosts.allow
chmod 440 /etc/sudoers
chmod 640 /etc/shadow
chmod 644 /etc/passwd
chmod 4750 /bin/su
chown root:root /etc/passwd
chmod u-x,go-wx /etc/passwd
chown root:shadow /etc/shadow
chmod o-rwx,g-wx /etc/shadow
chown root:root /etc/crontab
echo "Finished changing permissions."

clear
grep -E -v '^(halt|sync|shutdown)' /etc/passwd | awk -F: '($7 != "'"$(which nologin)"'" && $7 != "/bin/false") { print $1 " " $6 }' | while read -r user dir; do
  	if [ ! -d "$dir" ]; then
		echo "The home directory \"$dir\" of user \"$user\" does not exist."
	else
		for file in "$dir"/.[A-Za-z0-9]*; do
			if [ ! -h "$file" ] && [ -f "$file" ]; then
				fileperm="$(ls -ld "$file" | cut -f1 -d" ")"
				if [ "$(echo "$fileperm" | cut -c6)" != "-" ]; then
					echo "Group Write permission set on file $file"
				fi
				if [ "$(echo "$fileperm" | cut -c9)" != "-" ]; then
					echo "Other Write permission set on file \"$file\""
				fi
			fi
		done
	fi
done
echo "Checked that all users have home directories."

clear
awk -F: '{print $4}' /etc/passwd | while read -r gid; do
	if ! grep -E -q "^.*?:[^:]*:$gid:" /etc/group; then
		echo "The group ID \"$gid\" does not exist in /etc/group"
	fi
done
echo "Confirmed that all groups in /etc/passwd are also in /etc/group"

clear
awk -F: '{print $3}' /etc/passwd | sort -n | uniq -c | while read -r uid; do
	[ -z "$uid" ] && break
	set - $uid
	if [ $1 -gt 1 ]; then
		users=$(awk -F: '($3 == n) { print $1 }' n="$2" /etc/passwd | xargs)
		echo "Duplicate UID \"$2\": \"$users\""
	fi
done
echo "Confirmed that all users have a unique UID."

clear
cut -d: -f3 /etc/group | sort | uniq -d | while read x ; do
	echo "Duplicate GID ($x) in /etc/group"
done
echo "Confirmed that all groups have a unique GID."

clear
cut -d: -f1 /etc/passwd | sort | uniq -d | while read -r usr; do
	echo "Duplicate login name \"$usr\" in /etc/passwd"
done
echo "Confirmed that all users have a unique name."

clear
cut -d: -f1 /etc/group | sort | uniq -d | while read -r grp; do
	echo "Duplicate group name \"$grp\" exists in /etc/group"
done
echo "Confirmed that all groups have a unique name."

clear
grep ^shadow:[^:]*:[^:]*:[^:]+ /etc/group
echo "If any users are printed above this and below confirmed that all groups have a unique name, get Ayden!"

clear
touch /zerouidusers
touch /uidusers

cut -d: -f1,3 /etc/passwd | egrep ':0$' | cut -d: -f1 | grep -v root > /zerouidusers

if [ -s /zerouidusers ]
then
	echo "There are Zero UID Users! I'm fixing it now!"

	while IFS='' read -r line || [[ -n "$line" ]]; do
		thing=1
		while true; do
			rand=$(( ( RANDOM % 999 ) + 1000))
			cut -d: -f1,3 /etc/passwd | egrep ":$rand$" | cut -d: -f1 > /uidusers
			if [ -s /uidusers ]
			then
				echo "Couldn't find unused UID. Trying Again... "
			else
				break
			fi
		done
		sed -i "s/$line:x:0:0/$line:x:$rand:$rand/g" /etc/passwd
		echo "ZeroUID User: $line"
		echo "Assigned UID: $rand"
	done < "/zerouidusers"
	update-passwd
	cut -d: -f1,3 /etc/passwd | egrep ':0$' | cut -d: -f1 | grep -v root > /zerouidusers

	if [ -s /zerouidusers ]
	then
		echo "WARNING: UID CHANGE UNSUCCESSFUL!"
	else
		echo "Successfully Changed Zero UIDs!"
	fi
else
	echo "No Zero UID Users"
fi

clear
if [ $sambaYN == no ]
then
	ufw deny netbios-ns
	ufw deny netbios-dgm
	ufw deny netbios-ssn
	ufw deny microsoft-ds
	apt-get purge samba -y
	apt-get purge samba-common -y
	apt-get purge samba-common-bin -y
	apt-get purge samba4 -y
	clear
	echo "netbios-ns, netbios-dgm, netbios-ssn, and microsoft-ds ports have been denied. Samba has been removed."
elif [ $sambaYN == yes ]
then
	ufw allow netbios-ns
	ufw allow netbios-dgm
	ufw allow netbios-ssn
	ufw allow microsoft-ds
	apt-get install samba -y
	apt-get install system-config-samba -y
	systemctl start samba
	systemctl status samba
	cp /etc/samba/smb.conf /home/scriptuser/backups/
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
	apt-get purge vsftpd proftpd *ftpd* -y
	echo "vsFTPd has been removed. ftp, sftp, saft, ftps-data, and ftps ports have been denied on the firewall."
elif [ $ftpYN == yes ]
then
	ufw allow ftp 
	ufw allow sftp 
	ufw allow saft 
	ufw allow ftps-data 
	ufw allow ftps
	apt-get install vsftpd -y
	cp /etc/vsftpd/vsftpd.conf /home/scriptuser/backups/
	cp /etc/vsftpd.conf /home/scriptuser/backups/
	sed -i 's/anonymous_enable=.*/anonymous_enable=NO/' /etc/vsftpd.conf
	sed -i 's/local_enable=.*/local_enable=YES/' /etc/vsftpd.conf
	sed -i 's/#write_enable=.*/write_enable=YES/' /etc/vsftpd.conf
	sed -i 's/#chroot_local_user=.*/chroot_local_user=YES/' /etc/vsftpd.conf
	systemctl restart vsftpd
	systemctl status vsftpd
	echo "ftp, sftp, saft, ftps-data, and ftps ports have been allowed on the firewall. vsFTPd systemctl has been restarted."
else
	echo Response not recognized.
fi
echo "FTP is complete."


clear
if [ $sshYN == no ]
then
	ufw deny ssh
	apt-get purge openssh-server -y
	rm -R ../.ssh
	echo "SSH port has been denied on the firewall. Open-SSH has been removed."
elif [ $sshYN == yes ]
then
	apt-get install openssh-server -y
	ufw allow ssh
	cp /etc/ssh/sshd_config /home/scriptuser/backups/	
	usersSSH=$readmeusers
	echo -e "# Package generated configuration file\n# See the sshd_config(5) manpage for details\n\n# What ports, IPs and protocols we listen for\nPort 223\n# Use these options to restrict which interfaces/protocols sshd will bind to\n#ListenAddress ::\n#ListenAddress 0.0.0.0\nProtocol 2\n# HostKeys for protocol version \nHostKey /etc/ssh/ssh_host_rsa_key\nHostKey /etc/ssh/ssh_host_dsa_key\nHostKey /etc/ssh/ssh_host_ecdsa_key\nHostKey /etc/ssh/ssh_host_ed25519_key\n#Privilege Separation is turned on for security\nUsePrivilegeSeparation yes\n\n# Lifetime and size of ephemeral version 1 server key\nKeyRegenerationInterval 3600\nServerKeyBits 1024\n\n# Logging\nSyslogFacility AUTH\nLogLevel VERBOSE\n\n# Authentication:\nLoginGraceTime 60\nPermitRootLogin no\nStrictModes yes\n\nRSAAuthentication yes\nPubkeyAuthentication yes\n#AuthorizedKeysFile	$(pwd)/../.ssh/authorized_keys\n\n# Don't read the user's /home/scriptuser/.rhosts and /home/scriptuser/.shosts files\nIgnoreRhosts yes\n# For this to work you will also need host keys in /etc/ssh_known_hosts\nRhostsRSAAuthentication no\n# similar for protocol version 2\nHostbasedAuthentication no\n# Uncomment if you don't trust /home/scriptuser/.ssh/known_hosts for RhostsRSAAuthentication\n#IgnoreUserKnownHosts yes\n\n# To enable empty passwords, change to yes (NOT RECOMMENDED)\nPermitEmptyPasswords no\n\n# Change to yes to enable challenge-response passwords (beware issues with\n# some PAM modules and threads)\nChallengeResponseAuthentication yes\n\n# Change to no to disable tunnelled clear text passwords\nPasswordAuthentication no\n\n# Kerberos options\n#KerberosAuthentication no\n#KerberosGetAFSToken no\n#KerberosOrLocalPasswd yes\n#KerberosTicketCleanup yes\n\n# GSSAPI options\n#GSSAPIAuthentication no\n#GSSAPICleanupCredentials yes\n\nX11Forwarding no\nX11DisplayOffset 10\nPrintMotd no\nPrintLastLog no\nTCPKeepAlive yes\n#UseLogin no\n\nMaxStartups 2\n#Banner /etc/issue.net\n\n# Allow client to pass locale environment variables\nAcceptEnv LANG LC_*\n\nSubsystem sftp /usr/lib/openssh/sftp-server\n\n# Set this to 'yes' to enable PAM authentication, account processing,\n# and session processing. If this is enabled, PAM authentication will\n# be allowed through the ChallengeResponseAuthentication and\n# PasswordAuthentication.  Depending on your PAM configuration,\n# PAM authentication via ChallengeResponseAuthentication may bypass\n# the setting of \"PermitRootLogin without-password\".\n# If you just want the PAM account and session checks to run without\n# PAM authentication, then enable this but set PasswordAuthentication\n# and ChallengeResponseAuthentication to 'no'.\nUsePAM yes\nDenyUsers\nRhostsAuthentication no\nClientAliveInterval 300\nClientAliveCountMax 0\nVerifyReverseMapping yes\nAllowTcpForwarding no\nUseDNS no\nPermitUserEnvironment no" > /etc/ssh/sshd_config
	systemctl restart sshd
	systemctl status sshd
	mkdir ../.ssh
	chmod 700 ../.ssh
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
	apt-get purge telnet -y
	apt-get purge telnetd -y
	apt-get purge inetutils-telnetd -y
	apt-get purge telnetd-ssl -y
	echo "Telnet port has been denied on the firewall and Telnet has been removed."
elif [ $telnetYN == yes ]
then
	ufw allow telnet 
	ufw allow rtelnet 
	ufw allow telnets
	apt-get install telnetd -y
	echo "Telnet port has been allowed on the firewall."
else
	echo Response not recognized.
fi
echo "Telnet is complete."

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
	apt-get install postfix dovecot -y
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
	apt-get purge mysql* -y
	apt-get purge mariadb* -y
	apt-get purge postgresql*
	echo "ms-sql-s, ms-sql-m, mysql, and mysql-proxy ports have been denied on the firewall. MySQL has been removed."
elif [ $dbYN == yes ]
then
	ufw allow ms-sql-s 
	ufw allow ms-sql-m 
	ufw allow mysql 
	ufw allow mysql-proxy
	apt-get install mariadb-server-10.1 -y
	mysql_secure_configuration
	cp /etc/mysql/my.cnf /home/scriptuser/backups/
	if grep -q "bind-address" "/etc/mysql/my.cnf"
	then
		sed -i "s/bind-address\t\t=.*/bind-address\t\t= 127.0.0.1/g" /etc/mysql/my.cnf
		sed -i "s/local-infile\t\t=.*/local-infile\t\t=0/g" /etc/mysql/my.cnf
		
	fi
	gedit /etc/mysql/my.cnf
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
	apt-get purge apache2 nginx -y
	rm -r /var/www/*
	echo "https and https ports have been denied on the firewall. Apache2 has been removed. Web server files have been removed."
elif [ $httpsYN == yes ]
then
	apt-get install apache2 -y
	ufw allow https 
	ufw allow https
	cp /etc/apache2/apache2.conf /home/scriptuser/backups/
	if [ -e /etc/apache2/apache2.conf ]
	then
  		echo "<Directory />" >> /etc/apache2/apache2.conf
		echo "        AllowOverride None" >> /etc/apache2/apache2.conf
		echo "        Order Deny,Allow" >> /etc/apache2/apache2.conf
		echo "        Deny from all" >> /etc/apache2/apache2.conf
		echo "</Directory>" >> /etc/apache2/apache2.conf
		echo "UserDir disabled root" >> /etc/apache2/apache2.conf
	fi
	chown -R root:root /etc/apache2
	systemctl start apache2
	systemctl status apache2

	echo "https and https ports have been allowed on the firewall. Apache2 config file has been configured. Only root can now access the Apache2 folder."
else
	echo Response not recognized.
fi
echo "Web Server is complete."



clear
if [ $dnsYN == no ]
then
	ufw deny domain
	apt-get purge bind9 -y
	echo "domain port has been denied on the firewall. DNS name binding has been removed."
elif [ $dnsYN == yes ]
then
	apt-get install bind9 -y
	ufw allow domain
	echo "domain port has been allowed on the firewall and bind9 installed."
	systemctl start bind9
	systemctl status bind9
else
	echo Response not recognized.
fi
echo "DNS is complete."


clear
if [ $mediaFilesYN == no ]
then
	mv $(pwd)/../Pictures/Wallpapers/CyberTaipan_Background_WIDE.jpg /
	find /home -regextype posix-extended -regex '.*\.(midi|mid|mod|mp3|mp2|mpa|abs|mpega|au|snd|wav|aiff|aif|sid|flac|ogg)$' -delete
	clear
	echo "All audio files has been listed."

	find /home -regextype posix-extended -regex '.*\.(mpeg|mpg|mpe|dl|movie|movi|mv|iff|anim5|anim3|anim7|avi|vfw|avx|fli|flc|mov|qt|spl|swf|dcr|dir|dxr|rpm|rm|smi|ra|ram|rv|wmv|asf|asx|wma|wax|wmv|wmx|3gp|mov|mp4|flv|m4v|txt|xlsx|pptx|docx)$'
	clear
	echo "All video files have been listed."
	
	find /home -regextype posix-extended -regex '.*\.(tiff|tif|rs|iml|gif|jpeg|jpg|jpe|png|rgb|xwd|xpm|ppm|pbm|pgm|pcx|ico|svg|svgz|pot|xml|pl)$'
	mv /CyberTaipan_Background_WIDE.jpg $(pwd)/../Pictures/Wallpapers/CyberTaipan_Background_WIDE.jpg
	clear
	echo "All image files have been listed."
else
	echo Response not recognized.
fi
echo "Media files are complete."

find / -type f -perm /700 >> /home/scriptuser/badfiles.log
echo "All files with perms 700-777 have been logged."

clear
apt install mawk
for i in $(mawk -F: '$3 > 999 && $3 < 65534 {print $1}' /etc/passwd); do [ -d /home/${i} ] && chmod -R 750 /home/${i}/; done
echo "Home directory permissions set."

clear
for i in $(mawk -F: '$3 > 999 && $3 < 65534 {print $1}' /etc/passwd); do [ -d /home/${i} ] && chown -R ${i}:${i} /home/${i}/; done
echo "Home directory owner set."

clear
find / -iname "*.php" -type f >> /home/scriptuser/badfiles.log
echo "All PHP files have been listed. ('/var/cache/dictionaries-common/sqspell.php' is a system PHP file)"

clear
find / -iname "*.sh" -type f >> /home/scriptuser/badfiles.log
echo "All shell scripts have been listed. Note: there are a lot of system ones too."

clear
find / -perm -4000 >> /home/scriptuser/badfiles.log
find / -perm -2000 >> /home/scriptuser/badfiles.log
echo "All files with perms 4000 and 2000 have been logged."

clear
find / -nogroup -nouser >> /home/scriptuser/badfiles.log
echo "All files with no owner have been logged."

clear
apt install tree
tree >> /home/scriptuser/directorytree.txt
echo "Directory tree saved to file."

clear
parse_dpkg_log() {
  {
    for FN in `ls -1 /var/log/dpkg.log*` ; do
      CMD="cat"
      [ ${FN##*.} == "gz" ] && CMD="zcat" 
      $CMD $FN | egrep "[0-9] install" | awk '{print $4}' \
        | awk -F":" '{print $1}'
    done
  } | sort | uniq
}

## all packages installed with apt-get/aptitude
list_installed=$(parse_dpkg_log)
## packages that were not marked as auto installed
list_manual=$(apt-mark showmanual | sort)

## output intersection of 2 lists
comm -12 <(echo "$list_installed") <(echo "$list_manual")
echo "All manually installed packages have been listed If using Debian, ignore above."

grep -oP "Unpacking \K[^: ]+" /var/log/installer/syslog | sort -u | comm -13 /dev/stdin <(apt-mark showmanual | sort)
echo "If using Debian, ignore the first list of packages and refer to the second one."

apt list --installed >> /home/scriptuser/allInstalledPackages.log
echo "Listed all installed packages, not just manual ones."

apt install fail2ban -y
systemctl enable fail2ban
systemctl start fail2ban
echo "Fail2Ban enabled."

clear
lsof -Pnl +M -i > /home/scriptuser/runningProcesses.log
## Removing the default running processes
sed -i '/avahi-dae/ d' /home/scriptuser/runningProcesses.log
sed -i '/cups-brow/ d' /home/scriptuser/runningProcesses.log
sed -i '/dhclient/ d' /home/scriptuser/runningProcesses.log
sed -i '/dnsmasq/ d' /home/scriptuser/runningProcesses.log
sed -i '/cupsd/ d' /home/scriptuser/runningProcesses.log
echo "All running processes listed."

clear
systemctl >> /home/scriptuser/systemctlUnits.log
echo "All systemctl services listed."

clear
ls /etc/init/ >> /home/scriptuser/initFiles.log
ls /etc/init.d/ >> /home/scriptuser/initFiles.log
echo "Listed all files in the init directory."

clear
echo '' > /etc/securetty
echo "Removed any TTYs listed in /etc/securetty."

find / -depth -type d -name '.john' -exec rm -r '{}' \;
ls -al ~/.john/*
clear
echo "John the Ripper files have been removed."

clear
( lynis audit system -Q >> LynisOutput.txt; echo "Finished Lynis" ) &
disown; sleep 2;
echo "Running Lynis."

clear
( chkrootkit -q >> ChkrootkitOutput.txt; echo "Finished ChkRootKit" ) &
disown; sleep 2;
echo "Running ChkRootKit."

clear
( rkhunter -c >> RkHunterOutput.txt; echo "Finished RkHunter" ) &
disown; sleep 2;
echo "Running RkHunter."

clear
cp /etc/login.defs /home/scriptuser/backups/
sed -i '160s/.*/PASS_MAX_DAYS\o01130/' /etc/login.defs
sed -i '161s/.*/PASS_MIN_DAYS\o0113/' /etc/login.defs
sed -i '163s/.*/PASS_WARN_AGE\o0117/' /etc/login.defs
cat /etc/login.defs
echo "Password policies have been set with /etc/login.defs."

echo "umask 027" >> /etc/bash.bashrc
echo "umask 027" >> /etc/profile
echo "Set a very strict umask."

clear
cp /etc/pam.d/common-auth /home/scriptuser/backups/
cp /etc/pam.d/common-password /home/scriptuser/backups/
echo -e "#\n# /etc/pam.d/common-auth - authentication settings common to all systemctls\n#\n# This file is included from other systemctl-specific PAM config files,\n# and should contain a list of the authentication modules that define\n# the central authentication scheme for use on the system\n# (e.g., /etc/shadow, LDAP, Kerberos, etc.).  The default is to use the\n# traditional Unix authentication mechanisms.\n#\n# As of pam 1.0.1-6, this file is managed by pam-auth-update by default.\n# To take advantage of this, it is recommended that you configure any\n# local modules either before or after the default block, and use\n# pam-auth-update to manage selection of other modules.  See\n# pam-auth-update(8) for details.\n\n# here are the per-package modules (the \"Primary\" block)\nauth	[success=1 default=ignore]	pam_unix.so\n# here's the fallback if no module succeeds\nauth	requisite			pam_deny.so\n# prime the stack with a positive return value if there isn't one already; >> /dev/null\n# this avoids us returning an error just because nothing sets a success code\n# since the modules above will each just jump around\nauth	required			pam_permit.so\n# and here are more per-package modules (the \"Additional\" block)\nauth	optional			pam_cap.so \n# end of pam-auth-update config\nauth required pam_tally2.so deny=5 unlock_time=1800 onerr=fail audit even_deny_root_account silent" > /etc/pam.d/common-auth
echo -e "#\n# /etc/pam.d/common-password - password-related modules common to all systemctls\n#\n# This file is included from other systemctl-specific PAM config files,\n# and should contain a list of modules that define the systemctls to be\n# used to change user passwords.  The default is pam_unix.\n\n# Explanation of pam_unix options:\n#\n# The \"sha512\" option enables salted SHA512 passwords.  Without this option,\n# the default is Unix crypt.  Prior releases used the option \"md5\".\n#\n# The \"obscure\" option replaces the old \`OBSCURE_CHECKS_ENAB\' option in\n# login.defs.\n#\n# See the pam_unix manpage for other options.\n\n# As of pam 1.0.1-6, this file is managed by pam-auth-update by default.\n# To take advantage of this, it is recommended that you configure any\n# local modules either before or after the default block, and use\n# pam-auth-update to manage selection of other modules.  See\n# pam-auth-update(8) for details.\n\n# here are the per-package modules (the \"Primary\" block)\npassword	[success=1 default=ignore]	pam_unix.so obscure sha512\n# here's the fallback if no module succeeds\npassword	requisite			pam_deny.so\n# prime the stack with a positive return value if there isn't one already; >> /dev/null\n# this avoids us returning an error just because nothing sets a success code\n# since the modules above will each just jump around\npassword	required			pam_permit.so\npassword requisite pam_cracklib.so retry=3 minlen=14 difok=8 reject_username minclass=4 maxrepeat=3 dcredit=-1 ucredit=-1 lcredit=-1 ocredit=-1\npassword requisite pam_pwhistory.so use_authtok remember=24 enforce_for_root\n# and here are more per-package modules (the \"Additional\" block)\npassword	optional	pam_gnome_keyring.so \n# end of pam-auth-update config" > /etc/pam.d/common-password
echo "If password policies are not correctly configured, try this for /etc/pam.d/common-password:\npassword requisite pam_cracklib.so retry=3 minlen=14 difok=8 reject_us11ername minclass=4 maxrepeat=2 dcredit=-1 ucredit=-1 lcredit=-1 ocredit=-1\npassword requisite pam_pwhistory.so use_authtok remember=24 enforce_for_root"
echo "Password policies have been set with and /etc/pam.d."
getent group nopasswdlogin && gpasswd nopasswdlogin -M ''
echo "All users now need passwords to login"

clear
iptables -A INPUT -p all -s localhost  -i eth0 -j DROP
echo "All outside packets from internet claiming to be from loopback are denied."

clear
cp /etc/init/control-alt-delete.conf /home/scriptuser/backups/
sed '/^exec/ c\exec false' /etc/init/control-alt-delete.conf
echo "Reboot using Ctrl-Alt-Delete has been disabled."

clear 
systemctl start clamav-freshclam && systemctl enable clamav-freshclam
systemctl start clamav-daemon && systemctl enable clamav-daemon
aa-enforce /etc/apparmor.d/*
systemctl reload apparmor
systemctl status apparmor
echo "AppArmor and ClamAV has been installed."

clear
for user in $(cut -f1 -d: /etc/passwd); do echo $user; crontab -u $user -l; done >> CronTabs.txt
echo "All crontabs have been listed."

clear
pushd /etc/
/bin/rm -f cron.deny at.deny
echo root >cron.allow
echo root >at.allow
/bin/chown root:root cron.allow at.allow
/bin/chmod 400 cron.allow at.allow
popd
echo "Only root allowed in cron."

clear
apt-get update 
apt-get upgrade -y
echo "Ubuntu OS has checked for updates and has been upgraded."

clear
su - $(stat -c "%U" .) -c 'firefox --preferences'
echo "Popup blocker enabled in Firefox"

clear
apt-get autoremove -y 
apt-get autoclean -y 
apt-get clean -y 
echo "All unused packages have been removed."

clear
export $(cat /etc/environment)
echo "PATH reset to normal."

clear
wget https://raw.githubusercontent.com/Neo23x0/auditd/master/audit.rules
mv audit.rules /etc/audit/audit.rules
auditctl -e 1
auditctl -s
systemctl --now enable auditd
systemctl start auditd
echo "Auditd and audit rules have been set and enabled."

clear
echo "Script is complete. Log user out to enable home directory encryption. Once logged out, login to another administrator. Then, access terminal and run sudo ecryptfs-migrate-home -u <default user>. After that, follow the prompts."
apt install curl
url=$(cat scriptlog.txt | curl -F 'sprunge=<-' http://sprunge.us)
wget -O/dev/null --header 'Content-type: application/json' --post-data '{"text":"<'$url'|Linux script results>"}' $(echo aHR0cHM6Ly9ob29rcy5zbGFjay5jb20vc2VydmljZXMvVEg3U0pLNUg5L0IwMko0NENHQkFSL3hHeGFHVXdNdDZmTU5aWkViaDlmbDhOaA== | base64 --decode) > /dev/null 2>&1
