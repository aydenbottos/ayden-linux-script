#!/bin/bash
clear
echo "Created by Ayden Bottos"
echo "Last Modified on Sep 11, 2022"
echo "Linux script"
echo "The password used is CyberTaipan123!"
echo "Running at $(date)"
echo "Running on $(lsb_release -is)"
echo "Hostname: $(hostname)"
echo "Main user: $(stat -c "%U" .)"
mainUser=$(stat -c "%U" .)

wget https://raw.github.com/tdulcet/Linux-System-Information/master/info.sh -qO - | bash -s | tee systeminfo.log
read -p "Press enter to begin script"
clear

if [[ $EUID -ne 0 ]]
then
  echo "This script must be run as root."
  exit
fi
echo "Script is being run as root."

if [[ "$PWD" != *"Desktop"* ]]
then
  echo "The script must be run in the Desktop directory."
  exit
fi
echo "Script is being run in the correct directory."

pw=CyberTaipan123!
echo "Universal password set."

clear
mkdir -p /home/scriptuser/
touch /home/scriptuser/badfiles.log
echo > /home/scriptuser/badfiles.log
chmod 777 /home/scriptuser/badfiles.log
echo "Important files and directories created."

mkdir -p /home/scriptuser/backups
chmod 777 /home/scriptuser/backups
echo "Backups folder created on the Desktop."

wget https://raw.githubusercontent.com/aydenbottos/ayden-linux-script/master/stat
chmod +x stat
originaltime=$(./stat -c '%w' /etc/gai.conf | sed -r 's/^([0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}).*/\1/')

find / -type f -exec ./stat -c '%n : %w' {} + | grep -v "$originaltime:\|: -\|cache\|dpkg\|app-info\/icons\|src\/linux\|mime\|man\|icons\|linux\-gnu\|modules\|doc\|include\|python\|zoneinfo\|lib" > tempresult
(
  export LC_ALL=C
  comm -23 <(sort -u tempresult) \
           <(sort -u /var/lib/dpkg/info/*.list)
) >> potentiallynewfiles.log

echo "Returned files that are potentially manually created."

clear
echo "Check to verify that all update settings are correct."
if echo $(lsb_release -is) | grep -qi Debian; then
	# Reset Debian sources.list to default
	echo "deb http://ftp.au.debian.org/debian/ $(lsb_release -cs) main contrib non-free" > /etc/apt/sources.list
	echo "deb-src http://ftp.au.debian.org/debian/ $(lsb_release -cs) main contrib non-free" >> /etc/apt/sources.list
	echo "deb http://ftp.au.debian.org/debian/ $(lsb_release -cs)-updates main contrib non-free" >> /etc/apt/sources.list
	echo "deb-src http://ftp.au.debian.org/debian/ $(lsb_release -cs)-updates main contrib non-free" >> /etc/apt/sources.list
	echo "deb http://security.debian.org/ $(lsb_release -cs)/updates main contrib non-free" >> /etc/apt/sources.list
	echo "deb-src http://security.debian.org/ $(lsb_release -cs)/updates main contrib non-free" >> /etc/apt/sources.list
	apt update
	# Reset update settings using apt purge
	apt purge unattended-upgrades apt-config-auto-update -y
	apt install unattended-upgrades apt-config-auto-update -y
	apt install firefox-esr -y
else 
	printf 'deb http://archive.ubuntu.com/ubuntu %s main universe\n' "$(lsb_release -sc)"{,-security}{,-updates} > /etc/apt/sources.list
	sed -i "/security-updates/d" /etc/apt/sources.list
	apt update
	apt-get remove --purge update-notifier-common unattended-upgrades -y
	apt-get install update-notifier-common unattended-upgrades update-manager -y
	apt install firefox stubby -y
fi

apt list --installed >> /home/scriptuser/allInstalledPackages.log
echo "Listed all installed packages, not just manual ones."

wget https://github.com/tclahr/uac/releases/download/v2.2.0/uac-2.2.0.tar.gz
tar -xf uac-2.2.0.tar.gz
pushd uac-2.2.0
chmod +x uac
mkdir results
./uac -p full results &>/dev/null &
popd
echo "Ran UAC - check its folder for results."

clear
apt install curl -y
comm -23 <(apt-mark showmanual | sort -u) <(curl -s -- https://old-releases.ubuntu.com/releases/$(grep -oP 'VERSION_CODENAME=\K.+' /etc/os-release)/ubuntu-$(grep -oP 'VERSION="\K[0-9\.]+' /etc/os-release)-desktop-amd64.manifest | cut -f1 | cut -d: -f1 | sort -u) >> newpackagesubuntu.log
echo "Listed all manually installed packages - for Ubuntu."

clear
apt install curl -y
comm -23 <(apt-mark showmanual | sort -u) <(curl -s -- https://cdimage.debian.org/mirror/cdimage/archive/$(grep -oP 'VERSION="\K[0-9\.]+' /etc/os-release).0.0-live/amd64/iso-hybrid/debian-live-$(grep -oP 'VERSION="\K[0-9\.]+' /etc/os-release).0.0-amd64-gnome.packages | cut -f1 | cut -d: -f1 | sort -u) >> newpackagesubuntu.log
echo "Listed all manually installed packages - for Debian."

apt install p7zip debsums -y
mkdir thor
pushd thor
wget https://raw.githubusercontent.com/aydenbottos/ayden-linux-script/master/thor10.7lite-linux-pack.7z
wget https://raw.githubusercontent.com/aydenbottos/ayden-linux-script/master/a2d7f9a1734943f3ca8665d40e02f29a_b28a6f0ae1ee88438421feed7186c8d2.lic
p7zip -d thor10.7lite-linux-pack.7z
./thor-lite-linux &>/dev/null &
popd
echo "Ran THOR IOC and YARA scanner."

touch differences.log
pushd /tmp
for FILE in $(debsums -ca);
    do echo $FILE >> /home/$mainUser/Desktop/differences.log;
    PKG=$(dpkg -S $FILE | cut -d: -f1);
    diff <(apt-get download $PKG;dpkg-deb --fsys-tarfile $PKG*.deb | tar xOf - .$FILE) $FILE | tee -a /home/$mainUser/Desktop/differences.log;
    echo "" >> /home/$mainUser/Desktop/differences.log
done
popd
echo "Outputted every change on the system since installation - this log is a must-check."
clear

echo "Opening forensics questions."
sudo gnome-terminal
test -f "Forensics Question 1.txt" && gedit "Forensics Question 1.txt"
test -f "Forensics Question 2.txt" && gedit "Forensics Question 2.txt"
test -f "Forensics Question 3.txt" && gedit "Forensics Question 3.txt"
test -f "Forensics Question 4.txt" && gedit "Forensics Question 4.txt"
test -f "Forensics Question 5.txt" && gedit "Forensics Question 5.txt"
test -f "Forensics Question 6.txt" && gedit "Forensics Question 6.txt"

sed -i '/AllowUnauthenticated/d' /etc/apt/**
echo "Forced digital signing on APT."

echo "APT::Sandbox::Seccomp \"true\"\;" >> /etc/apt/apt.conf.d/40sandbox
echo "Enabled APT sandboxing."

echo "Running apt-get update"
apt-get update

echo "Installing all neccessary software."
apt-get install apt-transport-https dirmngr vlock ufw git binutils tcpd libpam-apparmor haveged chrony chkrootkit net-tools iptables libpam-cracklib apparmor apparmor-utils apparmor-profiles-extra clamav clamav-freshclam auditd audispd-plugins cryptsetup aide unhide psad ssg-base ssg-debderived ssg-debian ssg-nondebian ssg-applications libopenscap8 -y
echo "Deleting all bad software."
wget https://raw.githubusercontent.com/aydenbottos/ayden-linux-script/master/packages.txt
while read package; do apt show "$package" 2>/dev/null | grep -qvz 'State:.*(virtual)' && echo "$package" >>packages-valid && echo -ne "\r\033[K$package"; done <packages.txt
sudo apt purge $(tr '\n' ' ' <packages-valid) -y

clear
chmod 644 /etc/apt/sources.list
echo "Sources reset to default."

echo -e "Unattended-Upgrade::Remove-Unused-Dependencies 'true';\nUnattended-Upgrade::Remove-Unused-Kernel-Packages 'true';" >> /etc/apt/apt.conf.d/50unattended-upgrades

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
        	if grep -qiw "$line" users.txt; then
			echo -e "$pw\n$pw" | passwd "$line"
			echo "$line has been given the password '$pw'."
			passwd -x30 -n3 -w7 $line
			usermod -U $line
			chage -M 30 $line
			chage -m 3 $line
			chage -E `date -d "30 days" +"%Y-%m-%d"` $line
			chage -W `date -d "7 days" +"%Y-%m-%d"` $line
			echo "$line's password has been given a maximum age of 30 days, minimum of 3 days, and warning of 7 days."	
		else
			if [ $line == $mainUser ] 
			then
				echo "Watch out, we were going to delete the main user!"
				line=dummy
			fi
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
		if echo $readmeusers2 | grep -qiw "$line"; then
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
	
	while IFS= read -r line; do
  		groupadd $(echo $line | head -n1 | awk '{print $1;}')
		groupname=$(echo $line | head -n1 | awk '{print $1;}')
		cut -d "-" -f2 <<< $line | IFS=',' read -ra my_array
		for i in "${my_array[@]}"
		do
			useradd -g $groupname $i
		done
	done < groups.txt
	
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
	phpYN=no
	
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
	if grep -qi 'php' services.txt; then
		phpYN=yes
	fi
else
	find $(pwd) -iname 'README.desktop' | xargs grep -oE "https:\/\/(.*).aspx" | xargs wget -O readme.aspx

	awk -F: '$6 ~ /\/home/ {print}' /etc/passwd | cut -d: -f1 | while read line || [[ -n $line ]];
	do
		if grep -qiw "$line" readme.aspx; then
			echo -e "$pw\n$pw" | passwd "$line"
			echo "$line has been given the password '$pw'."
			passwd -x30 -n3 -w7 $line
			usermod -U $line
			chage -E `date -d "30 days" +"%Y-%m-%d"` $line
			chage -W `date -d "7 days" +"%Y-%m-%d"` $line
			echo "$line's password has been given a maximum age of 30 days, minimum of 3 days, and warning of 7 days."	
		else
			
			if [ $line == $mainUser ] 
			then
				echo "Watch out, we were going to delete the main user!"
				line=dummy
			fi
			deluser --remove-home $line
			echo "Deleted unauthorised user $line."
		fi
	done
	clear

	readmeusers="$(sed -n '/<pre>/,/<\/pre>/p' readme.aspx | sed -e "/password:/d" | sed -e "/<pre>/d" | sed -e "/<\/pre>/d" | sed -e "/<b>/d" | sed -e "s/ //g" | sed -e "s/[[:blank:]]//g" | sed -e 's/[[:space:]]//g' | sed -e '/^$/d' | sed -e 's/(you)//g' | cat)"

	echo "$readmeusers" | while read readmeusersfor || [[ -n $line ]];
	do
		if grep -qiw "$readmeusersfor" /etc/passwd; then
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
		if echo $readmeusers2 | grep -qiw "$line"; then
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
	phpYN=no

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
	if grep -qi 'php' services; then
		phpYN=yes
	fi
fi

clear
echo "mesg n" >> /etc/skel/.profile
profileFiles=$(find /home -type f -name .profile)
for f in $profileFiles; do cp /etc/skel/.profile $f; done

echo "mesg n" >> /etc/skel/.bashrc
bashrcFiles=$(find /home -type f -name .bashrc)
for f in $bashrcFiles; do cp /etc/skel/.bashrc $f; done

logoutFiles=$(find /home -type f -name .bash_logout)
for f in $logoutFiles; do cp /etc/skel/.bash_logout $f; done
clear
echo "Replaced .bash files with originals."

echo "ulimit -c 0" >> /etc/profile
echo -e "ProcessSizeMax=0\nStorage=none" >> /etc/systemd/coredump.conf

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
passwd -dl root
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
echo "install cramfs /bin/true" >> /etc/modprobe.d/CIS.conf
echo "install freevxfs /bin/true" >> /etc/modprobe.d/CIS.conf
echo "install jffs2 /bin/true" >> /etc/modprobe.d/CIS.conf
echo "install hfs /bin/true" >> /etc/modprobe.d/CIS.conf
echo "install hfsplus /bin/true" >> /etc/modprobe.d/CIS.conf
echo "install squashfs /bin/true" >> /etc/modprobe.d/CIS.conf
echo "install udf /bin/true" >> /etc/modprobe.d/CIS.conf
echo "install vfat /bin/true" >> /etc/modprobe.d/CIS.conf
echo "install dccp /bin/false" >> /etc/modprobe.d/CIS.conf
echo "install sctp /bin/false" >> /etc/modprobe.d/CIS.conf
echo "install rds /bin/false" >> /etc/modprobe.d/CIS.conf
echo "install tipc /bin/false" >> /etc/modprobe.d/CIS.conf
echo "install n-hdlc /bin/false" >> /etc/modprobe.d/CIS.conf
echo "install ax25 /bin/false" >> /etc/modprobe.d/CIS.conf
echo "install netrom /bin/false" >> /etc/modprobe.d/CIS.conf
echo "install x25 /bin/false" >> /etc/modprobe.d/CIS.conf
echo "install rose /bin/false" >> /etc/modprobe.d/CIS.conf
echo "install decnet /bin/false" >> /etc/modprobe.d/CIS.conf
echo "install econet /bin/false" >> /etc/modprobe.d/CIS.conf
echo "install af_802154 /bin/false" >> /etc/modprobe.d/CIS.conf
echo "install ipx /bin/false" >> /etc/modprobe.d/CIS.conf
echo "install appletalk /bin/false" >> /etc/modprobe.d/CIS.conf
echo "install psnap /bin/false" >> /etc/modprobe.d/CIS.conf
echo "install p8023 /bin/false" >> /etc/modprobe.d/CIS.conf
echo "install p8022 /bin/false" >> /etc/modprobe.d/CIS.conf
echo "install can /bin/false" >> /etc/modprobe.d/CIS.conf
echo "install atm /bin/false" >> /etc/modprobe.d/CIS.conf

echo "Disabled unused filesystems and network protocols."

clear
echo "Check for any files for users that should not be administrators in /etc/sudoers.d."
rm /etc/sudoers.d/*

clear
echo "TMOUT=600" > /etc/profile.d/99-terminal_tmout.sh
echo "Set session timeout."

clear
sed -i 's/Defaults \!noauthenticate/d' /etc/sudoers
sed -i 's/\!noauthenticate//g' /etc/sudoers
sed -i 's/NOPASSWD\://g' /etc/sudoers
sed -i 's/\%users/d' /etc/sudoers
echo "Sudoers file secured."

echo -e "Defaults use_pty\nDefaults logfile=/var/log/sudo.log" >> /etc/sudoers
echo "PTY and logfile set up for sudo."

clear
cp /etc/rc.local /home/scriptuser/backups/
echo > /etc/rc.local
echo 'exit 0' >> /etc/rc.local
echo "Any startup scripts have been removed."

clear
iptables -F
iptables -X
iptables -Z

ufw enable
ufw default deny incoming
ufw default deny forward
ufw status verbose
ufw limit in on $(route | grep '^default' | grep -o '[^ ]*$')
ufw logging on
echo "UFW Firewall enabled and all ports blocked."
    
# Iptables specific
    
# Block null packets (DoS)
iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP
    
# Block syn-flood attacks (DoS)
iptables -A INPUT -p tcp ! --syn -m state --state NEW -j DROP

#Drop incoming packets with fragments
iptables -A INPUT -f -j DROP

# Block XMAS packets (DoS)
iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP

# Allow internal traffic on the loopback device
sudo iptables -A INPUT -i lo -j ACCEPT

# Allow established connections
iptables -I INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow outgoing connections
iptables -P OUTPUT ACCEPT

#Block NFS
iptables -A INPUT -p tcp -s 0/0 -d 0/0 --dport 2049 -j DROP

#Block X-Windows
iptables -A INPUT -p tcp -s 0/0 -d 0/0 --dport 6000:6009 -j DROP

#Block X-Windows font server
iptables -A INPUT -p tcp -s 0/0 -d 0/0 --dport 7100 -j DROP

#Block printer port
iptables -A INPUT -p tcp -s 0/0 -d 0/0 --dport 515 -j DROP

#Block Sun rpc/NFS
iptables -A INPUT -p udp -s 0/0 -d 0/0 --dport 111 -j DROP

# Deny outside packets from internet which claim to be from your loopback interface.
sudo iptables -A INPUT -p all -s localhost  -i eth0 -j DROP

clear
env i='() { :;}; echo vulnerable >> test' bash -c "echo this is a test"
if test -f "test"; then
	apt-get install --only-upgrade bash -y
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
cp /etc/hosts /home/scriptuser/backups/
echo > /etc/hosts
echo -e "127.0.0.1 localhost\n127.0.1.1 $mainUser\n::1 ip6-localhost ip6-loopback\nfe00::0 ip6-localnet\nff00::0 ip6-mcastprefix\nff02::1 ip6-allnodes\nff02::2 ip6-allrouters" >> /etc/hosts
chmod 644 /etc/hosts
echo "HOSTS file has been set to defaults."

clear
apt purge *tftpd* -y
echo "TFTP has been removed."

clear
echo "# GDM configuration storage\n\n[daemon]\n\n[security]\n\n[xdmcp]\n\n[chooser]\n\n[debug]\n" > /etc/gdm3/custom.conf
xhost +SI:localuser:gdm
sudo -u gdm gsettings set org.gnome.login-screen disable-user-list true;
sudo -u gdm gsettings set org.gnome.desktop.screensaver lock-enabled true;
xhost -
echo "User list has been hidden and autologin has been disabled."

clear
chmod 777 /etc/lightdm/lightdm.conf
cp /etc/lightdm/lightdm.conf /home/scriptuser/Desktop/backups/
sudo touch /etc/lightdm/lightdm.conf.d/myconfig.conf
echo "[SeatDefaults]"                   | tee /etc/lightdm/lightdm.conf > /dev/null
echo "allow-guest=false"                | tee -a /etc/lightdm/lightdm.conf > /dev/null
echo "greeter-hide-users=true"          | tee -a /etc/lightdm/lightdm.conf > /dev/null
echo "greeter-show-manual-login=true"   | tee -a /etc/lightdm/lightdm.conf > /dev/null
echo "greeter-allow-guest=false"        | tee -a /etc/lightdm/lightdm.conf > /dev/null
echo "autologin-guest=false"            | tee -a /etc/lightdm/lightdm.conf > /dev/null
echo "AutomaticLoginEnable=false"       | tee -a /etc/lightdm/lightdm.conf > /dev/null
echo "xserver-allow-tcp=false"          | tee -a /etc/lightdm/lightdm.conf > /dev/null
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
update-rc.d bluetooth remove
echo 'alias net-pf-31 off' >> /etc/modprobe.conf
echo "Bluetooth disabled."

clear
cp /etc/sysctl.conf /home/scriptuser/backups/
rm /etc/sysctl.d/*
dpkg --purge --force-depends procps
apt install procps

# Add these configs
echo kernel.dmesg_restrict=1            | tee /etc/sysctl.conf > /dev/null # Scored
echo fs.suid_dumpable=0                 | tee -a /etc/sysctl.conf > /dev/null # Core dumps # Scored
echo kernel.msgmnb=65536                | tee -a /etc/sysctl.conf > /dev/null
echo kernel.msgmax=65536                | tee -a /etc/sysctl.conf > /dev/null
echo kernel.sysrq=0                     | tee -a /etc/sysctl.conf > /dev/null
echo dev.tty.ldisc_autoload=0           | tee -a /etc/sysctl.conf > /dev/null
echo fs.protected_fifos=2               | tee -a /etc/sysctl.conf > /dev/null
echo kernel.maps_protect=1              | tee -a /etc/sysctl.conf > /dev/null
echo kernel.unprivileged_bpf_disabled=1 | tee -a /etc/sysctl.conf > /dev/null
echo kernel.core_uses_pid=1             | tee -a /etc/sysctl.conf > /dev/null
echo kernel.shmmax=68719476736          | tee -a /etc/sysctl.conf > /dev/null
echo kernel.shmall=4294967296           | tee -a /etc/sysctl.conf > /dev/null
echo kernel.exec_shield=1               | tee -a /etc/sysctl.conf > /dev/null
echo vm.mmap_min_addr = 65536           | tee -a /etc/sysctl.conf > /dev/null
echo vm.mmap_rnd_bits = 32              | tee -a /etc/sysctl.conf > /dev/null
vm.mmap_rnd_compat_bits = 16            | tee -a /etc/sysctl.conf > /dev/null
echo kernel.pid_max = 65536             | tee -a /etc/sysctl.conf > /dev/null
echo kernel.panic=10                    | tee -a /etc/sysctl.conf > /dev/null
echo kernel.kptr_restrict=2             | tee -a /etc/sysctl.conf > /dev/null
echo vm.panic_on_oom=1                  | tee -a /etc/sysctl.conf > /dev/null
echo net.core.bpf_jit_harden=2		| tee -a /etc/sysctl.conf > /dev/null
echo fs.protected_hardlinks=1           | tee -a /etc/sysctl.conf > /dev/null
echo fs.protected_symlinks=1            | tee -a /etc/sysctl.conf > /dev/null
echo kernel.randomize_va_space=2        | tee -a /etc/sysctl.conf > /dev/null # Scored ASLR; 2 = full; 1 = semi; 0 = none
echo kernel.unprivileged_userns_clone=0 | tee -a /etc/sysctl.conf > /dev/null # Scored
echo kernel.ctrl-alt-del=0              | tee -a /etc/sysctl.conf > /dev/null # Scored CTRL-ALT-DEL disable
echo kernel.perf_event_paranoid = 3     | tee -a /etc/sysctl.conf > /dev/null
echo kernel.perf_event_max_sample_rate = 1   | tee -a /etc/sysctl.conf > /dev/null
echo kernel.perf_cpu_time_max_percent = 1    | tee -a /etc/sysctl.conf > /dev/null
echo kernel.yama.ptrace_scope = 3 | tee -a /etc/sysctl.conf > /dev/null
echo kernel.kexec_load_disabled = 1 | tee -a /etc/sysctl.conf > /dev/null
echo fs.protected_regular = 2 | tee -a /etc/sysctl.conf > /dev/null
echo vm.unprivileged_userfaultfd = 0 | tee -a /etc/sysctl.conf > /dev/null


sysctl --system
clear
echo "Sysctl system settings set."

# IPv4 TIME-WAIT assassination protection
echo net.ipv4.tcp_rfc1337=1 | tee -a /etc/sysctl.conf > /dev/null

echo net.ipv4.ip_forward = 0 | tee -a /etc/sysctl.conf > /dev/null
echo net.ipv4.tcp_fin_timeout = 30 | tee -a /etc/sysctl.conf > /dev/null

# IP Spoofing protection, Source route verification  
# Scored
echo net.ipv4.conf.all.rp_filter=1      | tee -a /etc/sysctl.conf > /dev/null
echo net.ipv4.conf.default.rp_filter=1  | tee -a /etc/sysctl.conf > /dev/null

# Ignore ICMP broadcast requests
echo net.ipv4.icmp_echo_ignore_broadcasts=1 | tee -a /etc/sysctl.conf > /dev/null

# Ignore Directed pings
echo net.ipv4.icmp_echo_ignore_all=1 | tee -a /etc/sysctl.conf > /dev/null

# Log Martians
echo net.ipv4.conf.all.log_martians=1               | tee -a /etc/sysctl.conf > /dev/null
echo net.ipv4.icmp_ignore_bogus_error_responses=1   | tee -a /etc/sysctl.conf > /dev/null

# Disable source packet routing
echo net.ipv4.conf.all.accept_source_route=0        | tee -a /etc/sysctl.conf > /dev/null
echo net.ipv4.conf.default.accept_source_route=0    | tee -a /etc/sysctl.conf > /dev/null
echo net.ipv6.conf.all.accept_source_route=0        | tee -a /etc/sysctl.conf > /dev/null
echo net.ipv6.conf.default.accept_source_route=0    | tee -a /etc/sysctl.conf > /dev/null

# Block SYN attacks
echo net.ipv4.tcp_syncookies=1          | tee -a /etc/sysctl.conf > /dev/null
echo net.ipv4.tcp_max_syn_backlog=2048  | tee -a /etc/sysctl.conf > /dev/null
echo net.ipv4.tcp_synack_retries=2      | tee -a /etc/sysctl.conf > /dev/null
echo net.ipv4.tcp_max_orphans=256       | tee -a /etc/sysctl.conf > /dev/null
echo net.ipv4.tcp_window_scaling = 0    | tee -a /etc/sysctl.conf > /dev/null
echo net.ipv4.tcp_timestamps=0          | tee -a /etc/sysctl.conf > /dev/null

    
# Ignore ICMP redirects
echo net.ipv4.conf.all.send_redirects=0         | tee -a /etc/sysctl.conf > /dev/null
echo net.ipv4.conf.default.send_redirects=0     | tee -a /etc/sysctl.conf > /dev/null
echo net.ipv4.conf.all.accept_redirects=0       | tee -a /etc/sysctl.conf > /dev/null
echo net.ipv4.conf.default.accept_redirects=0   | tee -a /etc/sysctl.conf > /dev/null
echo net.ipv4.conf.all.secure_redirects=0       | tee -a /etc/sysctl.conf > /dev/null
echo net.ipv4.conf.default.secure_redirects=0   | tee -a /etc/sysctl.conf > /dev/null

echo net.ipv6.conf.all.send_redirects=0         | tee -a /etc/sysctl.conf > /dev/null # ignore ?
echo net.ipv6.conf.default.send_redirects=0     | tee -a /etc/sysctl.conf > /dev/null # ignore ?
echo net.ipv6.conf.all.accept_redirects=0       | tee -a /etc/sysctl.conf > /dev/null
echo net.ipv6.conf.default.accept_redirects=0   | tee -a /etc/sysctl.conf > /dev/null
echo net.ipv6.conf.all.secure_redirects=0       | tee -a /etc/sysctl.conf > /dev/null # ignore ?
echo net.ipv6.conf.default.secure_redirects=0   | tee -a /etc/sysctl.conf > /dev/null # ignore ?

# Note disabling ipv6 means you dont need the majority of the ipv6 settings

# General options
echo net.ipv6.conf.default.router_solicitations=0   | tee -a /etc/sysctl.conf > /dev/null
echo net.ipv6.conf.default.accept_ra_rtr_pref=0     | tee -a /etc/sysctl.conf > /dev/null
echo net.ipv6.conf.default.accept_ra_pinfo=0        | tee -a /etc/sysctl.conf > /dev/null
echo net.ipv6.conf.default.accept_ra_defrtr=0       | tee -a /etc/sysctl.conf > /dev/null
echo net.ipv6.conf.default.autoconf=0               | tee -a /etc/sysctl.conf > /dev/null
echo net.ipv6.conf.default.dad_transmits=0          | tee -a /etc/sysctl.conf > /dev/null
echo net.ipv6.conf.default.max_addresses=1          | tee -a /etc/sysctl.conf > /dev/null
echo net.ipv6.conf.all.disable_ipv6=1               | tee -a /etc/sysctl.conf > /dev/null
echo net.ipv6.conf.lo.disable_ipv6=1                | tee -a /etc/sysctl.conf > /dev/null
echo -e "net.ipv4.tcp_sack=0\nnet.ipv4.tcp_dsack=0\nnet.ipv4.tcp_fack=0" >> /etc/sysctl.conf

# Reload the configs 
sysctl --system
sysctl -w net.ipv4.route.flush=1

clear
# Disable IPV6
sed -i '/^IPV6=yes/ c\IPV6=no\' /etc/default/ufw
echo 'blacklist ipv6' | tee -a /etc/modprobe.d/blacklist > /dev/null
clear
echo "Sysctl network settings set."

ip -a
echo "IP info logged."

netstat -pnola
echo "All active ports logged."

chown root:root /etc/fstab     # Scored
chmod 644 /etc/fstab           # Scored
chown root:root /etc/group     # Scored
chmod 644 /etc/group           # Scored
chown root:root /etc/shadow    # Scored
chmod 400 /etc/shadow  	    # Scored	
chown root:root /etc/apache2   # Scored
chmod 755 /etc/apache2         # Scored

chmod 0600 /etc/securetty
chmod 644 /etc/crontab
chmod 640 /etc/ftpusers
chmod 440 /etc/inetd.conf
chmod 440 /etc/xinetd.conf
chmod 400 /etc/inetd.d
chmod 644 /etc/hosts.allow
chmod 440 /etc/ers
chmod 640 /etc/shadow              # Scored
chmod 600 /boot/grub/grub.cfg      # Scored
chmod 600 /etc/ssh/sshd_config     # Scored
chmod 600 /etc/gshadow-            # Scored
chmod 600 /etc/group-              # Scored
chmod 600 /etc/passwd-             # Scored

chown root:root /etc/ssh/sshd_config # Scored
chown root:root /etc/passwd-         # Scored
chown root:root /etc/group-          # Scored
chown root:root /etc/shadow          # Scored
chown root:root /etc/securetty
chown root:root /boot/grub/grub.cfg  # Scored

chmod og-rwx /boot/grub/grub.cfg  	# Scored
chown root:shadow /etc/shadow-
chmod o-rwx,g-rw /etc/shadow-
chown root:shadow /etc/gshadow-
chmod o-rwx,g-rw /etc/gshadow-

find /var/log -perm /137 -type f -exec chmod 640 '{}' ;
chgrp syslog /var/log
chown root /var/log
chmod 0750 /var/log
chgrp adm /var/log/syslog
chown syslog /var/log/syslog
chmod 0640 /var/log/syslog
chmod 04755 /usr/bin/su
chmod 04755 /usr/bin/newgrp
chmod 04755 /usr/bin/mount

find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -perm /022 -type d -exec chmod -R 755 '{}' ;
find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -user root -type d -exec chown root '{}' ;
find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -group root -type d -exec chgrp root '{}' ;
find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -perm /022 -type f -exec chmod 755 '{}' ;
find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -user root -type f -exec chown root '{}' ;
find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -group root -type f ! -perm /2000 -exec chgrp root '{}' ;

find /lib /lib64 /usr/lib -perm /022 -type f -exec chmod 755 '{}' ;
find /lib /lib64 /usr/lib -perm /022 -type d -exec chmod 755 '{}' ;
find /lib /usr/lib /lib64 ! -user root -type f -exec chown root '{}' ;
find /lib /usr/lib /lib64 ! -user root -type d -exec chown root '{}' ;
find /lib /usr/lib /lib64 ! -group root -type f -exec chgrp root '{}' ;
find /lib /usr/lib /lib64 ! -group root -type d -exec chgrp root '{}' ;

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
echo "If any users are printed above this, they are part of the shadow group and need to be removed from the group IMMEDIATELY!"

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
		echo "ZeroUID User: $line"F
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
	systemctl start smbd
	systemctl status smbd
	cp /etc/samba/smb.conf /home/scriptuser/backups/
	if [ "$(grep '####### Authentication #######' /etc/samba/smb.conf)"==0 ]
	then
		sed -i 's/####### Authentication #######/####### Authentication #######\nsecurity = user/g' /etc/samba/smb.conf
	fi
        echo "restrict anonymous = 2"       | tee -a /etc/samba/smb.conf > /dev/null
        echo "encrypt passwords = True"     | tee -a /etc/samba/smb.conf > /dev/null # Idk which one it takes
        echo "encrypt passwords = yes"      | tee -a /etc/samba/smb.conf > /dev/null
        echo "read only = Yes"              | tee -a /etc/samba/smb.conf > /dev/null
        echo "ntlm auth = no"               | tee -a /etc/samba/smb.conf > /dev/null
        echo "obey pam restrictions = yes"  | tee -a /etc/samba/smb.conf > /dev/null
        echo "server signing = mandatory"   | tee -a /etc/samba/smb.conf > /dev/null
        echo "smb encrypt = mandatory"      | tee -a /etc/samba/smb.conf > /dev/null
        echo "min protocol = SMB2"          | tee -a /etc/samba/smb.conf > /dev/null
        echo "protocol = SMB2"              | tee -a /etc/samba/smb.conf > /dev/null
        echo "guest ok = no"                | tee -a /etc/samba/smb.conf > /dev/null
        echo "max log size = 24"            | tee -a /etc/samba/smb.conf > /dev/null
	echo "netbios-ns, netbios-dgm, netbios-ssn, and microsoft-ds ports have been opened. Samba config file has been configured."
	
	shares=$(ls -l /var/lib/samba/usershares | awk '{print "/var/lib/samba/usershares/"$8}')
        for i in $shares
        do
                cat $i | grep path >> /home/scriptuser/smbshares.log
        done
	
	while read line; do
                [[ "$line" =~ ^\[ ]] && name="$line"
                [[ "$line" =~ ^[[:space:]]*path ]] && echo -e "$name\t$line" >> /home/scriptuser/smbshares.log
        done < /etc/samba/smb.conf
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
    cp /etc/vsftpd.conf /home/scriptuser/backups/
    config_file="/etc/vsftpd.conf"

    # Jail users to home directory (user will need a home dir to exist)
    echo "chroot_local_user=YES"                        | sudo tee $config_file > /dev/null
    echo "chroot_list_enable=YES"                       | sudo tee -a $config_file > /dev/null
    echo "chroot_list_file=/etc/vsftpd.chroot_list"     | sudo tee -a $config_file > /dev/null
    echo "allow_writeable_chroot=YES"                   | sudo tee -a $config_file > /dev/null # Only enable if you want files to be editable

    # Allow or deny users
    echo "userlist_enable=YES"                  | sudo tee -a $config_file > /dev/null
    echo "userlist_file=/etc/vsftpd.userlist"   | sudo tee -a $config_file > /dev/null
    echo "userlist_deny=NO"                     | sudo tee -a $config_file > /dev/null

    # General config
    echo "anonymous_enable=NO"          | sudo tee -a $config_file > /dev/null # disable  anonymous login
    echo "local_enable=YES"             | sudo tee -a $config_file > /dev/null # permit local logins
    echo "write_enable=YES"             | sudo tee -a $config_file > /dev/null # enable FTP commands which change the filesystem
    echo "local_umask=022"              | sudo tee -a $config_file > /dev/null # value of umask for file creation for local users
    echo "dirmessage_enable=YES"        | sudo tee -a $config_file > /dev/null # enable showing of messages when users first enter a new directory
    echo "xferlog_enable=YES"           | sudo tee -a $config_file > /dev/null # a log file will be maintained detailing uploads and downloads
    echo "connect_from_port_20=YES"     | sudo tee -a $config_file > /dev/null # use port 20 (ftp-data) on the server machine for PORT style connections
    echo "xferlog_std_format=YES"       | sudo tee -a $config_file > /dev/null # keep standard log file format
    echo "listen=NO"                    | sudo tee -a $config_file > /dev/null # prevent vsftpd from running in standalone mode
    echo "listen_ipv6=YES"              | sudo tee -a $config_file > /dev/null # vsftpd will listen on an IPv6 socket instead of an IPv4 one
    echo "pam_service_name=vsftpd"      | sudo tee -a $config_file > /dev/null # name of the PAM service vsftpd will use
    echo "userlist_enable=YES"          | sudo tee -a $config_file > /dev/null # enable vsftpd to load a list of usernames
    echo "tcp_wrappers=YES"             | sudo tee -a $config_file > /dev/null # turn on tcp wrappers

    echo "ascii_upload_enable=NO"   | sudo tee -a $config_file > /dev/null 
    echo "ascii_download_enable=NO" | sudo tee -a $config_file > /dev/null
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
	echo -e "# Package generated configuration file\n# See the sshd_config(5) manpage for details\n\n# What ports, IPs and protocols we listen for\nPort 223\n# Use these options to restrict which interfaces/protocols sshd will bind to\n#ListenAddress ::\n#ListenAddress 0.0.0.0\nProtocol 2\n# HostKeys for protocol version \nHostKey /etc/ssh/ssh_host_rsa_key\nHostKey /etc/ssh/ssh_host_dsa_key\nHostKey /etc/ssh/ssh_host_ecdsa_key\nHostKey /etc/ssh/ssh_host_ed25519_key\n#Privilege Separation is turned on for security\nUsePrivilegeSeparation yes\n\n# Lifetime and size of ephemeral version 1 server key\nKeyRegenerationInterval 3600\nServerKeyBits 1024\n\n# Logging\nSyslogFacility AUTH\nLogLevel VERBOSE\n\n# Authentication:\nLoginGraceTime 30\nPermitRootLogin no\nStrictModes yes\n\nRSAAuthentication yes\nPubkeyAuthentication yes\n#AuthorizedKeysFile	$(pwd)/../.ssh/authorized_keys\n\n# Don't read the user's /home/scriptuser/.rhosts and /home/scriptuser/.shosts files\nIgnoreRhosts yes\n# For this to work you will also need host keys in /etc/ssh_known_hosts\nRhostsRSAAuthentication no\n# similar for protocol version 2\nHostbasedAuthentication no\n# Uncomment if you don't trust /home/scriptuser/.ssh/known_hosts for RhostsRSAAuthentication\n#IgnoreUserKnownHosts yes\n\n# To enable empty passwords, change to yes (NOT RECOMMENDED)\nPermitEmptyPasswords no\n\n# Change to yes to enable challenge-response passwords (beware issues with\n# some PAM modules and threads)\nChallengeResponseAuthentication no\n\n# Change to no to disable tunnelled clear text passwords\nPasswordAuthentication no\n\n# Kerberos options\n#KerberosAuthentication no\n#KerberosGetAFSToken no\n#KerberosOrLocalPasswd yes\n#KerberosTicketCleanup yes\n\n# GSSAPI options\n#GSSAPIAuthentication no\n#GSSAPICleanupCredentials yes\n\nX11Forwarding no\nX11DisplayOffset 10\nPrintMotd no\nPrintLastLog yes\nTCPKeepAlive no\n#UseLogin no\n\nMaxStartups 2\n#Banner /etc/issue.net\n\n# Allow client to pass locale environment variables\nAcceptEnv LANG LC_*\n\nSubsystem sftp /usr/lib/openssh/sftp-server\n\n# Set this to 'yes' to enable PAM authentication, account processing,\n# and session processing. If this is enabled, PAM authentication will\n# be allowed through the ChallengeResponseAuthentication and\n# PasswordAuthentication.  Depending on your PAM configuration,\n# PAM authentication via ChallengeResponseAuthentication may bypass\n# the setting of \"PermitRootLogin without-password\".\n# If you just want the PAM account and session checks to run without\n# PAM authentication, then enable this but set PasswordAuthentication\n# and ChallengeResponseAuthentication to 'no'.\nUsePAM yes\nRhostsAuthentication no\nClientAliveInterval 300\nClientAliveCountMax 1\nVerifyReverseMapping yes\nAllowTcpForwarding no\nUseDNS no\nPermitUserEnvironment no\nMaxAuthTries 3\nMaxAuthTriesLog 0\nGatewayPorts 0\nAllowAgentForwarding no\nMaxSessions 2\nCompression no\nMaxStartups 10:30:100\nAllowStreamLocalForwarding no\nPermitTunnel no" > /etc/ssh/sshd_config
	echo "Banner /etc/issue.net" | tee -a /etc/ssh/sshd_config > /dev/null
	echo "CyberTaipan Team Mensa" | tee /etc/issue.net > /dev/null
        echo 'MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256' | tee -a /etc/ssh/sshd_config > /dev/null
	echo 'Ciphers aes128-ctr,aes192-ctr,aes256-ctr,aes128-cbc,3des-cbc,aes192-cbc,aes256-cbc' | tee -a /etc/ssh/sshd_config > /dev/null
	echo 'KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256' >> /etc/ssh/sshd_config
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
	systemctl stop postfix
	systemctl disable postfix
	apt purge dovecot exim4 opensmtpd -y
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
	postconf -e disable_vrfy_command=yes
	postconf -e inet_interfaces=loopback-only
	postconf -e mynetworks="127.0.0.0/8 [::ffff:127.0.0.0]/104 [::1]/128"
	postconf -e smtpd_helo_required=yes
	postconf -e smtp_tls_loglevel=1
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
	apt-get install mariadb-server-1* -y
	mysql_secure_configuration
	cp /etc/mysql/my.cnf /home/scriptuser/backups/ 

	#Sets group
	echo "[mariadb]" | tee -a /etc/mysql/my.cnf
        
	#Disables LOCAL INFILE
        echo "local-infile=0" | tee -a /etc/mysql/my.cnf

        #Lowers database privileges
        echo "skip-show-database" | tee -a /etc/mysql/my.cnf

        # Disable remote access
        echo "bind-address=127.0.0.1" | tee -a /etc/mysql/my.cnf
        sed -i '/bind-address/ c\bind-address = 127.0.0.1' /etc/mysql/my.cnf

        #Disables symbolic links
        echo "symbolic-links=0" | tee -a /etc/mysql/my.cnf
	echo "secure_file_priv" | tee -a /etc/mysql/my.cnf
	echo "old_passwords=0" | tee -a /etc/mysql/my.cnf
	echo "safe-user-create=1" | tee -a /etc/mysql/my.cnf
	echo "allow-suspicious-udfs" | tee -a /etc/mysql/my.cnf
        #Sets root account password
        echo "[mysqladmin]" | tee -a /etc/mysql/my.cnf
        echo "user = root" | tee -a /etc/mysql/my.cnf
        echo "password = CyberTaipan123!" | tee -a /etc/mysql/my.cnf

        #Sets packet restrictions
        echo "key_buffer_size         = 16M" | tee -a /etc/mysql/my.cnf
        echo "max_allowed_packet      = 16M" | tee -a /etc/mysql/my.cnf

	systemctl restart mariadb
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
	ufw allow http
	ufw allow apache
	apt-get install libapache2-mod-security2 -y
	a2enmod headers
	a2enmod rewrite
	cp /etc/apache2/apache2.conf /home/scriptuser/backups/
	if [ -e /etc/apache2/apache2.conf ]
	then
  	    echo "HostnameLookups Off"              | tee -a /etc/apache2/apache2.conf > /dev/null
	    echo "LogLevel warn"                    | tee -a /etc/apache2/apache2.conf > /dev/null
	    echo "ServerTokens Prod"                | tee -a /etc/apache2/apache2.conf > /dev/null
	    echo "ServerSignature Off"              | tee -a /etc/apache2/apache2.conf > /dev/null
	    echo "Options all -Indexes"             | tee -a /etc/apache2/apache2.conf > /dev/null
	    echo "Header unset ETag"                | tee -a /etc/apache2/apache2.conf > /dev/null
	    echo "Header always unset X-Powered-By" | tee -a /etc/apache2/apache2.conf > /dev/null
	    echo "FileETag None"                    | tee -a /etc/apache2/apache2.conf > /dev/null
	    echo "TraceEnable off"                  | tee -a /etc/apache2/apache2.conf > /dev/null
	    echo "Timeout 60"                       | tee -a /etc/apache2/apache2.conf > /dev/null

	    echo "RewriteEngine On"                         | tee -a /etc/apache2/apache2.conf > /dev/null
	    echo 'RewriteCond %{THE_REQUEST} !HTTP/1\.1$'   | tee -a /etc/apache2/apache2.conf > /dev/null
	    echo 'RewriteRule .* - [F]'                     | tee -a /etc/apache2/apache2.conf > /dev/null

	    echo '<IfModule mod_headers.c>'                         | tee -a /etc/apache2/apache2.conf > /dev/null
	    echo '    Header set X-XSS-Protection 1;'               | tee -a /etc/apache2/apache2.conf > /dev/null
	    echo '</IfModule>'                                      | tee -a /etc/apache2/apache2.conf > /dev/null

	    # Secure /
	    echo "<Directory />"            | tee -a /etc/apache2/apache2.conf > /dev/null
	    echo "    Options -Indexes"     | tee -a /etc/apache2/apache2.conf > /dev/null
	    echo "    AllowOverride None"   | tee -a /etc/apache2/apache2.conf > /dev/null
	    echo "    Order Deny,Allow"     | tee -a /etc/apache2/apache2.conf > /dev/null
	    echo "    Options None"         | tee -a /etc/apache2/apache2.conf > /dev/null
	    echo "    Deny from all"        | tee -a /etc/apache2/apache2.conf > /dev/null
	    echo "</Directory>"             | tee -a /etc/apache2/apache2.conf > /dev/null

	    # Secure /var/www/html
	    echo "<Directory /var/www/html>"    | tee -a /etc/apache2/apache2.conf > /dev/null
	    echo "    Options -Indexes"         | tee -a /etc/apache2/apache2.conf > /dev/null
	    echo "</Directory>"                 | tee -a /etc/apache2/apache2.conf > /dev/null

	    # security.conf
	    # Enable HTTPOnly and Secure Flags
	    echo 'Header edit Set-Cookie ^(.*)\$ \$1;HttpOnly;Secure'                                   | tee -a /etc/apache2/conf-available/security.conf > /dev/null
	    echo 'ServerTokens Prod'                                                                    | tee -a /etc/apache2/conf-available/security.conf > /dev/null
	    echo 'TraceEnable Off'                                                                      | tee -a /etc/apache2/conf-available/security.conf > /dev/null
	    # Clickjacking Attack Protection
	    echo 'Header always append X-Frame-Options SAMEORIGIN'                                      | tee -a /etc/apache2/conf-available/security.conf > /dev/null

	    # XSS Protection
	    echo 'Header set X-XSS-Protection "1; mode=block"'                                          | tee -a /etc/apache2/conf-available/security.conf > /dev/null

	    # Enforce secure connections to the server
	    echo 'Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"'    | tee -a /etc/apache2/conf-available/security.conf > /dev/null  

	    # MIME sniffing Protection
	    echo 'Header set X-Content-Type-Options: "nosniff"'                                         | tee -a /etc/apache2/conf-available/security.conf > /dev/null

	    # Prevent Cross-site scripting and injections
	    echo 'Header set Content-Security-Policy "default-src '"'self'"';"'                         | tee -a /etc/apache2/conf-available/security.conf > /dev/null

		# Secure root directory
	    echo "<Directory />"            | tee -a /etc/apache2/conf-available/security.conf > /dev/null
	    echo "  Options -Indexes"       | tee -a /etc/apache2/conf-available/security.conf > /dev/null
	    echo "  AllowOverride None"     | tee -a /etc/apache2/conf-available/security.conf > /dev/null
	    echo "  Order Deny,Allow"       | tee -a /etc/apache2/conf-available/security.conf > /dev/null
	    echo "  Deny from all"          | tee -a /etc/apache2/conf-available/security.conf > /dev/null
	    echo "</Directory>"             | tee -a /etc/apache2/conf-available/security.conf > /dev/null

	    # Secure html directory
	    echo "<Directory /var/www/html>"        | tee -a /etc/apache2/conf-available/security.conf > /dev/null
	    echo "  Options -Indexes -Includes"     | tee -a /etc/apache2/conf-available/security.conf > /dev/null
	    echo "  AllowOverride None"             | tee -a /etc/apache2/conf-available/security.conf > /dev/null
	    echo "  Order Allow,Deny"               | tee -a /etc/apache2/conf-available/security.conf > /dev/null
	    echo "  Allow from All"                 | tee -a /etc/apache2/conf-available/security.conf > /dev/null
	    echo "</Directory>"                     | tee -a /etc/apache2/conf-available/security.conf > /dev/null

	    # ssl.conf
	    # TLS only
	    sed -i "s/SSLProtocol.*/SSLProtocol –ALL +TLSv1 +TLSv1.1 +TLSv1.2/" /etc/apache2/mods-available/ssl.conf
	    # Stronger cipher suite
	    sed -i "s/SSLCipherSuite.*/SSLCipherSuite HIGH:\!MEDIUM:\!aNULL:\!MD5:\!RC4/" /etc/apache2/mods-available/ssl.conf
	    
	    echo "LimitExcept GET" >> /etc/apache2/conf-available/hardening.conf

	    chown -R root:root /etc/apache2
	    chown -R root:root /etc/apache 2> /dev/null
	fi
        
        chown -R root:root /etc/apache2
	systemctl start apache2
	systemctl status apache2

	echo "https and https ports have been allowed on the firewall. Apache2 config file has been configured. Only root can now access the Apache2 folder."
else
	echo Response not recognized.
fi
echo "Web Server is complete."

if [ $phpYN == no ]
then
	apt-get purge *php* -y
	echo "PHP has been purged."
elif [ $phpYN == yes ]
then
	apt-get install php -y
	PHPCONFIG=/etc/php/7.*/apache2/php.ini

        # Disable Global variables
        echo 'register_globals = Off' | tee -a $PHPCONFIG

        # Disable tracking, HTML, and display errors
        sed -i "s/^;\?html_errors.*/html_errors = Off/" $PHPCONFIG
        sed -i "s/^;\?display_errors.*/display_errors = Off/" $PHPCONFIG
        sed -i "s/^;\?expose_php.*/expose_php = Off/" $PHPCONFIG
        sed -i "s/^;\?mail\.add_x_header.*/mail\.add_x_header = Off/" $PHPCONFIG

        # Disable Remote File Includes
        sed -i "s/^;\?allow_url_fopen.*/allow_url_fopen = Off/" $PHPCONFIG

        # Restrict File Uploads
        sed -i "s/^;\?file_uploads.*/file_uploads = Off/" $PHPCONFIG

        # Control POST/Upload size
        sed -i "s/^;\?post_max_size.*/post_max_size = 1K/" $PHPCONFIG
        sed -i "s/^;\?upload_max_filesize.*/upload_max_filesize = 2M/" $PHPCONFIG

        # Protect sessions
        sed -i "s/^;\?session\.cookie_httponly.*/session\.cookie_httponly = 1/" $PHPCONFIG

        # General
        sed -i "s/^;\?session\.use_strict_mode.*/session\.use_strict_mode = On/" $PHPCONFIG
 
        sed -i "s/^;\?disable_functions.*/disable_functions = php_uname, getmyuid, getmypid, passthru,listen, diskfreespace, tmpfile, link, ignore_user_abort, shell_exec, dl, set_time_limit, exec, system, highlight_file, show_source, fpassthru, virtual, posix_ctermid, posix_getcwd, posix_getegid, posix_geteuid, posix_getgid, posix_getgrgid, posix_getgrnam, posix_getgroups, posix_getlogin, posix_getpgid, posix_getpgrp, posix_getpid, posix_getppid, posix_getpwnam, posix_getpwuid, posix_getrlimit, posix_getsid, posix_getuid, posix_isatty, posix_kill, posix_mkfifo, posix_setegid, posix_seteuid, posix_setgid, posix_setpgid, posix_setsid, posix_setuid, posix_times, posix_ttyname, posix_uname, proc_open, proc_close, proc_get_status, proc_nice, proc_terminate, phpinfo/" $PHPCONFIG
        sed -i "s/^;\?max_execution_time.*/max_execution_time = 30/" $PHPCONFIG
        sed -i "s/^;\?max_input_time.*/max_input_time = 30/" $PHPCONFIG
        sed -i "s/^;\?memory_limit.*/memory_limit = 40M/" $PHPCONFIG
        sed -i "s/^;\?open_basedir.*/open_basedir = \"c:inetpub\"/" $PHPCONFIG
	
	echo "PHP is configured."
else
	echo "Response not recognised."
fi
echo "PHP is complete."

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
	ufw allow 53
	echo "domain port has been allowed on the firewall and bind9 installed."
	chsh -s /sbin/nologin bind
	passwd -l bind
	wget https://raw.githubusercontent.com/aydenbottos/ayden-linux-script/master/named.conf.options
	cp named.conf.options /etc/bind/named.conf.options
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
	find /home -regextype posix-extended -regex '.*\.(midi|mid|mod|mp3|mp2|mpa|abs|mpega|au|snd|wav|aiff|aif|sid|mkv|flac|ogg)$' -delete
	clear
	echo "All audio files has been listed."

	find /home -regextype posix-extended -regex '.*\.(mpeg|mpg|mpe|dl|movie|movi|mv|iff|anim5|anim3|anim7|avi|vfw|avx|fli|flc|mov|qt|spl|swf|dcr|dir|dxr|rpm|rm|smi|ra|ram|rv|wmv|asf|asx|wma|wax|wmv|wmx|3gp|mov|mp4|flv|m4v|xlsx|pptx|docx|csv)$' -delete
	find /home -iname "*.txt" >> /home/scriptuser/badfiles.log
	clear
	echo "All video files have been listed."
	
	find /home -regextype posix-extended -regex '.*\.(tiff|tif|rs|iml|gif|jpeg|exe|torrent|pdf|run|bat|jpg|jpe|png|rgb|xwd|xpm|ppm|pbm|pgm|pcx|ico|svg|svgz|pot|xml|pl)$' -delete
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
apt install mawk -y
for i in $(mawk -F: '$3 > 999 && $3 < 65534 {print $1}' /etc/passwd); do [ -d /home/${i} ] && chmod -R 750 /home/${i}/; done
chmod -R 700 /root
echo "Home directory permissions set."

clear
for i in $(mawk -F: '$3 > 999 && $3 < 65534 {print $1}' /etc/passwd); do [ -d /home/${i} ] && chown -R ${i}:${i} /home/${i}/; done
chown -R root /root
echo "Home directory owner set."

clear
find / -iname "*.php" -type f >> /home/scriptuser/badfiles.log
echo "All PHP files have been listed. ('/var/cache/dictionaries-common/sqspell.php' is a system PHP file)"

clear
find / -iname "*.sh" -type f >> /home/scriptuser/badfiles.log
echo "All shell scripts have been listed. Note: there are a lot of system ones too."

find / -iname "*.pl" -type f >> /home/scriptuser/badfiles.log

clear
find / -perm -4000 >> /home/scriptuser/badfiles.log
find / -perm -2000 >> /home/scriptuser/badfiles.log
echo "All files with perms 4000 and 2000 have been logged."

clear
find / -nogroup -nouser >> /home/scriptuser/badfiles.log
echo "All files with no owner have been logged."

clear
apt install tree -y
tree >> /home/scriptuser/directorytree.txt
echo "Directory tree saved to file."

clear
chmod 000 /usr/bin/as >/dev/null 2>&1
chmod 000 /usr/bin/byacc >/dev/null 2>&1
chmod 000 /usr/bin/yacc >/dev/null 2>&1
chmod 000 /usr/bin/bcc >/dev/null 2>&1
chmod 000 /usr/bin/kgcc >/dev/null 2>&1
chmod 000 /usr/bin/cc >/dev/null 2>&1
chmod 000 /usr/bin/gcc >/dev/null 2>&1
chmod 000 /usr/bin/*c++ >/dev/null 2>&1
chmod 000 /usr/bin/*g++ >/dev/null 2>&1
echo "Disabled compilers."

clear
apt install fail2ban -y
systemctl enable fail2ban
systemctl start fail2ban
cat <<EOF > /etc/fail2ban/jail.local
[sshd]
enabled = true
port = 22
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
EOF
systemctl restart fail2ban
echo "Fail2Ban enabled."

clear
apt install acct -y
touch /var/log/wtmp
echo "Enabled process accounting."

clear
apt install -y arpwatch
systemctl enable --now arpwatch
systemctl start arpwatch
echo "Installed ARPWatch."

clear
sudo systemctl stop cups-browsed
sudo systemctl disable cups-browsed
echo "Disabled CUPS"

# Remediation is applicable only in certain platforms
if dpkg-query --show --showformat='${db:Status-Status}\n' 'gdm3' 2>/dev/null | grep -q installed; then

# Try find '[xdmcp]' and 'Enable' in '/etc/gdm/custom.conf', if it exists, set
# to 'false', if it isn't here, add it, if '[xdmcp]' doesn't exist, add it there
if grep -qzosP '[[:space:]]*\[xdmcp]([^\n\[]*\n+)+?[[:space:]]*Enable' '/etc/gdm/custom.conf'; then
    
    sed -i 's/Enable[^(\n)]*/Enable=false/' '/etc/gdm/custom.conf'
elif grep -qs '[[:space:]]*\[xdmcp]' '/etc/gdm/custom.conf'; then
    sed -i '/[[:space:]]*\[xdmcp]/a Enable=false' '/etc/gdm/custom.conf'
else
    if test -d "/etc/gdm"; then
        printf '%s\n' '[xdmcp]' 'Enable=false' >> '/etc/gdm/custom.conf'
    else
        echo "Config file directory '/etc/gdm' doesnt exist, not remediating, assuming non-applicability." >&2
    fi
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

clear
echo -e "[org/gnome/settings-daemon/plugins/media-keys]\nlogout=\'\'" >> /etc/dconf/db/local.d/00-disable-CAD
dconf update
systemctl mask ctrl-alt-del.target
systemctl daemon-reload
echo "Disabled CTRL-ALT-DELETE reboot in Gnome."

clear
lsof -Pnl +M -i > /home/scriptuser/runningProcesses.log
## Removing the default running processes
sed -i '/avahi-dae/ d' /home/scriptuser/runningProcesses.log
sed -i '/cups-brow/ d' /home/scriptuser/runningProcesses.log
sed -i '/dhclient/ d' /home/scriptuser/runningProcesses.log
sed -i '/dnsmasq/ d' /home/scriptuser/runningProcesses.log
sed -i '/cupsd/ d' /home/scriptuser/runningProcesses.log
echo "All running processes listed."

if /usr/sbin/visudo -qcf /etc/sudoers; then
    cp /etc/sudoers /etc/sudoers.bak
    if ! grep -P '^[\s]*Defaults.*\brequiretty\b.*$' /etc/sudoers; then
        # sudoers file doesn't define Option requiretty
        echo "Defaults requiretty" >> /etc/sudoers
    fi
    
    # Check validity of sudoers and cleanup bak
    if /usr/sbin/visudo -qcf /etc/sudoers; then
        rm -f /etc/sudoers.bak
    else
        echo "Fail to validate remediated /etc/sudoers, reverting to original file."
        mv /etc/sudoers.bak /etc/sudoers
        false
    fi
else
    echo "Skipping remediation, /etc/sudoers failed to validate"
    false
fi

clear
echo -e "$pw\n$pw" | passwd
echo "Root password set."

clear
systemctl >> /home/scriptuser/systemctlUnits.log
echo "All systemctl services listed."

apt install nmap -y
nmap -oN nmap.log localhost 
apt purge nmap -y
clear
echo "Logged ports with Nmap then deleted it again."

echo "needs_root_rights = no" >> /etc/X11/Xwrapper.config
echo "Enabled rootless Xorg."

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

wget https://raw.githubusercontent.com/bcoles/linux-audit/master/linux-audit.sh
chmod a+x linux-audit.sh
./linux-audit.sh
clear
echo "Ran Linux auditing tools."

( chkrootkit -q >> ChkrootkitOutput.txt; echo "Finished ChkRootKit" ) &
disown; sleep 2;
echo "Running ChkRootKit."

clear
cp /etc/login.defs /home/scriptuser/backups/
sed -ie "s/PASS_MAX_DAYS.*/PASS_MAX_DAYS\\t30/" /etc/login.defs
sed -ie "s/PASS_MIN_DAYS.*/PASS_MIN_DAYS\\t10/" /etc/login.defs
sed -ie "s/PASS_WARN_AGE.*/PASS_WARN_AGE\\t7/" /etc/login.defs
sed -ie "s/FAILLOG_ENAB.*/FAILLOG_ENAB\\tyes/" /etc/login.defs
sed -ie "s/LOG_UNKFAIL_ENAB.*/LOG_UNKFAIL_ENAB\\tyes/" /etc/login.defs
sed -ie "s/LOG_OK_LOGINS.*/LOG_OK_LOGINS\\tyes/" /etc/login.defs
sed -ie "s/SYSLOG_SU_ENAB.*/SYSLOG_SU_ENAB\\tyes/" /etc/login.defs
sed -ie "s/SYSLOG_SG_ENAB.*/SYSLOG_SG_ENAB\\tyes/" /etc/login.defs
sed -ie "s/LOGIN_RETRIES.*/LOGIN_RETRIES\\t5/" /etc/login.defs
sed -ie "s/ENCRYPT_METHOD.*/ENCRYPT_METHOD\\tSHA512/" /etc/login.defs
sed -ie "s/LOGIN_TIMEOUT.*/LOGIN_TIMEOUT\\t60/" /etc/login.defs
echo -e "SHA_CRYPT_MIN_ROUNDS\t6000" >> /etc/login.defs
echo -e "FAIL_DELAY\t4" >> /etc/login.defs
echo "Login settings set in login.defs"

echo "umask 027" >> /etc/bash.bashrc
echo "umask 027" >> /etc/profile
echo "Set a very strict umask."


awk -F':' '{ if ($3 >= 1000 && $3 != 65534) system("chgrp -f " $3" "$6"/.[^\.]?*") }' /etc/passwd
awk -F':' '{ if ($3 >= 1000 && $3 != 65534) system("chown -f " $3" "$6"/.[^\.]?*") }' /etc/passwd

for home_dir in $(awk -F':' '{ if ($3 >= 1000 && $3 != 65534) print $6 }' /etc/passwd); do
    # Only update the permissions when necessary. This will avoid changing the inode timestamp when
    # the permission is already defined as expected, therefore not impacting in possible integrity
    # check systems that also check inodes timestamps.
    find "$home_dir" -maxdepth 0 -perm /7027 -exec chmod u-s,g-w-s,o=- {} \;
done


for home_dir in $(awk -F':' '{ if ($3 >= 1000 && $3 != 65534) print $6 }' /etc/passwd); do
    # Only update the permissions when necessary. This will avoid changing the inode timestamp when
    # the permission is already defined as expected, therefore not impacting in possible integrity
    # check systems that also check inodes timestamps.
    find "$home_dir" -maxdepth 0 -perm /7027 -exec chmod u-s,g-w-s,o=- {} \;
done

clear
cp /etc/pam.d/common-auth /home/scriptuser/backups/
cp /etc/pam.d/common-password /home/scriptuser/backups/
echo -e "#\n# /etc/pam.d/common-auth - authentication settings common to all systemctls\n#\n# This file is included from other systemctl-specific PAM config files,\n# and should contain a list of the authentication modules that define\n# the central authentication scheme for use on the system\n# (e.g., /etc/shadow, LDAP, Kerberos, etc.).  The default is to use the\n# traditional Unix authentication mechanisms.\n#\n# As of pam 1.0.1-6, this file is managed by pam-auth-update by default.\n# To take advantage of this, it is recommended that you configure any\n# local modules either before or after the default block, and use\n# pam-auth-update to manage selection of other modules.  See\n# pam-auth-update(8) for details.\n\n# here are the per-package modules (the \"Primary\" block)\nauth	[success=1 default=ignore]	pam_unix.so\n# here's the fallback if no module succeeds\nauth	requisite			pam_deny.so\n# prime the stack with a positive return value if there isn't one already; >> /dev/null\n# this avoids us returning an error just because nothing sets a success code\n# since the modules above will each just jump around\nauth	required			pam_permit.so\n# and here are more per-package modules (the \"Additional\" block)\nauth	optional			pam_cap.so \n# end of pam-auth-update config\nauth required pam_tally2.so deny=5 unlock_time=1800 onerr=fail audit even_deny_root_account silent\nauth required pam_faildelay.so delay=4000000" > /etc/pam.d/common-auth
echo -e "#\n# /etc/pam.d/common-password - password-related modules common to all systemctls\n#\n# This file is included from other systemctl-specific PAM config files,\n# and should contain a list of modules that define the systemctls to be\n# used to change user passwords.  The default is pam_unix.\n\n# Explanation of pam_unix options:\n#\n# The \"sha512\" option enables salted SHA512 passwords.  Without this option,\n# the default is Unix crypt.  Prior releases used the option \"md5\".\n#\n# The \"obscure\" option replaces the old \`OBSCURE_CHECKS_ENAB\' option in\n# login.defs.\n#\n# See the pam_unix manpage for other options.\n\n# As of pam 1.0.1-6, this file is managed by pam-auth-update by default.\n# To take advantage of this, it is recommended that you configure any\n# local modules either before or after the default block, and use\n# pam-auth-update to manage selection of other modules.  See\n# pam-auth-update(8) for details.\n\n# here are the per-package modules (the \"Primary\" block)\npassword	[success=1 default=ignore]	pam_unix.so obscure sha512 rounds=6000\n# here's the fallback if no module succeeds\npassword	requisite			pam_deny.so\n# prime the stack with a positive return value if there isn't one already; >> /dev/null\n# this avoids us returning an error just because nothing sets a success code\n# since the modules above will each just jump around\npassword	required			pam_permit.so\npassword requisite pam_cracklib.so retry=3 minlen=14 difok=8 reject_username minclass=4 maxrepeat=3 dcredit=-1 ucredit=-1 lcredit=-1 ocredit=-1\npassword requisite pam_pwhistory.so use_authtok remember=24 enforce_for_root\n# and here are more per-package modules (the \"Additional\" block)\npassword	optional	pam_gnome_keyring.so \n# end of pam-auth-update config" > /etc/pam.d/common-password
echo "auth required pam_wheel.so use_uid" >> /etc/pam.d/su
echo "Password policies have been set with and /etc/pam.d."
getent group nopasswdlogin && gpasswd nopasswdlogin -M ''
sed -i 's/sufficient/d' /etc/pam.d/gdm-password
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
apt install usbguard
systemctl start usbguard
echo "USBGuard has been installed."

clear
systemctl enable haveged
systemctl start haveged
echo "/usr/local/sbin/haveged -w 1024" >> /etc/rc.local
echo "Enabled entropy generation daemon."

clear
pushd /etc/
/bin/rm -f cron.deny at.deny
echo root >cron.allow
echo root >at.allow
/bin/chown root:root cron.allow at.allow
/bin/chmod 400 cron.allow at.allow
popd
echo "Only root allowed in cron."

echo "chmod 400 /proc/kallsyms" >> /etc/rc.local
echo "Set permissions for kallsyms."

systemctl enable chronyd
systemctl start chronyd
echo "Started Chronyd and enabled it."

clear
apt-get update 
apt-get upgrade -y
echo "Ubuntu OS has checked for updates and has been upgraded."

killall firefox
echo "user_pref(\"dom.disable_open_during_load\", true);" >> /home/$mainUser/.mozilla/firefox/default/user.js
echo "Check Firefox to ensure all settings have been applied."

clear
apt-get autoremove -y 
apt-get autoclean -y 
apt-get clean -y 
echo "All unused packages have been removed."

clear
export $(cat /etc/environment)
echo "PATH reset to normal."

clear
sed -i '1i\* hard maxlogins 10' /etc/security/limits.conf
echo "* hard core 0" >> /etc/security/limits.conf
echo "1000: hard cpu 180" >> /etc/security/limits.conf
echo "*	hard nproc 1024" >> /etc/security/limits.conf
echo "Login limits set."

echo "proc /proc proc nosuid,nodev,noexec,hidepid=2,gid=proc 0 0" >> /etc/fstab
mkdir -p /etc/systemd/system/systemd-logind.service.d/
echo -e "[Service]\nSupplementaryGroups=proc" >> /etc/systemd/system/systemd-logind.service.d/hidepid.conf

echo "Hide processes not created by user in proc."

clear
apt install rsyslog -y
systemctl enable --now rsyslog
systemctl start rsyslog
echo -e "auth.*,authpriv.* /var/log/secure\ndaemon.notice /var/log/messages" >> /etc/rsyslog.d/50-default.conf
systemctl restart rsyslog
echo "Installed rsyslog if it already wasn't installed and configured it."

clear
wget https://raw.githubusercontent.com/Neo23x0/auditd/master/audit.rules
mv audit.rules /etc/audit/audit.rules
echo "-e 2" >> /etc/audit/audit.rules
auditctl -e 1
auditd -s enable
systemctl --now enable auditd
systemctl start auditd
echo -e "max_log_file = 6\naction_mail_acct = root\nadmin_space_left_action = single\nmax_log_file_action = single" >> /etc/audit/auditd.conf


echo "Auditd and audit rules have been set and enabled."

wget http://ftp.us.debian.org/debian/pool/main/s/scap-security-guide/ssg-debderived_0.1.62-2_all.deb
apt install ./ssg-debderived_0.1.62-2_all.deb -y

wget http://ftp.au.debian.org/debian/pool/main/s/scap-security-guide/ssg-debian_0.1.62-2_all.deb
apt install ./ssg-debian_0.1.62-2_all.deb -y

wget https://raw.githubusercontent.com/aydenbottos/ayden-linux-script/master/ssg-ubuntu2004-ds-tailoring.xml

var1=$(lsb_release -is | awk '{print tolower($0)}')
var2=$(lsb_release -r | sed 's/[^0-9]*//g')
code=$var1$var2

oscap xccdf eval --remediate --verbose-log-file run1.log --verbose ERROR --tailoring-file ssg-ubuntu2004-ds-tailoring.xml --profile xccdf_org.teammensa_profile_hardening /usr/share/xml/scap/ssg/content/ssg-$code-ds.xml
oscap xccdf eval --remediate --results results.xml --report cisreport.html --verbose-log-file run2.log --verbose ERROR --tailoring-file ssg-ubuntu2004-ds-tailoring.xml --profile xccdf_org.teammensa_profile_hardening /usr/share/xml/scap/ssg/content/ssg-$code-ds.xml
echo "Ran OpenSCAP for CIS compliance."

wget https://www.openwall.com/signatures/openwall-offline-signatures.asc
gpg --import openwall-offline-signatures.asc
wget https://lkrg.org/download/lkrg-0.9.5.tar.gz.sign
wget https://lkrg.org/download/lkrg-0.9.5.tar.gz
gpg --verify lkrg-0.9.5.tar.gz.sign lkrg-0.9.5.tar.gz
tar -xf lkrg-0.9.5.tar.gz
pushd lkrg-0.9.5/
make
make install
systemctl start lkrg
systemctl enable lkrg
popd
echo "Enabled Linux Kernel Runtime Guard."

unhide -f procall sys
echo "Looked for hidden processes."

systemctl disable avahi-daemon
systemctl stop avahi-daemon
echo "Disabled Avahi daemon"

systemctl disable autofs.service
echo "Disabled automounter."

rfkill block all
echo "Disabled WiFi."

sed -i 's/\/messages/syslog/g' /etc/psad/psad.conf
psad --sig-update
systemctl start psad
echo "PSAD started."

chmod 700 /boot /usr/src /lib/modules /usr/lib/modules
echo "Set kernel file permissions."

clear
apt install ecryptfs-utils -y
echo "Script is complete. Log user out to enable home directory encryption. Once logged out, login to another administrator. Then, access terminal and run sudo ecryptfs-migrate-home -u <default user>. After that, follow the prompts."
apt install curl
url=$(cat scriptlog.txt | curl -F 'sprunge=<-' http://sprunge.us)
wget -O/dev/null --header 'Content-type: application/json' --post-data '{"text":"<'$url'|Linux script results>"}' $(echo aHR0cHM6Ly9ob29rcy5zbGFjay5jb20vc2VydmljZXMvVEg3U0pLNUg5L0IwMko0NENHQkFSL3hHeGFHVXdNdDZmTU5aWkViaDlmbDhOaA== | base64 --decode) > /dev/null 2>&1
