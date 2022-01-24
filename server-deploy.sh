#!/bin/sh

## Packetsync Networks' Server Deploy Script
## v0.11 (Debian/Ubuntu)

VERSION = 0.11
DISTRO = "ubuntu-lts"
TIMEZONE="Europe/London"

# Enable logging
exec 1> >(tee -a "/var/log/deploy.log") 2>&1

# Display motd and branding
cat /etc/motd
cat << "EOF"
   ___              _          _                                  __       _                          _
  / _ \ __ _   ___ | | __ ___ | |_  ___  _   _  _ __    ___    /\ \ \ ___ | |_ __      __ ___   _ __ | | __ ___
 / /_)// _` | / __|| |/ // _ \| __|/ __|| | | || '_ \  / __|  /  \/ // _ \| __|\ \ /\ / // _ \ | '__|| |/ // __|
/ ___/| (_| || (__ |   <|  __/| |_ \__ \| |_| || | | || (__  / /\  /|  __/| |_  \ V  V /| (_) || |   |   < \__ \
\/     \__,_| \___||_|\_\\___| \__||___/ \__, ||_| |_| \___| \_\ \/  \___| \__|  \_/\_/  \___/ |_|   |_|\_\|___/
    ___              _                 __|___/         _         _
   /   \ ___  _ __  | |  ___   _   _  / _\  ___  _ __ (_) _ __  | |_
  / /\ // _ \| '_ \ | | / _ \ | | | | \ \  / __|| '__|| || '_ \ | __|
 / /_//|  __/| |_) || || (_) || |_| | _\ \| (__ | |   | || |_) || |_
/___,'  \___|| .__/ |_| \___/  \__, | \__/ \___||_|   |_|| .__/  \__|
             |_|               |___/                     |_|
EOF

# User account queries
read -p 'Username: ' USERNAME
PASSWORD=$(/lib/cryptsetup/askpass "Password: ")

# Harden SSH Access
sed -i -e 's/#Port 22/Port 22123/g' /etc/ssh/sshd_config
sed -i -e 's/#AddressFamily any/AddressFamily inet/g' /etc/ssh/sshd_config
sed -i -e 's/PermitRootLogin yes/PermitRootLogin no/g' /etc/ssh/sshd_config
sed -i -e 's/#PasswordAuthentication yes/PasswordAuthentication no/g' /etc/ssh/sshd_config
sed -i -e 's/#PermitEmptyPasswords no/PermitEmptyPasswords no/g' /etc/ssh/sshd_config
sed -i -e 's/#PubkeyAuthentication yes/PubkeyAuthentication yes/g' /etc/ssh/sshd_config
cat 'AllowUsers $USERNAME' >> /etc/ssh/sshd_config

# Create user account
if [ "$USERNAME" != "" ] && [ "$USERNAME" != "root" ]; then
    passwd --lock root
    apt -y install sudo
    adduser $USERNAME --disabled-password --gecos ""
    echo "$USERNAME:$PASSWORD" | chpasswd
    usermod -aG sudo $USERNAME
    SSHOMEDIR="/home/$USERNAME/.ssh"
    mkdir $SSHOMEDIR && echo "$SSHKEY" >> $SSHOMEDIR/authorized_keys
    chmod -R 700 $SSHOMEDIR && chmod 600 $SSHOMEDIR/authorized_keys
    chown -R $USERNAME:$USERNAME $SSHOMEDIR
fi

# Perform full system update
apt-get -o Acquire::ForceIPv4=true update
DEBIAN_FRONTEND=noninteractive \
  apt-get \
  -o Dpkg::Options::=--force-confold \
  -o Dpkg::Options::=--force-confdef \
  -y --allow-downgrades --allow-remove-essential --allow-change-held-packages

# Setup networking
IPADDR=`hostname -I | awk '{ print $1 }'`
apt install -y dnsutils net-tools nmap whois netcat wireguard openvpn openresolv
echo -e "\n# Added by Packetsync Networks Deploy Script" >> /etc/hosts
if [ "$FQDN" == "" ]; then
    FQDN=`dnsdomainname -A | cut -d' ' -f1`
fi
if [ "$HOST" == "" ]; then
    HOSTNAME=`echo $FQDN | cut -d'.' -f1`
else
    HOSTNAME="$HOST"
fi
echo -e "$IPADDR\t$FQDN $HOSTNAME" >> /etc/hosts
hostnamectl set-hostname "$HOSTNAME"

# Configure timezone
timedatectl set-timezone "$TIMEZONE"

# Preliminary firewall rules
apt install -y ufw
ufw default allow outgoing
ufw default deny incoming
ufw allow proto tcp from any to any port 443 # OpenVPN
ufw allow proto tcp from 10.101.12.2 to any port 22123 # ssh
ufw allow proto udp from any to any port 53 # DNS
ufw allow proto tcp from any to any port 853 # Unbound
ufw allow proto udp from any to any port 33123 # Wireguard
ufw --force enable

# Install Fail2ban
apt install -y fail2ban
cp /etc/fail2ban/fail2ban.conf /etc/fail2ban/fail2ban.local
cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
systemctl start fail2ban
systemctl enable fail2ban

# Setup shell
apt install -y zsh git powerline fonts-powerline curl wget
sh -c "$(curl -fsSL https://raw.github.com/ohmyzsh/ohmyzsh/master/tools/install.sh)"
git clone https://github.com/zsh-users/zsh-autosuggestions ${ZSH_CUSTOM:-/home/$USERNAME/.oh-my-zsh/custom}/plugins/zsh-autosuggestions
sed -i -e 's/#plugins=(git)/plugins=(git zsh-autosuggestions)/g' /home/$USERNAME/.zshrc

# Todo: Provide interactive environment to finetune the deployment process

echo "All done!\n"
