#!/bin/bash
clear
echo -e "\e[1;32m-----------------------------------------------------"
echo -e "\e[1;32m                  XFRANZ Installer                   "
echo -e "\e[1;32m-----------------------------------------------------"
sleep 2
clear
ip1=`curl -s https://ipinfo.io/ip`
echo "IP Address = ${ip1}"
sleep 3
clear	
echo -----------------------------------------------------
echo Updating System
echo -----------------------------------------------------
sleep 1
apt-get -o Acquire::ForceIPv4=true update
sleep 1
clear
echo -----------------------------------------------------
echo Installing Dependencies, Please wait.
echo -----------------------------------------------------
sleep 1
apt-get -o Acquire::ForceIPv4=true install mysql-client fail2ban apache2 -y
apt-get -o Acquire::ForceIPv4=true install dos2unix nano curl unzip jq virt-what net-tools -y
apt-get -o Acquire::ForceIPv4=true install php-cli net-tools cron php-fpm php-json php-pdo php-zip php-gd  php-mbstring php-curl php-xml php-bcmath php-json -y
apt-get -o Acquire::ForceIPv4=true install gnutls-bin pwgen python -y
sleep 1
clear
echo -----------------------------------------------------
echo Installing Openvpn
echo -----------------------------------------------------
sleep 2
apt-get install openvpn easy-rsa -y
sleep 1
mkdir -p /etc/openvpn/easy-rsa/keys
mkdir -p /etc/openvpn/login
mkdir -p /var/www/html/status
clear
echo -----------------------------------------------------
echo Installing Squid Proxy
echo -----------------------------------------------------
sleep 2
sudo touch /etc/apt/sources.list.d/trusty_sources.list
echo "deb http://us.archive.ubuntu.com/ubuntu/ trusty main universe" | sudo tee --append /etc/apt/sources.list.d/trusty_sources.list > /dev/null
sudo apt update
sleep 1
sudo apt install -y squid3=3.3.8-1ubuntu6 squid=3.3.8-1ubuntu6 squid3-common=3.3.8-1ubuntu6
sleep 1
wget -q https://api.memorykey.net/fastnet/installer/squid3
sudo cp squid3 /etc/init.d/
sudo chmod +x /etc/init.d/squid3
sudo update-rc.d squid3 defaults
clear
echo -----------------------------------------------------
echo Configuring Sysctl
echo -----------------------------------------------------
sleep 2
echo 'fs.file-max = 51200
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.core.netdev_max_backlog = 250000
net.core.somaxconn = 4096
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_keepalive_time = 1200
net.ipv4.ip_local_port_range = 10000 65000
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.tcp_max_tw_buckets = 5000
net.ipv4.tcp_mem = 25600 51200 102400
net.ipv4.tcp_rmem = 4096 87380 67108864
net.ipv4.tcp_wmem = 4096 65536 67108864
net.ipv4.tcp_mtu_probing = 1
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
net.ipv4.ip_forward=1
net.ipv4.icmp_echo_ignore_all = 1' >> /etc/sysctl.conf
echo '* soft nofile 512000
* hard nofile 512000' >> /etc/security/limits.conf
ulimit -n 512000
clear 
echo -----------------------------------------------------
echo Installing Stunnel
echo -----------------------------------------------------
sleep 2
apt-get install stunnel4 -y
sleep 1
sed -i 's/ENABLED=0/ENABLED=1/g' /etc/default/stunnel4
clear
echo -----------------------------------------------------
echo Reduce Overheating with TLP
echo -----------------------------------------------------
sleep 2
sudo add-apt-repository ppa:linrunner/tlp -y
sleep 1
sudo apt-get update
sleep 1
sudo apt-get install tlp tlp-rdw -y
sleep 1
sudo tlp start
clear
echo -----------------------------------------------------
echo Configuring Stunnel.conf 
echo -----------------------------------------------------
wget -q https://api.memorykey.net/fastnet/installer/stunnel.zip
unzip stunnel.zip
cat key.pem cert.pem >> /etc/stunnel/stunnel.pem
touch /var/www/html/status/tcp.txt
touch /var/www/html/status/udp.txt
touch /var/www/html/status/tcp-ipp.txt
touch /var/www/html/status/udp-ipp.txt
sleep 1
rm key.pem
rm cert.pem
sleep 1
echo 'cert = /etc/stunnel/stunnel.pem
socket = a:SO_REUSEADDR=1
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1
client = no

[openvpn]
connect = '$ip1':1194
accept = 443' > /etc/stunnel/stunnel.conf
clear
echo -----------------------------------------------------
echo Checking Configuration
echo -----------------------------------------------------
sleep 2
update-rc.d apache2 enable  > /dev/null
update-rc.d squid3 enable  > /dev/null
update-rc.d cron enable  > /dev/null
update-rc.d openvpn enable  > /dev/null
update-rc.d stunnel4 enable  > /dev/null
update-rc.d fail2ban enable  > /dev/null
update-rc.d tlp enable  > /dev/null
clear
echo -----------------------------------------------------
echo Configuring IP Tables
echo -----------------------------------------------------
sleep 2
sysctl -p
sudo iptables -P INPUT ACCEPT
sudo iptables -P FORWARD ACCEPT
sudo iptables -P OUTPUT ACCEPT
iptables -t nat -A POSTROUTING -s 172.20.0.0/21 -j SNAT --to $ip1
iptables -t nat -A POSTROUTING -s 173.20.0.0/21 -j SNAT --to $ip1
iptables -I INPUT -p tcp -m tcp --dport 80 -j ACCEPT
iptables -I INPUT -p tcp -m tcp --dport 443 -j ACCEPT
iptables -I INPUT -p tcp -m tcp --dport 1194 -j ACCEPT
iptables -I INPUT -p tcp -m tcp --dport 8080 -j ACCEPT
iptables -I INPUT -p tcp -m tcp --dport 3128 -j ACCEPT
iptables -I INPUT -p tcp -m tcp --dport 8000 -j ACCEPT
iptables -I INPUT -p tcp -m tcp --dport 9090 -j ACCEPT
iptables -I INPUT -p tcp -m tcp --dport 8040 -j ACCEPT
iptables -I INPUT -p udp -m udp --dport 53 -j ACCEPT
clear
echo -----------------------------------------------------
echo Configuring Server and Squid conf
echo -----------------------------------------------------
sleep 2
touch /etc/openvpn/server1.conf
touch /etc/openvpn/server2.conf
sleep 1
echo 'http_port 8080
http_port 3128
http_port 9090
http_port 8000
acl to_vpn dst '$ip1'
http_access allow to_vpn 
via off
forwarded_for off
request_header_access Allow allow all
request_header_access Authorization allow all
request_header_access WWW-Authenticate allow all
request_header_access Proxy-Authorization allow all
request_header_access Proxy-Authenticate allow all
request_header_access Cache-Control allow all
request_header_access Content-Encoding allow all
request_header_access Content-Length allow all
request_header_access Content-Type allow all
request_header_access Date allow all
request_header_access Expires allow all
request_header_access Host allow all
request_header_access If-Modified-Since allow all
request_header_access Last-Modified allow all
request_header_access Location allow all
request_header_access Pragma allow all
request_header_access Accept allow all
request_header_access Accept-Charset allow all
request_header_access Accept-Encoding allow all
request_header_access Accept-Language allow all
request_header_access Content-Language allow all
request_header_access Mime-Version allow all
request_header_access Retry-After allow all
request_header_access Title allow all
request_header_access Connection allow all
request_header_access Proxy-Connection allow all
request_header_access User-Agent allow all
request_header_access Cookie allow all
request_header_access All deny all 
http_access deny all' > /etc/squid3/squid.conf
sleep 2
echo 'local '$ip1'
mode server 
tls-server 
port 1194 
proto tcp 
dev tun
keepalive 1 180
resolv-retry infinite 
max-clients 2000
ca /etc/openvpn/easy-rsa/keys/ca.crt 
cert /etc/openvpn/easy-rsa/keys/server.crt 
key /etc/openvpn/easy-rsa/keys/server.key 
dh /etc/openvpn/easy-rsa/keys/dh2048.pem 
client-cert-not-required 
username-as-common-name
client-connect /etc/openvpn/login/connect 
auth-user-pass-verify "/etc/openvpn/login/auth_vpn" via-file # 
tmp-dir "/etc/openvpn/" # 
server 172.20.0.0 255.255.248.0
push "redirect-gateway def1" 
push "dhcp-option DNS 8.8.8.8"
push "dhcp-option DNS 8.8.4.4"
push "sndbuf 393216"
push "rcvbuf 393216"
cipher AES-128-CBC
tcp-nodelay
tun-mtu 1400 
mssfix 1360
verb 3
script-security 2
status /var/www/html/status/tcp.txt
ifconfig-pool-persist /var/www/html/status/tcp-ipp.txt' > /etc/openvpn/server1.conf
echo 'local '$ip1'
mode server 
tls-server 
port 53 
proto udp 
dev tun
keepalive 1 180
resolv-retry infinite 
max-clients 2000
ca /etc/openvpn/easy-rsa/keys/ca.crt 
cert /etc/openvpn/easy-rsa/keys/server.crt 
key /etc/openvpn/easy-rsa/keys/server.key 
dh /etc/openvpn/easy-rsa/keys/dh2048.pem 
client-cert-not-required 
username-as-common-name
client-connect /etc/openvpn/login/connect 
auth-user-pass-verify "/etc/openvpn/login/auth_vpn" via-file # 
tmp-dir "/etc/openvpn/" # 
server 173.20.0.0 255.255.248.0
push "redirect-gateway def1" 
push "dhcp-option DNS 8.8.8.8"
push "dhcp-option DNS 8.8.4.4"
push "sndbuf 393216"
push "rcvbuf 393216"
cipher AES-128-CBC
tcp-nodelay
tun-mtu 1400 
mssfix 1360
verb 3
script-security 2
status /var/www/html/status/udp.txt
ifconfig-pool-persist /var/www/html/status/udp-ipp.txt' > /etc/openvpn/server2.conf
sleep 1
cd /etc/openvpn/
chmod 755 server1.conf
chmod 755 server2.conf
sleep 1
cd /etc/openvpn/login/
wget -q https://api.memorykey.net/fastnet/installer/auth_vpn
wget -q https://api.memorykey.net/fastnet/installer/connect
sleep 1
chmod 755 auth_vpn
chmod 755 connect
sleep 1
cd /etc/openvpn/easy-rsa/keys
wget -q https://api.memorykey.net/fastnet/installer/keys.zip
unzip keys.zip
clear
echo -----------------------------------------------------
echo Changing Apache Port
echo -----------------------------------------------------
sleep 2
sed -i 's/Listen 80/Listen 8040/g' /etc/apache2/ports.conf
service apache2 restart
clear
echo -----------------------------------------------------
echo Installing WS
echo -----------------------------------------------------
sleep 2
wget -q https://api.memorykey.net/fastnet/installer/socksws -O /etc/ubuntu
dos2unix /etc/ubuntu
sed -i 's/0.0.0.0/'$ip1'/g' /etc/ubuntu
chmod +x /etc/ubuntu    
screen -dmS socks python /etc/ubuntu
clear
echo -----------------------------------------------------
echo Modifying Permission
echo -----------------------------------------------------
sleep 2
sudo usermod -a -G www-data root
sudo chgrp -R www-data /var/www
sudo chmod -R g+w /var/www
clear
echo -----------------------------------------------------
echo Adding Cron File
echo -----------------------------------------------------
sleep 2
touch /usr/local/sbin/xFranz.sh
touch /usr/local/sbin/WS.sh
echo 'sudo sync; echo 3 > /proc/sys/vm/drop_caches
swapoff -a && swapon -a
' > /usr/local/sbin/xFranz.sh
echo '#!/bin/bash
screen -dmS socks python /etc/ubuntu
' > /usr/local/sbin/WS.sh
cd /usr/local/sbin/
chmod +x *
clear
echo -----------------------------------------------------
echo Adding Cron Settings
echo -----------------------------------------------------
sleep 2
(crontab -l 2>/dev/null || true; echo "#
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
* * * * * /usr/local/sbin/xFranz.sh
@reboot /usr/local/sbin/WS.sh") | crontab -
sleep 1
service cron restart
clear
echo -----------------------------------------------------
echo Configuring Fail2Ban
echo -----------------------------------------------------
sleep 3
sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
sed -i 's/bantime  = 600/bantime  = 3600/g' /etc/fail2ban/jail.local
sed -i 's/maxretry = 6/maxretry = 3/g' /etc/fail2ban/jail.local
clear
echo -----------------------------------------------------
echo Setting up Time Zone 
echo -----------------------------------------------------
sleep 2
sudo timedatectl set-timezone Asia/Dhaka
timedatectl
sleep 2
clear
echo -----------------------------------------------------
echo Saving Setup Rules
echo -----------------------------------------------------
sleep 2
sudo apt install debconf-utils -y
sleep 1
echo iptables-persistent iptables-persistent/autosave_v4 boolean true | sudo debconf-set-selections
echo iptables-persistent iptables-persistent/autosave_v6 boolean true | sudo debconf-set-selections
sudo apt-get install iptables-persistent -y
sleep 1
iptables-save > /etc/iptables/rules.v4 
ip6tables-save > /etc/iptables/rules.v6
clear
echo -----------------------------------------------------
echo Starting Services
echo -----------------------------------------------------
sleep 2
service openvpn start  > /dev/null
service squid3 start  > /dev/null
service apache2 start  > /dev/null
service fail2ban start  > /dev/null
service stunnel4 start  > /dev/null
clear
echo -----------------------------------------------------
echo Cleaning up
echo -----------------------------------------------------
sleep 2
sudo apt-get autoremove -y
sleep 1
sudo apt-get clean
history -c
clear
echo -----------------------------------------------------
echo "Installation is finish! Server Reboot in 5 seconds"
echo -----------------------------------------------------
echo "OPENVPN TCP port : 1194"
echo "OPENVPN UDP port : 53"
echo "OPENVPN SSL port : 443"
echo "OPENVPN WS port : 80"
echo "SQUID port : 3128, 8080, 8000, 9090"
sleep 3
cd /root
rm -rf *  > /dev/null
rm *  > /dev/null
reboot
