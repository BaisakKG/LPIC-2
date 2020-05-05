# System Security
## Настройка маршрутизации
```
ip -4 a s --- ip v4 all show
ip r s --- ip route show
/proc/sys/net/ipv4/
/proc/sys/net/ipv6/

ip r a 192.168.59.0/24 via 192.168.60.253
```
* Настраиваем форвард пакетов
```
sysctl -a
sysctl -w net.ipv4.ip_forward=1
OR
nano /etc/sysctl.conf
	net.ipv4.ip_forward=1
sysctl -p
```
* Настраиваем постоянный маршрутизации
```
nano /etc/network/interface
	up ip route replace 192.168.59.0/24 via 192.168.60.253
systemctl restart networking
```
## NAT iptables
```
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE #натирование исходящих пакетов

ss -ltu #show listen ports tcp udp
yum install w3m #console browser

ip route del 192.168.59.0/24

iptables -t nat -A PREROUTING -i eth0 -p tcp -m tcp --dport 80 -j DNAT --to 10.24.69.17:80 #перенаправление входящего пакета 
```
## Firewall Rules
```
iptables -L
iptables -t filter -L
iptables -t nat -nvL

iptables -F # удаляет все правила
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 22 -j ACCEPT
iptables -I INPUT 1 -m state --state ESTABLISHED,RELATED -j ACCEPT # разрешаем уже установленные соединения
iptables -I INPUT 1 -i lo -j ACCEPT # обычно нужно для почтовых серверов
iptables -A INPUT -j DROP

iptables-save > fw
iptables-restore < fw
OR
yum install iptables-persistent
```
## Fail2ban
```
grep -F sshd /var/log/auth.log

yum install fail2ban
nano /etc/fail2ban/jail.local
	[sshd]
	enabled = true
	port = ssh
	filter = sshd
	logpath = /var/log/auth.log
	maxretry = 3
	findtime = 300 (5 minutes)
	bantime = 86400 (1 day) # если в течении 5 минут будет 3 неудачной попытки залогинится с одного айпиадреса забанить на 1 день
	ignoreip = 127.0.0.1 # or which need
systemctl restart fail2ban
iptables -nL
fail2ban-client status sshd

fail2ban-client set sshd unbanip 192.168.2.5
```
## SSH
* Настройка клиента SSH
```
nano ~/.ssh/config
	Host *
		ServerAliveInterval 300 # проверяю каждые 5 минут что сервер отвечает
		ServerAliveCountMax 3 # указываем сколько ошибок можем получить передтем как сделать дроп
	Host w
		Hostname 192.168.195.27
		User root

#/etc/ssh/ssh_config(натсройки клиента) sshd_config(настройки сервера)

~/.ssh/known-hosts # когда мы подключаемся к другому серверу, публичный ключ того сервера заносится в этот файл у нас
grep -F StrictHostKeyChecking /etc/ssh/ssh_config
ssh -o StrictHostKeyChecking=no (yes, ask) 192.168.5.2 # не нужны предварительные общие ключи
ssh-keyscan <ip-address> | tee /etc/ssh/ssh_known_hosts
```
* Настройка сервера SSH
```
nano /etc/ssh/sshd_config	
	PermitRootLogin yes
systemctl restart sshd
ssh root@127.0.0.1
```
	* Теперь более безопасная настройка
	```
	nano /etc/ssh/sshd_config	
		PermitRootLogin no
		AllowUsers sbn bob
	systemctl restart sshd
	```
* Настройка доступа через ключи с отключением парольного доступа
```
nano /etc/ssh/sshd_config	
	PubkeyAuthentication yes
	PasswordAuthentication no
ssh-keygen -t rsa 
ssh-copy-id -i "~/.ssh/id_rsa.pub" sbn@192.168.2.5 # это добавить мой публичный ключ в тот сервер в ~/.ssh/authorized_keys
# чтобы каждый раз не вводить пароль моего закрытого ключа проходим аунтификацию в этой оболочке через закрытый ключ:
ssh-agent bash
ssh-add # и вводим пароль
```
## FTP
* Настройка файервола
```
modprobe ip_conntrack_ftp
iptables -I INPUT 6 -p tcp -m tcp --dport 21 -m conntrack --ctstate ESTABLISHED,NEW -j ACCEPT --- командный порт
iptables -I INPUT 7 -p tcp -m tcp --dport 20 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT --- порт данных
iptables -I INPUT 8 -p tcp -m tcp --dport 1024: --sport 1024: -m conntrack --ctstate ESTABLISHED -j ACCEPT --- для пасивных подключений	

iptables-save | tee /etc/iptables/rules.v4 --- чтобы сохранился после перезагрузки
```
* Установка Peru-FTP
```
ss -ntl --- номера портов, протокол тсп, лист, то что открыто
ss -4 state listening --- увидем прослушивающие порты
ss -4 state established --- увидем установленные

apt-get install -y pure-ftpd
cd /etc/pure-ftpd/conf/
cat NoAnonymous
	yes # значит не разрешаем анонимные подключения
nano IPV4Only
	yes
systemctl restart pure-ftpd

ftp 192.168.2.5 # подключаемся
```
* Установка vsftpd
```
apt-get install -y vsftpd
nano /etc/vsftpd.conf
	listen=YES
	listen_ipv6=NO
	local_enable=YES
grep ftp /etc/passwd # чтобы увидеть папку загрузки для анонимных, они будут использовать эту четку для подключения
```

## Monitoring Systems
* Port scaner nmap
```
namp -A scanme.nmap.org
nmap 192.168.195.0/24 
```
* Vulnerability scan OpenVAS
```
#Ubuntu
add-apt-repository ppa:mrazavi/openvas
apt install openvas 

#Centos 
sed -i 's/=enforcing/=disabled/' /etc/selinux/config
yum -y install wget rsync curl net-tools
wget -q -O - http://www.atomicorp.com/installers/atomic |sh
yum -y install openvas atomic-sqlite-sqlite
openvas-setup 
openvasmd --user=admin --new-password=MySecretPassword
###############
/usr/sbin/greenbone-nvt-sync
/usr/sbin/greenbone-certdata-sync
/usr/sbin/greenbone-scapdata-sync

systemctl enable redis
systemctl enable gsad
systemctl enable gvmd

systemctl enable openvas-manager && systemctl start openvas-manager
systemctl enable openvas-scanner && systemctl start openvas-scanner

https://ip-address

35 1 * * * /usr/sbin/greenbone-nvt-sync > /dev/null
5 0 * * * /usr/sbin/greenbone-scapdata-sync > /dev/null
5 1 * * * /usr/sbin/greenbone-certdata-sync > /dev/null
```

* Snort intruder detection system
```
apt install -y snort
#Настраиваем его на порт интернета

snort -V
less /etc/snort/rules/icmp.rules
nano /etc/snort/rules/local.rules
	aler icmp any any -> $HOME_NET any (msg: 'Ping'; sid: 10000001; rev:1;)
snort -A console -c /etc/snort/snort.conf -i enp0s8 
``` 
## VPN
```
apt install openvpn -y # устанавливаем в обоих серверах

openvpn --genkey --secret /etc/openvpn/secret.key 
scp /etc/openvpn/secret.key root@192.168.2.5:/etc/openvpn/secret.key
192.168.5.2
	chown root.root /etc/openvpn/secret.key
	chmod 600 /etc/openvpn/secret.key
nano /etc/openvpn/vpnserver.conf
	dev tun
	ifconfig 192.168.1.1 10.0.1.1
	keepalive 10 60
	ping-timer-rem
	persist-tun
	persist-key
	secret /etc/openvpn/secret.key
	
openvpn /etc/openvpn/vpnserver.conf
ip a s tun0 

192.168.5.2
	nano /etc/openvpn/client.conf
		remote <server-ip>
		dev tun
		ifconfig 10.0.1.1 192.168.1.1
		persist-tun
		persist-key
		secret /etc/openvpn/secret.key

	openvpn /etc/openvpn/client.conf
$? # последний аргумен
```
