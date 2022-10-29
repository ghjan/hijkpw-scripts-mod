#!/bin/bash

#Xray one click installation script

# Author: hijk<https://hijk.art>



RED="\033[31m"      # Error message

GREEN="\033[32m"    # Success message

YELLOW="\033[33m"   # Warning message

BLUE="\033[36m"     # Info message

PLAIN='\033[0m'


#The following websites are ad free novel websites randomly found on Google. If you don't like them, please change them to other websites, starting with http or https

#After setting up, the masquerade domain name cannot be opened. It may be that the anti generation novel website has hung up. Please leave a message on the website or Github issue an issue to replace the new website

SITES=(

http://www.zhuizishu.com/

http://xs.56dyc.com/

#http://www.xiaoshuosk.com/

#https://www.quledu.net/

http://www.ddxsku.com/

http://www.biqu6.com/

https://www.wenshulou.cc/

#http://www.auutea.com/

http://www.55shuba.com/

http://www.39shubao.com/

https://www.23xsw.cc/

#https://www.huanbige.com/

https://www.jueshitangmen.info/

https://www.zhetian.org/

http://www.bequgexs.com/

http://www.tjwl.com/

)


CONFIG_FILE="/usr/local/etc/xray/config.json"

OS=`hostnamectl | grep -i system | cut -d: -f2`


V6_PROXY=""

IP=`curl -sL -4 ip. sb`

if [[ "$?" != "0" ]]; then

IP=`curl -sL -6 ip. sb`

V6_PROXY=" https://gh.hijk.art/"

fi


BT="false"

NGINX_CONF_PATH="/etc/nginx/conf.d/"

res=`which bt 2>/dev/null`

if [[ "$res" != "" ]]; then

BT="true"

NGINX_CONF_PATH="/www/server/panel/vhost/nginx/"

fi


VLESS="false"

TROJAN="false"

TLS="false"

WS="false"

XTLS="false"

KCP="false"


checkSystem() {

result=$(id | awk '{print $1}')

if [[ $result != "uid=0(root)" ]]; then

ColorEcho $RED "Please execute the script as root"

exit 1

fi


res=`which yum 2>/dev/null`

if [[ "$?" != "0" ]]; then

res=`which apt 2>/dev/null`

if [[ "$?" != "0" ]]; then

ColorEcho $RED "Unsupported Linux system"

exit 1

fi

PMT="apt"

CMD_INSTALL="apt install -y "

CMD_REMOVE="apt remove -y "

CMD_UPGRADE="apt update; apt upgrade -y; apt autoremove -y"

else

PMT="yum"

CMD_INSTALL="yum install -y "

CMD_REMOVE="yum remove -y "

CMD_UPGRADE="yum update -y"

fi

res=`which systemctl 2>/dev/null`

if [[ "$?" != "0" ]]; then

ColorEcho $RED "The system version is too low, please upgrade to the latest version"

exit 1

fi

}


colorEcho() {

echo -e "${1}${@:2}${PLAIN}"

}


configNeedNginx() {

local ws=`grep wsSettings $CONFIG_FILE`

if [[ -z "$ws" ]]; then

echo no

return

fi

echo yes

}


needNginx() {

if [[ "$WS" = "false" ]]; then

echo no

return

fi

echo yes

}


status() {

if [[ ! -f /usr/local/bin/xray ]]; then

echo 0

return

fi

if [[ ! -f $CONFIG_FILE ]]; then

echo 1

return

fi

port=`grep port $CONFIG_FILE| head -n 1| cut -d: -f2| tr -d \",' '`

res=`ss -nutlp| grep ${port} | grep -i xray`

if [[ -z "$res" ]]; then

echo 2

return

fi


if [[ `configNeedNginx` != "yes" ]]; then

echo 3

else

res=`ss -nutlp|grep -i nginx`

if [[ -z "$res" ]]; then

echo 4

else

echo 5

fi

fi

}


statusText() {

res=`status`

case $res in

2)

Echo - e ${GREEN} installed ${PLAIN} ${RED} not running ${PLAIN}

;;

3)

Echo - e ${GREEN} is installed ${PLAIN} ${GREEN} Xray is running ${PLAIN}

;;

4)

Echo - e ${GREEN} Installed ${PLAIN} ${GREEN} Xray is running ${PLAIN}, ${RED} Nginx is not running ${PLAIN}

;;

5)

Echo - e ${GREEN} Installed ${PLAIN} ${GREEN} Xray is running, Nginx is running ${PLAIN}

;;

*)

Echo - e ${RED} is not installed ${PLAIN}

;;

esac

}


normalizeVersion() {

if [ -n "$1" ]; then

case "$1" in

v*)

echo "$1"

;;

http*)

echo "v1.4.2"

;;

*)

echo "v$1"

;;

esac

else

echo ""

fi

}


# 1: new Xray.










return 3

elif [[ $RETVAL -ne 0 ]]; then

return 2

elif [[ $NEW_VER != $CUR_VER ]]; then

return 1

fi

return 0

}


archAffix(){

case "$(uname -m)" in

i686|i386)

echo '32'

;;

x86_64|amd64)

echo '64'

;;

armv5tel)

echo 'arm32-v5'

;;

armv6l)

echo 'arm32-v6'

;;

armv7|armv7l)

echo 'arm32-v7a'

;;

armv8|aarch64)

echo 'arm64-v8a'

;;

mips64le)

echo 'mips64le'

;;

mips64)

echo 'mips64'

;;

mipsle)

echo 'mips32le'

;;

mips)

echo 'mips32'

;;

ppc64le)

echo 'ppc64le'

;;

ppc64)

echo 'ppc64'

;;

ppc64le)

echo 'ppc64le'

;;

riscv64)

echo 'riscv64'

;;

s390x)

echo 's390x'

;;

*)

ColorEcho $RED "Unsupported CPU architecture!"

exit 1

;;

esac


return 0

}


getData() {

if [[ "$TLS" = "true" || "$XTLS" = "true" ]]; then

echo ""

Echo "Before running the Xray one click script, please confirm that the following conditions have been met:"

ColorEcho ${YELLOW} "1. A fake domain name"

ColorEcho ${YELLOW} "2. The DNS resolution of the disguised domain name points to the current server ip (${IP})"

ColorEcho ${BLUE} "3. If there are xray.pem and xray.key certificate key files in the/root directory, ignore condition 2"

echo " "

Read - p "Press y to confirm the satisfaction, and press other buttons to exit the script:" answer

if [[ "${answer,,}" != "y" ]]; then

exit 0

fi


echo ""

while true

do

Read - p "Please enter the masquerade domain name:" DOMAIN

if [[ -z "${DOMAIN}" ]]; then

ColorEcho ${RED} "The domain name is entered incorrectly, please re-enter!"

else

break

fi

done

DOMAIN=${DOMAIN,,}

colorEcho ${BLUE} "Camouflage domain name (host): $DOMAIN"


echo ""

if [[ -f ~/xray.pem && -f ~/xray.key ]]; then

ColorEcho ${BLUE} "Self owned certificate is detected and will be used for deployment"

CERT_FILE="/usr/local/etc/xray/${DOMAIN}.pem"

KEY_FILE="/usr/local/etc/xray/${DOMAIN}.key"

else

resolve=`curl -sL http://ip-api.com/json/${DOMAIN}`

res=`echo -n ${resolve} | grep ${IP}`

if [[ -z "${res}" ]]; then

colorEcho ${BLUE} "${DOMAIN} parsing result: ${resolve}"

ColorEcho ${RED} "The domain name has not been resolved to the current server IP (${IP})!"

exit 1

fi

fi

fi


echo ""

if [[ "$(needNginx)" = "no" ]]; then

if [[ "$TLS" = "true" ]]; then

Read - p "Please enter the xray listening port [443 is strongly recommended, default 443]:" PORT

[[ -z "${PORT}" ]] && PORT=443

else

Read - p "Please enter the xray listening port [a number of 100-65535]:" PORT

[[ -z "${PORT}" ]] && PORT=`shuf -i200-65000 -n1`

if [[ "${PORT:0:1}" = "0" ]]; then

ColorEcho ${RED} "Port cannot start with 0"

exit 1

fi

fi

ColorEcho ${BLUE} "xray port: $PORT"

else

Read - p "Please enter a number of Nginx listening ports [100-65535, default 443]:" PORT

[[ -z "${PORT}" ]] && PORT=443

if [ "${PORT:0:1}" = "0" ]; then

ColorEcho ${BLUE} "Port cannot start with 0"

exit 1

fi

ColorEcho ${BLUE} "Nginx port: $PORT"

XPORT=`shuf -i10000-65000 -n1`

fi


if [[ "$KCP" = "true" ]]; then

echo ""

ColorEcho $BLUE "Please select the camouflage type:"

Echo "1) None"

Echo "2) BT download"

Echo "3) Video call"

Echo "4) WeChat video call"

echo "   5) dtls"

echo "   6) wiregard"

Read - p "Please select the camouflage type [default: none]:" answer

case $answer in

2)

HEADER_TYPE="utp"

;;

3)

HEADER_TYPE="srtp"

;;

4)

HEADER_TYPE="wechat-video"

;;

5)

HEADER_TYPE="dtls"

;;

6)

HEADER_TYPE="wireguard"

;;

*)

HEADER_TYPE="none"

;;

esac

ColorEcho $BLUE "Camouflage type: $HEADER_TYPE"

SEED=`cat /proc/sys/kernel/random/uuid`

fi


if [[ "$TROJAN" = "true" ]]; then

echo ""

Read - p "Please set trojan password (randomly generated if not entered):" PASSWORD

[[ -z "$PASSWORD" ]] && PASSWORD=`cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 16 | head -n 1`

ColorEcho $BLUE "trojan password: $PASSWORD"

fi


if [[ "$XTLS" = "true" ]]; then

echo ""

ColorEcho $BLUE "Please select the flow control mode:"

Echo - e "1) xtls rprx direct [$RED recommended $PLAIN]"

echo "   2) xtls-rprx-origin"

Read - p "Please select flow control mode [default: direct]" answer

[[ -z "$answer" ]] && answer=1

case $answer in

1)

FLOW="xtls-rprx-direct"

;;

2)

FLOW="xtls-rprx-origin"

;;

*)

ColorEcho $RED "Invalid option, use the default xtls rprx direct"

FLOW="xtls-rprx-direct"

;;

esac

ColorEcho $BLUE "Flow control mode: $FLOW"

fi


if [[ "${WS}" = "true" ]]; then

echo ""

while true

do

Read - p "Please enter the camouflage path starting with/(please enter directly if you don't understand):" WSPATH

if [[ -z "${WSPATH}" ]]; then

len=`shuf -i5-12 -n1`

ws=`cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w $len | head -n 1`

WSPATH="/$ws"

break

elif [[ "${WSPATH:0:1}" != "/" ]]; then

ColorEcho ${RED} "The camouflage path must start with/!"

elif [[ "${WSPATH}" = "/" ]]; then

ColorEcho ${RED} "Cannot use root path!"

else

break

fi

done

ColorEcho ${BLUE} "ws path: $WSPATH"

fi


if [[ "$TLS" = "true" || "$XTLS" = "true" ]]; then

echo ""

ColorEcho $BLUE "Please select the camouflage station type:"

Echo "1) Static website (located in/usr/share/nginx/html)"

Echo "2) Fiction station (random selection)"

echo "3) Beauty Station（https://imeizi.me)"

Echo "4) High definition wallpaper station（https://bing.imeizi.me)"

Echo "5) Customized anti proxy sites (start with http or https)"

Read - p "Please select the type of camouflage website [Default: HD wallpaper station]" answer

if [[ -z "$answer" ]]; then

PROXY_URL=" https://bing.imeizi.me"

else

case $answer in

1)

PROXY_URL=""

;;

2)

len=${#SITES[@]}

((len--))

while true

do

index=`shuf -i0-${len} -n1`

PROXY_URL=${SITES[$index]}

host=`echo ${PROXY_URL} | cut -d/ -f3`

ip=`curl -sL http://ip-api.com/json/${host}`

res=`echo -n ${ip} | grep ${host}`

if [[ "${res}" = "" ]]; then

echo "$ip $host" >> /etc/hosts

break

fi

done

;;

3)

PROXY_URL=" https://imeizi.me"

;;

4)

PROXY_URL=" https://bing.imeizi.me"

;;

5)

Read - p "Please enter the reverse generation site (starting with http or https):" PROXY_URL

if [[ -z "$PROXY_URL" ]]; then

ColorEcho $RED "Please enter the reverse website!"

exit 1

elif [[ "${PROXY_URL:0:4}" != "http" ]]; then

ColorEcho $RED "The anti proxy website must start with http or https!"

exit 1

fi

;;

*)

ColorEcho $RED "Please enter the correct option!"

exit 1

esac

fi

REMOTE_HOST=`echo ${PROXY_URL} | cut -d/ -f3`

ColorEcho $BLUE "Camouflage website: $PROXY_URL"


echo ""

ColorEcho $BLUE "Do you want to allow search engines to crawl websites? [Default: Not allowed]"

Echo "y) Yes, there will be more IP requests for websites, but some traffic will be consumed. It is recommended when the vps traffic is sufficient"

Echo "n) Not allowed. The crawler will not visit the website. The access IP is relatively simple, but it can save vps traffic."

Read - p "Please select: [y/n]" answer

if [[ -z "$answer" ]]; then

ALLOW_SPIDER="n"

elif [[ "${answer,,}" = "y" ]]; then

ALLOW_SPIDER="y"

else

ALLOW_SPIDER="n"

fi

ColorEcho $BLUE "Allow search engines: $ALLOW_SPIDER"

fi


echo ""

Read - p "Do you want to install BBR (default installation)? [y/n]:" NEED_BBR

[[ -z "$NEED_BBR" ]] && NEED_BBR=y

[[ "$NEED_BBR" = "Y" ]] && NEED_BBR=y

ColorEcho $BLUE "Installing BBR: $NEED_BBR"

}


installNginx() {

echo ""

ColorEcho $BLUE "Install nginx..."

if [[ "$BT" = "false" ]]; then

if [[ "$PMT" = "yum" ]]; then

$CMD_INSTALL epel-release

if [[ "$?" != "0" ]]; then

echo '[nginx-stable]

name=nginx stable repo

baseurl=http://nginx.org/packages/centos/$releasever/$basearch/

gpgcheck=1

enabled=1

gpgkey=https://nginx.org/keys/nginx_signing.key

module_hotfixes=true' > /etc/yum. repos. d/nginx. repo

fi

fi

$CMD_INSTALL nginx

if [[ "$?" != "0" ]]; then

ColorEcho $RED "Nginx installation failed, please go tohttps://hijk.artFeedback“

exit 1

fi

systemctl enable nginx

else

res=`which nginx 2>/dev/null`

if [[ "$?" != "0" ]]; then

ColorEcho $RED "You have installed the pagoda, please run this script after installing nginx in the pagoda background"

exit 1

fi

fi

}


startNginx() {

if [[ "$BT" = "false" ]]; then

systemctl start nginx

else

nginx -c /www/server/nginx/conf/nginx. conf

fi

}


stopNginx() {

if [[ "$BT" = "false" ]]; then

systemctl stop nginx

else

res=`ps aux | grep -i nginx`

if [[ "$res" != "" ]]; then

nginx -s stop

fi

fi

}


getCert() {

mkdir -p /usr/local/etc/xray

if [[ -z ${CERT_FILE+x} ]]; then

stopNginx

systemctl stop xray

res=`netstat -ntlp| grep -E ':80 |:443 '`

if [[ "${res}" != "" ]]; then

ColorEcho ${RED} "Other processes occupy port 80 or 443, please close it first and then run the one click script"

Echo "The port usage information is as follows:"

echo ${res}

exit 1

fi


$CMD_INSTALL socat openssl

if [[ "$PMT" = "yum" ]]; then

$CMD_INSTALL cronie

systemctl start crond

systemctl enable crond

else

$CMD_INSTALL cron

systemctl start cron

systemctl enable cron

fi

curl -sL https://get.acme.sh| sh -s email=hijk. pw@protonmail.sh

source ~/. bashrc

~/. acme. sh/acme. sh  --upgrade  --auto-upgrade

~/. acme. sh/acme. sh --set-default-ca --server letsencrypt

if [[ "$BT" = "false" ]]; then

~/. acme. sh/acme. sh   --issue -d $DOMAIN --keylength ec-256 --pre-hook "systemctl stop nginx" --post-hook "systemctl restart nginx"  --standalone

else

~/. acme. sh/acme. sh   --issue -d $DOMAIN --keylength ec-256 --pre-hook "nginx -s stop || { echo -n ''; }" --post-hook "nginx -c /www/server/nginx/conf/nginx.conf || { echo -n ''; }"  --standalone

fi

[[ -f ~/.acme.sh/${DOMAIN}_ecc/ca.cer ]] || {

ColorEcho $RED "Failed to obtain the certificate, please copy the above red text tohttps://hijk.artFeedback“

exit 1

}

CERT_FILE="/usr/local/etc/xray/${DOMAIN}.pem"

KEY_FILE="/usr/local/etc/xray/${DOMAIN}.key"

~/. acme. sh/acme. sh  --install-cert -d $DOMAIN --ecc \

--key-file       $KEY_FILE  \

--fullchain-file $CERT_FILE \

--reloadcmd     "service nginx force-reload"

[[ -f $CERT_FILE && -f $KEY_FILE ]] || {

ColorEcho $RED "Failed to obtain the certificate, please go tohttps://hijk.artFeedback“

exit 1

}

else

cp ~/xray. pem /usr/local/etc/xray/${DOMAIN}. pem

cp ~/xray. key /usr/local/etc/xray/${DOMAIN}. key

fi

}


configNginx() {

mkdir -p /usr/share/nginx/html;

if [[ "$ALLOW_SPIDER" = "n" ]]; then

echo 'User-Agent: *' > /usr/share/nginx/html/robots. txt

echo 'Disallow: /' >> /usr/share/nginx/html/robots. txt

ROBOT_CONFIG="    location = /robots.txt {}"

else

ROBOT_CONFIG=""

fi


if [[ "$BT" = "false" ]]; then

if [[ ! -f /etc/nginx/nginx.conf.bak ]]; then

mv /etc/nginx/nginx. conf /etc/nginx/nginx. conf.bak

fi

res=`id nginx 2>/dev/null`

if [[ "$?" != "0" ]]; then

user="www-data"

else

user="nginx"

fi

cat > /etc/nginx/nginx. conf<<-EOF

user $user;

worker_processes auto;

error_log /var/log/nginx/error. log;

pid /run/nginx. pid;


# Load dynamic modules. See /usr/share/doc/nginx/README. dynamic.

include /usr/share/nginx/modules/*. conf;


events {

worker_connections 1024;

}


http {

log_format  main  '\$remote_addr - \$remote_user [\$time_local] "\$request" '

'\$status \$body_bytes_sent "\$http_referer" '

'"\$http_user_agent" "\$http_x_forwarded_for"';


access_log  /var/log/nginx/access. log  main;

server_tokens off;


sendfile            on;

tcp_nopush          on;

tcp_nodelay         on;

keepalive_timeout   65;

types_hash_max_size 2048;

gzip                on;


include             /etc/nginx/mime. types;

default_type        application/octet-stream;


# Load modular configuration files from the /etc/nginx/conf. d directory.

# See http://nginx.org/en/docs/ngx_core_module.html#include

# for more information.

include /etc/nginx/conf.d/*. conf;

}






















































































































































































































































































































































































































































































































































































































































































"seed": "$SEED"

}

}

}

}],

"outbounds": [{

"protocol": "freedom",

"settings": {}

},{

"protocol": "blackhole",

"settings": {},

"tag": "blocked"

}]

}

EOF

}


configXray() {

mkdir -p /usr/local/xray

if [[ "$TROJAN" = "true" ]]; then

if [[ "$XTLS" = "true" ]]; then

trojanXTLSConfig

else

trojanConfig

fi

return 0

fi

if [[ "$VLESS" = "false" ]]; then

# VMESS + kcp

if [[ "$KCP" = "true" ]]; then

vmessKCPConfig

return 0

fi

# VMESS

if [[ "$TLS" = "false" ]]; then

vmessConfig

elif [[ "$WS" = "false" ]]; then

# VMESS+TCP+TLS

vmessTLSConfig

# VMESS+WS+TLS

else

vmessWSConfig

fi

#VLESS

else

if [[ "$KCP" = "true" ]]; then

vlessKCPConfig

return 0

fi

# VLESS+TCP

if [[ "$WS" = "false" ]]; then

# VLESS+TCP+TLS

if [[ "$XTLS" = "false" ]]; then

vlessTLSConfig

# VLESS+TCP+XTLS

else

vlessXTLSConfig

fi

# VLESS+WS+TLS

else

vlessWSConfig

fi

fi

}


install() {

getData


$PMT clean all

[[ "$PMT" = "apt" ]] && $PMT update

#echo $CMD_UPGRADE | bash

$CMD_INSTALL wget vim unzip tar gcc openssl

$CMD_INSTALL net-tools

if [[ "$PMT" = "apt" ]]; then

$CMD_INSTALL libssl-dev g++

fi

res=`which unzip 2>/dev/null`

if [[ $? -ne 0 ]]; then

ColorEcho $RED "unzip installation failed, please check the network"

exit 1

fi


installNginx

setFirewall

if [[ "$TLS" = "true" || "$XTLS" = "true" ]]; then

getCert

fi

configNginx


ColorEcho $BLUE "Install Xray..."

getVersion

RETVAL="$?"

if [[ $RETVAL == 0 ]]; then

ColorEcho $BLUE "The latest version of Xray ${CUR_VER} has been installed"

elif [[ $RETVAL == 3 ]]; then

exit 1

else

ColorEcho $BLUE "Install Xray ${NEW_VER}, schema $(archAffix)"

installXray

fi


configXray


setSelinux

installBBR


start

showInfo


bbrReboot

}


bbrReboot() {

if [[ "${INSTALL_BBR}" == "true" ]]; then

echo

Echo "To make the BBR module take effect, the system will restart in 30 seconds"

echo

Echo - e "You can press ctrl+c to cancel the restart, and then enter ${RED} reboot ${PLAIN} to restart the system"

sleep 30

reboot

fi

}


update() {

res=`status`

if [[ $res -lt 2 ]]; then

ColorEcho $RED "Xray is not installed, please install it first!"

return

fi


getVersion

RETVAL="$?"

if [[ $RETVAL == 0 ]]; then

ColorEcho $BLUE "The latest version of Xray ${CUR_VER} has been installed"

elif [[ $RETVAL == 3 ]]; then

exit 1

else

ColorEcho $BLUE "Install Xray ${NEW_VER}, schema $(archAffix)"

installXray

stop

start


ColorEcho $GREEN "The latest version of Xray was installed successfully!"

fi

}


uninstall() {

res=`status`

if [[ $res -lt 2 ]]; then

ColorEcho $RED "Xray is not installed, please install it first!"

return

fi


echo ""

read - p "Are you sure to uninstall Xray? [y/n]:" answer

if [[ "${answer,,}" = "y" ]]; then

domain=`grep Host $CONFIG_FILE | cut -d: -f2 | tr -d \",' '`

if [[ "$domain" = "" ]]; then

domain=`grep serverName $CONFIG_FILE | cut -d: -f2 | tr -d \",' '`

fi


stop

systemctl disable xray

rm -rf /etc/systemd/system/xray. service

rm -rf /usr/local/bin/xray

rm -rf /usr/local/etc/xray


if [[ "$BT" = "false" ]]; then

systemctl disable nginx

$CMD_REMOVE nginx

if [[ "$PMT" = "apt" ]]; then

$CMD_REMOVE nginx-common

fi

rm -rf /etc/nginx/nginx. conf

if [[ -f /etc/nginx/nginx.conf.bak ]]; then

mv /etc/nginx/nginx. conf.bak /etc/nginx/nginx. conf

fi

fi

if [[ "$domain" != "" ]]; then

rm -rf ${NGINX_CONF_PATH}${domain}. conf

fi

[[ -f ~/.acme.sh/acme.sh ]] && ~/. acme. sh/acme. sh --uninstall

ColorEcho $GREEN "Xray uninstalled successfully"

fi

}


start() {

res=`status`

if [[ $res -lt 2 ]]; then

ColorEcho $RED "Xray is not installed, please install it first!"

return

fi

stopNginx

startNginx

systemctl restart xray

sleep 2


port=`grep port $CONFIG_FILE| head -n 1| cut -d: -f2| tr -d \",' '`

res=`ss -nutlp| grep ${port} | grep -i xray`

if [[ "$res" = "" ]]; then

ColorEcho $RED "Xray failed to start, please check the log or check whether the port is occupied!"

else

ColorEcho $BLUE "Xray started successfully"

fi

}


stop() {

stopNginx

systemctl stop xray

ColorEcho $BLUE "Xray stopped successfully"

}



restart() {

res=`status`

if [[ $res -lt 2 ]]; then

ColorEcho $RED "Xray is not installed, please install it first!"

return

fi


stop

start

}



getConfigFileInfo() {

vless="false"

tls="false"

ws="false"

xtls="false"

trojan="false"

protocol="VMess"

kcp="false"


uid=`grep id $CONFIG_FILE | head -n1| cut -d: -f2 | tr -d \",' '`

alterid=`grep alterId $CONFIG_FILE  | cut -d: -f2 | tr -d \",' '`

network=`grep network $CONFIG_FILE  | tail -n1| cut -d: -f2 | tr -d \",' '`

[[ -z "$network" ]] && network="tcp"

domain=`grep serverName $CONFIG_FILE | cut -d: -f2 | tr -d \",' '`

if [[ "$domain" = "" ]]; then

domain=`grep Host $CONFIG_FILE | cut -d: -f2 | tr -d \",' '`

if [[ "$domain" != "" ]]; then

ws="true"

tls="true"

wspath=`grep path $CONFIG_FILE | cut -d: -f2 | tr -d \",' '`

fi

else

tls="true"

fi

if [[ "$ws" = "true" ]]; then

port=`grep -i ssl $NGINX_CONF_PATH${domain}. conf| head -n1 | awk '{print $2}'`

else

port=`grep port $CONFIG_FILE | cut -d: -f2 | tr -d \",' '`

fi

res=`grep -i kcp $CONFIG_FILE`

if [[ "$res" != "" ]]; then

kcp="true"

type=`grep header -A 3 $CONFIG_FILE | grep 'type' | cut -d: -f2 | tr -d \",' '`

seed=`grep seed $CONFIG_FILE | cut -d: -f2 | tr -d \",' '`

fi


vmess=`grep vmess $CONFIG_FILE`

if [[ "$vmess" = "" ]]; then

trojan=`grep trojan $CONFIG_FILE`

if [[ "$trojan" = "" ]]; then

vless="true"

protocol="VLESS"

else

trojan="true"

password=`grep password $CONFIG_FILE | cut -d: -f2 | tr -d \",' '`

protocol="trojan"

fi

tls="true"

encryption="none"

xtls=`grep xtlsSettings $CONFIG_FILE`

if [[ "$xtls" != "" ]]; then

xtls="true"

flow=`grep flow $CONFIG_FILE | cut -d: -f2 | tr -d \",' '`

else

Flow="None"

fi

fi

}


outputVmess() {

raw="{

\"v\":\"2\",

\"ps\":\"\",

\"add\":\"$IP\",

\"port\":\"${port}\",

\"id\":\"${uid}\",

\"aid\":\"$alterid\",

\"net\":\"tcp\",

\"type\":\"none\",

\"host\":\"\",

\"path\":\"\",

\"tls\":\"\"

}"

link=`echo -n ${raw} | base64 -w 0`

link="vmess://${link}"


echo -e "   ${BLUE}IP(address): ${PLAIN} ${RED}${IP}${PLAIN}"

Echo - e "${BLUE} port: ${PLAIN} ${RED} ${port} ${PLAIN}"

echo -e "   ${BLUE}id(uuid)：${PLAIN}${RED}${uid}${PLAIN}"

Echo - e "${BLUE} extra id (alter id): ${PLAIN} ${RED} ${alter id} ${PLAIN}"

Echo - e "${BLUE} encryption method (security): ${PLAIN} ${RED} auto ${PLAIN}"

Echo - e "${BLUE} transport protocol (network): ${PLAIN} ${RED} ${network} ${PLAIN}"

echo

Echo - e "${BLUE} vmess link: ${PLAIN} $RED $link $PLAIN"

}


outputVmessKCP() {

echo -e "   ${BLUE}IP(address): ${PLAIN} ${RED}${IP}${PLAIN}"

Echo - e "${BLUE} port: ${PLAIN} ${RED} ${port} ${PLAIN}"

echo -e "   ${BLUE}id(uuid)：${PLAIN}${RED}${uid}${PLAIN}"

Echo - e "${BLUE} extra id (alter id): ${PLAIN} ${RED} ${alter id} ${PLAIN}"

Echo - e "${BLUE} encryption method (security): ${PLAIN} ${RED} auto ${PLAIN}"

Echo - e "${BLUE} transport protocol (network): ${PLAIN} ${RED} ${network} ${PLAIN}"

Echo - e "${BLUE} camouflage type (type): ${PLAIN} ${RED} ${type} ${PLAIN}"

echo -e "   ${BLUE}mkcp seed：${PLAIN} ${RED}${seed}${PLAIN}"

}


outputTrojan() {

if [[ "$xtls" = "true" ]]; then

Echo - e "${BLUE} IP/domain name (address): ${PLAIN} ${RED} ${domain} ${PLAIN}"

Echo - e "${BLUE} port: ${PLAIN} ${RED} ${port} ${PLAIN}"

Echo - e "${BLUE} password: ${PLAIN} ${RED} ${password} ${PLAIN}"

Echo - e "${BLUE} flow control (flow): ${PLAIN} $RED $flow ${PLAIN}"

Echo - e "${BLUE} encryption: ${PLAIN} ${RED} none ${PLAIN}"

Echo - e "${BLUE} transport protocol (network): ${PLAIN} ${RED} ${network} ${PLAIN}"

Echo - e "${BLUE} underlying secure transport (tls): ${PLAIN} ${RED} XTLS ${PLAIN}"

else

Echo - e "${BLUE} IP/domain name (address): ${PLAIN} ${RED} ${domain} ${PLAIN}"

Echo - e "${BLUE} port: ${PLAIN} ${RED} ${port} ${PLAIN}"

Echo - e "${BLUE} password: ${PLAIN} ${RED} ${password} ${PLAIN}"

Echo - e "${BLUE} transport protocol (network): ${PLAIN} ${RED} ${network} ${PLAIN}"

Echo - e "${BLUE} Low Level Secure Transport (tls): ${PLAIN} ${RED} TLS ${PLAIN}"

fi














\"path\":\"\",

\"tls\":\"tls\"

}"

link=`echo -n ${raw} | base64 -w 0`

link="vmess://${link}"

echo -e "   ${BLUE}IP(address): ${PLAIN} ${RED}${IP}${PLAIN}"

Echo - e "${BLUE} port: ${PLAIN} ${RED} ${port} ${PLAIN}"

echo -e "   ${BLUE}id(uuid)：${PLAIN}${RED}${uid}${PLAIN}"

Echo - e "${BLUE} extra id (alter id): ${PLAIN} ${RED} ${alter id} ${PLAIN}"

Echo - e "${BLUE} encryption method (security): ${PLAIN} ${RED} none ${PLAIN}"

Echo - e "${BLUE} transport protocol (network): ${PLAIN} ${RED} ${network} ${PLAIN}"

echo - e "${BLUE} disguise domain name/host name/SNI/peer name: ${PLAIN} ${RED} ${domain} ${PLAIN}"

Echo - e "${BLUE} Low Level Secure Transport (tls): ${PLAIN} ${RED} TLS ${PLAIN}"

echo

Echo - e "${BLUE} vmess link: ${PLAIN} $RED $link $PLAIN"

}


outputVmessWS() {

raw="{

\"v\":\"2\",

\"ps\":\"\",

\"add\":\"$IP\",

\"port\":\"${port}\",

\"id\":\"${uid}\",

\"aid\":\"$alterid\",

\"net\":\"${network}\",

\"type\":\"none\",

\"host\":\"${domain}\",

\"path\":\"${wspath}\",

\"tls\":\"tls\"

}"

link=`echo -n ${raw} | base64 -w 0`

link="vmess://${link}"


echo -e "   ${BLUE}IP(address): ${PLAIN} ${RED}${IP}${PLAIN}"

Echo - e "${BLUE} port: ${PLAIN} ${RED} ${port} ${PLAIN}"

echo -e "   ${BLUE}id(uuid)：${PLAIN}${RED}${uid}${PLAIN}"

Echo - e "${BLUE} extra id (alter id): ${PLAIN} ${RED} ${alter id} ${PLAIN}"

Echo - e "${BLUE} encryption method (security): ${PLAIN} ${RED} none ${PLAIN}"

Echo - e "${BLUE} transport protocol (network): ${PLAIN} ${RED} ${network} ${PLAIN}"

Echo - e "${BLUE} camouflage type (type): ${PLAIN} ${RED} none $PLAIN"

echo - e "${BLUE} disguise domain name/host name/SNI/peer name: ${PLAIN} ${RED} ${domain} ${PLAIN}"

Echo - e "${BLUE} path: ${PLAIN} ${RED} ${wspath} ${PLAIN}"

Echo - e "${BLUE} Low Level Secure Transport (tls): ${PLAIN} ${RED} TLS ${PLAIN}"

echo

Echo - e "${BLUE} vmess link: ${PLAIN} $RED $link $PLAIN"

}


showInfo() {

res=`status`

if [[ $res -lt 2 ]]; then

ColorEcho $RED "Xray is not installed, please install it first!"

return

fi


echo ""

Echo - n - e "${BLUE} Xray running status: ${PLAIN}"

statusText

Echo - e "${BLUE} Xray configuration file: ${PLAIN} ${RED} ${CONFIG_FILE} ${PLAIN}"

colorEcho $BLUE "Xray configuration information:"


getConfigFileInfo


echo - e "${BLUE} protocol: ${PLAIN} ${RED} ${protocol} ${PLAIN}"

if [[ "$trojan" = "true" ]]; then

outputTrojan

return 0

fi

if [[ "$vless" = "false" ]]; then

if [[ "$kcp" = "true" ]]; then

outputVmessKCP

return 0

fi

if [[ "$tls" = "false" ]]; then

outputVmess

elif [[ "$ws" = "false" ]]; then

outputVmessTLS

else

outputVmessWS

fi

else

if [[ "$kcp" = "true" ]]; then

echo -e "   ${BLUE}IP(address): ${PLAIN} ${RED}${IP}${PLAIN}"

Echo - e "${BLUE} port: ${PLAIN} ${RED} ${port} ${PLAIN}"

echo -e "   ${BLUE}id(uuid)：${PLAIN}${RED}${uid}${PLAIN}"

Echo - e "${BLUE} encryption: ${PLAIN} ${RED} none ${PLAIN}"

Echo - e "${BLUE} transport protocol (network): ${PLAIN} ${RED} ${network} ${PLAIN}"

Echo - e "${BLUE} camouflage type (type): ${PLAIN} ${RED} ${type} ${PLAIN}"

echo -e "   ${BLUE}mkcp seed：${PLAIN} ${RED}${seed}${PLAIN}"

return 0

fi

if [[ "$xtls" = "true" ]]; then

echo -e " ${BLUE}IP(address): ${PLAIN} ${RED}${IP}${PLAIN}"

Echo - e "${BLUE} port: ${PLAIN} ${RED} ${port} ${PLAIN}"

echo -e " ${BLUE}id(uuid)：${PLAIN}${RED}${uid}${PLAIN}"

Echo - e "${BLUE} flow control (flow): ${PLAIN} $RED $flow ${PLAIN}"

Echo - e "${BLUE} encryption: ${PLAIN} ${RED} none ${PLAIN}"

Echo - e "${BLUE} transport protocol (network): ${PLAIN} ${RED} ${network} ${PLAIN}"

Echo - e "${BLUE} camouflage type (type): ${PLAIN} ${RED} none $PLAIN"

Echo - e "${BLUE} disguise domain name/host name/SNI/peer name: ${PLAIN} ${RED} ${domain} ${PLAIN}"

Echo - e "${BLUE} underlying secure transport (tls): ${PLAIN} ${RED} XTLS ${PLAIN}"

elif [[ "$ws" = "false" ]]; then

echo -e " ${BLUE}IP(address):  ${PLAIN}${RED}${IP}${PLAIN}"

Echo - e "${BLUE} port: ${PLAIN} ${RED} ${port} ${PLAIN}"

echo -e " ${BLUE}id(uuid)：${PLAIN}${RED}${uid}${PLAIN}"

Echo - e "${BLUE} flow control (flow): ${PLAIN} $RED $flow ${PLAIN}"

Echo - e "${BLUE} encryption: ${PLAIN} ${RED} none ${PLAIN}"

Echo - e "${BLUE} transport protocol (network): ${PLAIN} ${RED} ${network} ${PLAIN}"

Echo - e "${BLUE} camouflage type (type): ${PLAIN} ${RED} none $PLAIN"

Echo - e "${BLUE} disguise domain name/host name/SNI/peer name: ${PLAIN} ${RED} ${domain} ${PLAIN}"

Echo - e "${BLUE} Low Level Secure Transport (tls): ${PLAIN} ${RED} TLS ${PLAIN}"

else

echo -e " ${BLUE}IP(address): ${PLAIN} ${RED}${IP}${PLAIN}"

echo - e "${BLUE} port: ${PLAIN} ${RED} ${port} ${PLAIN}"

echo -e " ${BLUE}id(uuid)：${PLAIN}${RED}${uid}${PLAIN}"

Echo - e "${BLUE} flow control (flow): ${PLAIN} $RED $flow ${PLAIN}"

Echo - e "${BLUE} encryption: ${PLAIN} ${RED} none ${PLAIN}"

Echo - e "${BLUE} transport protocol (network): ${PLAIN} ${RED} ${network} ${PLAIN}"

Echo - e "${BLUE} camouflage type (type): ${PLAIN} ${RED} none $PLAIN"

Echo - e "${BLUE} disguise domain name/host name/SNI/peer name: ${PLAIN} ${RED} ${domain} ${PLAIN}"

Echo - e "${BLUE} path: ${PLAIN} ${RED} ${wspath} ${PLAIN}"

Echo - e "${BLUE} Low Level Secure Transport (tls): ${PLAIN} ${RED} TLS ${PLAIN}"

fi

fi

}


showLog() {

res=`status`

if [[ $res -lt 2 ]]; then

ColorEcho $RED "Xray is not installed, please install it first!"

return

fi


journalctl -xen -u xray --no-pager

}


menu() {

clear

echo "#############################################################"

Echo - e "# ${RED} Xray one key installation script ${PLAIN} #"

Echo - e "# ${GREEN} Author ${PLAIN}: Network Jump (hijk) #"

Echo - e "# ${GREEN} URL ${PLAIN}: https://hijk.art#"

Echo - e "# ${GREEN} Forum ${PLAIN}: https://hijk.club#"

Echo - e "# ${GREEN} TG group ${PLAIN}: https://t.me/hijkclub#"

Echo - e "# ${GREEN} YouTube channel ${PLAIN}: https://youtube.com/channel/UCYTB--VsObzepVJtc9yvUxQ#"

echo "#############################################################"

Echo - e "${GREEN} 1. ${PLAIN} Install Xray VMESS"

Echo - e "${GREEN} 2. ${PLAIN} Install Xray - ${BLUE} VMESS+mKCP ${PLAIN}"

Echo - e "${GREEN} 3. ${PLAIN} Install Xray VMESS+TCP+TLS"

Echo - e "${GREEN} 4. ${PLAIN} Install Xray - ${BLUE} VMESS+WS+TLS ${PLAIN} ${RED} (Recommended) ${PLAIN}"

Echo - e "${GREEN} 5. ${PLAIN} Install Xray - ${BLUE} VLESS+mKCP ${PLAIN}"

Echo - e "${GREEN} 6. ${PLAIN} Install Xray VLESS+TCP+TLS"

Echo - e "${GREEN} 7. ${PLAIN} Install Xray - ${BLUE} VLESS+WS+TLS ${PLAIN} ${RED} (via cdn) ${PLAIN}"

Echo - e "${GREEN} 8. ${PLAIN} Install Xray - ${BLUE} VLESS+TCP+XTLS ${PLAIN} ${RED} (recommended) ${PLAIN}"

Echo - e "${GREEN} 9. ${PLAIN} Install ${BLUE} trojan ${PLAIN} ${RED} (Recommended) ${PLAIN}"

Echo - e "${GREEN} 10. ${PLAIN} Install ${BLUE} trojan+XTLS ${PLAIN} ${RED} (Recommended) ${PLAIN}"

echo " -------------"

Echo - e "${GREEN} 11. ${PLAIN} Update Xray"

Echo - e "${GREEN} 12. ${RED} Uninstall Xray ${PLAIN}"

echo " -------------"

Echo - e "${GREEN} 13. ${PLAIN} Start Xray"

Echo - e "${GREEN} 14. ${PLAIN} Restart Xray"

Echo - e "${GREEN} 15. ${PLAIN} Stop Xray"

echo " -------------"

Echo - e "${GREEN} 16. ${PLAIN} View the Xray configuration"

Echo - e "${GREEN} 17. ${PLAIN} View the Xray log"

echo " -------------"

echo - e "${GREEN} 0. ${PLAIN} Exit"

Echo - n "Current status:"

statusText

echo


read - p "Please select the operation [0-17]:" answer

case $answer in

0)

exit 0

;;

1)

install

;;

2)

KCP="true"

install

;;

3)

TLS="true"

install

;;

4)

TLS="true"

WS="true"

install

;;

5)

VLESS="true"

KCP="true"

install

;;

6)

VLESS="true"

TLS="true"

install

;;

7)

VLESS="true"

TLS="true"

WS="true"

install

;;

8)

VLESS="true"

TLS="true"

XTLS="true"

install

;;

9)

TROJAN="true"

TLS="true"

install

;;

10)

TROJAN="true"

TLS="true"

XTLS="true"

install

;;

11)

update

;;

12)

uninstall

;;

13)

start

;;

14)

restart

;;

15)

stop

;;

16)

showInfo

;;

17)

showLog

;;

*)

ColorEcho $RED "Please select the correct operation!"

exit 1

;;

esac

}


checkSystem


action=$1

[[ -z $1 ]] && action=menu

case "$action" in

menu|update|uninstall|start|restart|stop|showInfo|showLog)

${action}

;;

*)

echo "Parameter error"

Echo "Usage: ` basename $0 ` [menu | update | uninstall | start | restart | stop | showInfo | showLog]"

;;

esac


