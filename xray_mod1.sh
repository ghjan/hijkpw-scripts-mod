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
IP=`curl -sL -4 ip.sb`
if [[ "$?" != "0" ]]; then
    IP=`curl -sL -6 ip.sb`
    V6_PROXY="https://gh.hijk.art/"
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
        colorecho $RED " Please execute the script as root"
        exit 1
    fi

    res=`which yum 2>/dev/null`
    if [[ "$?" != "0" ]]; then
        res=`which apt 2>/dev/null`
        if [[ "$?" != "0" ]]; then
            colorecho $RED " Unsupported Linux system"
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
        colorecho $RED " The system version is too low, please upgrade to the latest version"
        exit 1
    fi
}

colorecho() {
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
            echo -e ${GREEN}installed${PLAIN} ${RED}is not installed${PLAIN}
            ;;
        3)
            echo -e ${GREEN}installed${PLAIN} ${GREEN}Xray is running${PLAIN}
            ;;
        4)
            echo -e ${GREEN}installed${PLAIN} ${GREEN}Xray is running${PLAIN}, ${RED}Nginxis not installed${PLAIN}
            ;;
        5)
            echo -e ${GREEN}installed${PLAIN} ${GREEN}Xray is running, Nginx is running${PLAIN}
            ;;
        *)
            echo -e ${RED}is not installed${PLAIN}
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

# 1: new Xray. 0: no. 1: yes. 2: not installed. 3: check failed.
getVersion() {
    VER=`/usr/local/bin/xray version|head -n1 | awk '{print $2}'`
    RETVAL=$?
    CUR_VER="$(normalizeVersion "$(echo "$VER" | head -n 1 | cut -d " " -f2)")"
    TAG_URL="${V6_PROXY}https://api.github.com/repos/XTLS/Xray-core/releases/latest"
    NEW_VER="$(normalizeVersion "$(curl -s "${TAG_URL}" --connect-timeout 10| grep 'tag_name' | cut -d\" -f4)")"

    if [[ $? -ne 0 ]] || [[ $NEW_VER == "" ]]; then
        colorecho $RED " check version info of Xray fail , please check network"
        return 3
    elif [[ $RETVAL -ne 0 ]];then
        return 2
    elif [[ $NEW_VER != $CUR_VER ]];then
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
            colorecho $RED " unsupported CPU framework !"
            exit 1
        ;;
    esac

	return 0
}

getData() {
    if [[ "$TLS" = "true" || "$XTLS" = "true" ]]; then
        echo ""
        echo " Before running the Xray one click script, please confirm that the following conditions have been met:"
        colorecho ${YELLOW} "1. A fake domain name"
        colorecho ${YELLOW} "2. The DNS resolution of the disguised domain name points to the current server ip（${IP}）"
        colorecho ${BLUE} "3. If there are xray.pem and xray.key certificate key files in the/root directory, ignore condition 2"
        echo " "
        read -p "Press y to confirm the satisfaction, and press other buttons to exit the script:" answer
        if [[ "${answer,,}" != "y" ]]; then
            exit 0
        fi

        echo ""
        while true
        do
            read -p "Please enter the masquerade domain name:" DOMAIN
            if [[ -z "${DOMAIN}" ]]; then
                colorecho ${RED} "The domain name is entered incorrectly, please re-enter!"
            else
                break
            fi
        done
        DOMAIN=${DOMAIN,,}
        colorecho ${BLUE}  "Camouflage domain name (host):$DOMAIN"

        echo ""
        if [[ -f ~/xray.pem && -f ~/xray.key ]]; then
            colorecho ${BLUE}  "Self owned certificate is detected and will be used for deployment"
            CERT_FILE="/usr/local/etc/xray/${DOMAIN}.pem"
            KEY_FILE="/usr/local/etc/xray/${DOMAIN}.key"
        else
            resolve=`curl -sL http://ip-api.com/json/${DOMAIN}`
            res=`echo -n ${resolve} | grep ${IP}`
            if [[ -z "${res}" ]]; then
                colorecho ${BLUE}  "${DOMAIN} parsing result:${resolve}"
                colorecho ${RED}  "The domain name has not been resolved to the current server IP (${IP})!"
                exit 1
            fi
        fi
    fi

    echo ""
    if [[ "$(needNginx)" = "no" ]]; then
        if [[ "$TLS" = "true" ]]; then
            read -p "Please enter the xray listening port [443 is strongly recommended, default 443]:" PORT
            [[ -z "${PORT}" ]] && PORT=443
        else
            read -p "Please enter the xray listening port [a number of 100-65535]:" PORT
            [[ -z "${PORT}" ]] && PORT=`shuf -i200-65000 -n1`
            if [[ "${PORT:0:1}" = "0" ]]; then
                colorecho ${RED}  "Port cannot start with 0"
                exit 1
            fi
        fi
        colorecho ${BLUE}  " xray port:$PORT"
    else
        read -p "Please enter a number of Nginx listening ports [100-65535, default 443]:" PORT
        [[ -z "${PORT}" ]] && PORT=443
        if [ "${PORT:0:1}" = "0" ]; then
            colorecho ${BLUE}  "Port cannot start with 0"
            exit 1
        fi
        colorecho ${BLUE}  "Nginx port:$PORT"
        XPORT=`shuf -i10000-65000 -n1`
    fi

    if [[ "$KCP" = "true" ]]; then
        echo ""
        colorecho $BLUE "Please select the camouflage type:"
        echo "   1) None"
        echo "   2) BT download"
        echo "   3) Video call"
        echo "   4) WeChat video call"
        echo "   5) dtls"
        echo "   6) wiregard"
        read -p "Please select the camouflage type [default: none]:" answer
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
        colorecho $BLUE "Camouflage type:$HEADER_TYPE"
        SEED=`cat /proc/sys/kernel/random/uuid`
    fi

    if [[ "$TROJAN" = "true" ]]; then
        echo ""
        read -p "Please set trojan password (randomly generated if not entered):" PASSWORD
        [[ -z "$PASSWORD" ]] && PASSWORD=`cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 16 | head -n 1`
        colorecho $BLUE "trojan password:$PASSWORD"
    fi

    if [[ "$XTLS" = "true" ]]; then
        echo ""
        colorecho $BLUE "Please select the flow control mode:"
        echo -e "   1) xtls-rprx-direct [$RED tuijian$PLAIN]"
        echo "   2) xtls-rprx-origin"
        read -p "Please select flow control mode [default: direct]" answer
        [[ -z "$answer" ]] && answer=1
        case $answer in
            1)
                FLOW="xtls-rprx-direct"
                ;;
            2)
                FLOW="xtls-rprx-origin"
                ;;
            *)
                colorecho $RED "Invalid option, use the default xtls rprx direct"
                FLOW="xtls-rprx-direct"
                ;;
        esac
        colorecho $BLUE "Flow control mode:$FLOW"
    fi

    if [[ "${WS}" = "true" ]]; then
        echo ""
        while true
        do
            read -p "Please enter the camouflage path starting with/(please enter directly if you don't understand):" WSPATH
            if [[ -z "${WSPATH}" ]]; then
                len=`shuf -i5-12 -n1`
                ws=`cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w $len | head -n 1`
                WSPATH="/$ws"
                break
            elif [[ "${WSPATH:0:1}" != "/" ]]; then
                colorecho ${RED}  "The camouflage path must start with/!"
            elif [[ "${WSPATH}" = "/" ]]; then
                colorecho ${RED}   "Cannot use root path!"
            else
                break
            fi
        done
        colorecho ${BLUE}  "ws path:$WSPATH"
    fi

    if [[ "$TLS" = "true" || "$XTLS" = "true" ]]; then
        echo ""
        colorecho $BLUE "Please select the camouflage station type:"
        echo "   1) Static website (located in/usr/share/nginx/html)"
        echo "2) Fiction station (random selection)"
        echo "3) Beauty Station（https://imeizi.me)"
        echo "4) High definition wallpaper station（https://bing.imeizi.me)"
        echo "5) Customized anti proxy sites (start with http or https)"
        read - p "Please select the type of camouflage website [Default: HD wallpaper station]" answer
        if [[ -z "$answer" ]]; then
            PROXY_URL="https://bing.imeizi.me"
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
                PROXY_URL="https://imeizi.me"
                ;;
            4)
                PROXY_URL="https://bing.imeizi.me"
                ;;
            5)
                read -p "Please enter the reverse generation site (starting with http or https):" PROXY_URL
                if [[ -z "$PROXY_URL" ]]; then
                    colorecho $RED "Please enter the reverse website!"
                    exit 1
                elif [[ "${PROXY_URL:0:4}" != "http" ]]; then
                    colorecho $RED "The anti proxy website must start with http or https!"
                    exit 1
                fi
                ;;
            *)
                colorecho $RED "Please enter the correct option!"
                exit 1
            esac
        fi
        REMOTE_HOST=`echo ${PROXY_URL} | cut -d/ -f3`
        colorecho $BLUE "Camouflage website:$PROXY_URL"

        echo ""
        colorecho $BLUE "Do you want to allow search engines to crawl websites? [Default: Not allowed]"
        echo "y) Yes, there will be more IP requests for websites, but some traffic will be consumed. It is recommended when the vps traffic is sufficient"
        echo "n) Not allowed. The crawler will not visit the website. The access IP is relatively simple, but it can save vps traffic."
        read - p "Please select: [y/n]" answer
        if [[ -z "$answer" ]]; then
            ALLOW_SPIDER="n"
        elif [[ "${answer,,}" = "y" ]]; then
            ALLOW_SPIDER="y"
        else
            ALLOW_SPIDER="n"
        fi
        colorecho $BLUE "Allow search engines:$ALLOW_SPIDER"
    fi

    echo ""
    read -p "Do you want to install BBR (default installation)? [y/n]:" NEED_BBR
    [[ -z "$NEED_BBR" ]] && NEED_BBR=y
    [[ "$NEED_BBR" = "Y" ]] && NEED_BBR=y
    colorecho $BLUE " install BBR:$NEED_BBR"
}

installNginx() {
    echo ""
    colorecho $BLUE " install nginx..."
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
module_hotfixes=true' > /etc/yum.repos.d/nginx.repo
            fi
        fi
        $CMD_INSTALL nginx
        if [[ "$?" != "0" ]]; then
            colorecho $RED "Nginx installation failed, please go tohttps://hijk.art Feedback"
            exit 1
        fi
        systemctl enable nginx
    else
        res=`which nginx 2>/dev/null`
        if [[ "$?" != "0" ]]; then
            colorecho $RED "You have installed the pagoda(baota), please run this script after installing nginx in the pagoda background"
            exit 1
        fi
    fi
}

startNginx() {
    if [[ "$BT" = "false" ]]; then
        systemctl start nginx
    else
        nginx -c /www/server/nginx/conf/nginx.conf
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
            colorecho ${RED}  "Other processes occupy port 80 or 443, please close it first and then run the one click script"
            echo "The port usage information is as follows:"
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
        curl -sL https://get.acme.sh | sh -s email=hijk.pw@protonmail.sh
        source ~/.bashrc
        ~/.acme.sh/acme.sh  --upgrade  --auto-upgrade
        ~/.acme.sh/acme.sh --set-default-ca --server letsencrypt
        if [[ "$BT" = "false" ]]; then
            ~/.acme.sh/acme.sh   --issue -d $DOMAIN --keylength ec-256 --pre-hook "systemctl stop nginx" --post-hook "systemctl restart nginx"  --standalone
        else
            ~/.acme.sh/acme.sh   --issue -d $DOMAIN --keylength ec-256 --pre-hook "nginx -s stop || { echo -n ''; }" --post-hook "nginx -c /www/server/nginx/conf/nginx.conf || { echo -n ''; }"  --standalone
        fi
        [[ -f ~/.acme.sh/${DOMAIN}_ecc/ca.cer ]] || {
            colorecho $RED "Failed to obtain the certificate, please copy the above red text to https://hijk.art Feedback"
            exit 1
        }
        CERT_FILE="/usr/local/etc/xray/${DOMAIN}.pem"
        KEY_FILE="/usr/local/etc/xray/${DOMAIN}.key"
        ~/.acme.sh/acme.sh  --install-cert -d $DOMAIN --ecc \
            --key-file       $KEY_FILE  \
            --fullchain-file $CERT_FILE \
            --reloadcmd     "service nginx force-reload"
        [[ -f $CERT_FILE && -f $KEY_FILE ]] || {
            colorecho $RED "Failed to obtain the certificate, please go to https://hijk.art Feedback"
            exit 1
        }
    else
        cp ~/xray.pem /usr/local/etc/xray/${DOMAIN}.pem
        cp ~/xray.key /usr/local/etc/xray/${DOMAIN}.key
    fi
}

configNginx() {
    mkdir -p /usr/share/nginx/html;
    if [[ "$ALLOW_SPIDER" = "n" ]]; then
        echo 'User-Agent: *' > /usr/share/nginx/html/robots.txt
        echo 'Disallow: /' >> /usr/share/nginx/html/robots.txt
        ROBOT_CONFIG="    location = /robots.txt {}"
    else
        ROBOT_CONFIG=""
    fi

    if [[ "$BT" = "false" ]]; then
        if [[ ! -f /etc/nginx/nginx.conf.bak ]]; then
            mv /etc/nginx/nginx.conf /etc/nginx/nginx.conf.bak
        fi
        res=`id nginx 2>/dev/null`
        if [[ "$?" != "0" ]]; then
            user="www-data"
        else
            user="nginx"
        fi
        cat > /etc/nginx/nginx.conf<<-EOF
user $user;
worker_processes auto;
error_log /var/log/nginx/error.log;
pid /run/nginx.pid;

# Load dynamic modules. See /usr/share/doc/nginx/README.dynamic.
include /usr/share/nginx/modules/*.conf;

events {
    worker_connections 1024;
}

http {
    log_format  main  '\$remote_addr - \$remote_user [\$time_local] "\$request" '
                      '\$status \$body_bytes_sent "\$http_referer" '
                      '"\$http_user_agent" "\$http_x_forwarded_for"';

    access_log  /var/log/nginx/access.log  main;
    server_tokens off;

    sendfile            on;
    tcp_nopush          on;
    tcp_nodelay         on;
    keepalive_timeout   65;
    types_hash_max_size 2048;
    gzip                on;

    include             /etc/nginx/mime.types;
    default_type        application/octet-stream;

    # Load modular configuration files from the /etc/nginx/conf.d directory.
    # See http://nginx.org/en/docs/ngx_core_module.html#include
    # for more information.
    include /etc/nginx/conf.d/*.conf;
}
EOF
    fi

    if [[ "$PROXY_URL" = "" ]]; then
        action=""
    else
        action="proxy_ssl_server_name on;
        proxy_pass $PROXY_URL;
        proxy_set_header Accept-Encoding '';
        sub_filter \"$REMOTE_HOST\" \"$DOMAIN\";
        sub_filter_once off;"
    fi

    if [[ "$TLS" = "true" || "$XTLS" = "true" ]]; then
        mkdir -p ${NGINX_CONF_PATH}
        # VMESS+WS+TLS
        # VLESS+WS+TLS
        if [[ "$WS" = "true" ]]; then
            cat > ${NGINX_CONF_PATH}${DOMAIN}.conf<<-EOF
server {
    listen 80;
    listen [::]:80;
    server_name ${DOMAIN};
    return 301 https://\$server_name:${PORT}\$request_uri;
}

server {
    listen       ${PORT} ssl http2;
    listen       [::]:${PORT} ssl http2;
    server_name ${DOMAIN};
    charset utf-8;

    # ssl配置
    ssl_protocols TLSv1.1 TLSv1.2;
    ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:ECDHE:ECDH:AES:HIGH:!NULL:!aNULL:!MD5:!ADH:!RC4;
    ssl_ecdh_curve secp384r1;
    ssl_prefer_server_ciphers on;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    ssl_session_tickets off;
    ssl_certificate $CERT_FILE;
    ssl_certificate_key $KEY_FILE;

    root /usr/share/nginx/html;
    location / {
        $action
    }
    $ROBOT_CONFIG

    location ${WSPATH} {
      proxy_redirect off;
      proxy_pass http://127.0.0.1:${XPORT};
      proxy_http_version 1.1;
      proxy_set_header Upgrade \$http_upgrade;
      proxy_set_header Connection "upgrade";
      proxy_set_header Host \$host;
      proxy_set_header X-Real-IP \$remote_addr;
      proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
}
EOF
        else
            # VLESS+TCP+TLS
            # VLESS+TCP+XTLS
            # trojan
            cat > ${NGINX_CONF_PATH}${DOMAIN}.conf<<-EOF
server {
    listen 80;
    listen [::]:80;
    listen 81 http2;
    server_name ${DOMAIN};
    root /usr/share/nginx/html;
    location / {
        $action
    }
    $ROBOT_CONFIG
}
EOF
        fi
    fi
}

setSelinux() {
    if [[ -s /etc/selinux/config ]] && grep 'SELINUX=enforcing' /etc/selinux/config; then
        sed -i 's/SELINUX=enforcing/SELINUX=permissive/g' /etc/selinux/config
        setenforce 0
    fi
}

setFirewall() {
    res=`which firewall-cmd 2>/dev/null`
    if [[ $? -eq 0 ]]; then
        systemctl status firewalld > /dev/null 2>&1
        if [[ $? -eq 0 ]];then
            firewall-cmd --permanent --add-service=http
            firewall-cmd --permanent --add-service=https
            if [[ "$PORT" != "443" ]]; then
                firewall-cmd --permanent --add-port=${PORT}/tcp
                firewall-cmd --permanent --add-port=${PORT}/udp
            fi
            firewall-cmd --reload
        else
            nl=`iptables -nL | nl | grep FORWARD | awk '{print $1}'`
            if [[ "$nl" != "3" ]]; then
                iptables -I INPUT -p tcp --dport 80 -j ACCEPT
                iptables -I INPUT -p tcp --dport 443 -j ACCEPT
                if [[ "$PORT" != "443" ]]; then
                    iptables -I INPUT -p tcp --dport ${PORT} -j ACCEPT
                    iptables -I INPUT -p udp --dport ${PORT} -j ACCEPT
                fi
            fi
        fi
    else
        res=`which iptables 2>/dev/null`
        if [[ $? -eq 0 ]]; then
            nl=`iptables -nL | nl | grep FORWARD | awk '{print $1}'`
            if [[ "$nl" != "3" ]]; then
                iptables -I INPUT -p tcp --dport 80 -j ACCEPT
                iptables -I INPUT -p tcp --dport 443 -j ACCEPT
                if [[ "$PORT" != "443" ]]; then
                    iptables -I INPUT -p tcp --dport ${PORT} -j ACCEPT
                    iptables -I INPUT -p udp --dport ${PORT} -j ACCEPT
                fi
            fi
        else
            res=`which ufw 2>/dev/null`
            if [[ $? -eq 0 ]]; then
                res=`ufw status | grep -i inactive`
                if [[ "$res" = "" ]]; then
                    ufw allow http/tcp
                    ufw allow https/tcp
                    if [[ "$PORT" != "443" ]]; then
                        ufw allow ${PORT}/tcp
                        ufw allow ${PORT}/udp
                    fi
                fi
            fi
        fi
    fi
}

installBBR() {
    if [[ "$NEED_BBR" != "y" ]]; then
        INSTALL_BBR=false
        return
    fi
    result=$(lsmod | grep bbr)
    if [[ "$result" != "" ]]; then
        colorecho $BLUE " BBR module installed"
        INSTALL_BBR=false
        return
    fi
    res=`hostnamectl | grep -i openvz`
    if [[ "$res" != "" ]]; then
        colorecho $BLUE " openvz machine, skip install "
        INSTALL_BBR=false
        return
    fi

    echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
    echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
    sysctl -p
    result=$(lsmod | grep bbr)
    if [[ "$result" != "" ]]; then
        colorecho $GREEN " BBR module started"
        INSTALL_BBR=false
        return
    fi

    colorecho $BLUE " install BBR module..."
    if [[ "$PMT" = "yum" ]]; then
        if [[ "$V6_PROXY" = "" ]]; then
            rpm --import https://www.elrepo.org/RPM-GPG-KEY-elrepo.org
            rpm -Uvh http://www.elrepo.org/elrepo-release-7.0-4.el7.elrepo.noarch.rpm
            $CMD_INSTALL --enablerepo=elrepo-kernel kernel-ml
            $CMD_REMOVE kernel-3.*
            grub2-set-default 0
            echo "tcp_bbr" >> /etc/modules-load.d/modules.conf
            INSTALL_BBR=true
        fi
    else
        $CMD_INSTALL --install-recommends linux-generic-hwe-16.04
        grub-set-default 0
        echo "tcp_bbr" >> /etc/modules-load.d/modules.conf
        INSTALL_BBR=true
    fi
}

installXray() {
    rm -rf /tmp/xray
    mkdir -p /tmp/xray
    DOWNLOAD_LINK="${V6_PROXY}https://github.com/XTLS/Xray-core/releases/download/${NEW_VER}/Xray-linux-$(archAffix).zip"
    colorecho $BLUE " download Xray: ${DOWNLOAD_LINK}"
    curl -L -H "Cache-Control: no-cache" -o /tmp/xray/xray.zip ${DOWNLOAD_LINK}
    if [ $? != 0 ];then
        colorecho $RED " Xray install fail , please check network"
        exit 1
    fi
    systemctl stop xray
    mkdir -p /usr/local/etc/xray /usr/local/share/xray && \
    unzip /tmp/xray/xray.zip -d /tmp/xray
    cp /tmp/xray/xray /usr/local/bin
    cp /tmp/xray/geo* /usr/local/share/xray
    chmod +x /usr/local/bin/xray || {
        colorecho $RED " Xray install fail "
        exit 1
    }

    cat >/etc/systemd/system/xray.service<<-EOF
[Unit]
Description=Xray Service
Documentation=https://github.com/xtls https://hijk.art
After=network.target nss-lookup.target

[Service]
User=root
#User=nobody
#CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
#AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/xray run -config /usr/local/etc/xray/config.json
Restart=on-failure
RestartPreventExitStatus=23

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable xray.service
}

trojanConfig() {
    cat > $CONFIG_FILE<<-EOF
{
  "inbounds": [{
    "port": $PORT,
    "protocol": "trojan",
    "settings": {
      "clients": [
        {
          "password": "$PASSWORD"
        }
      ],
      "fallbacks": [
        {
              "alpn": "http/1.1",
              "dest": 80
          },
          {
              "alpn": "h2",
              "dest": 81
          }
      ]
    },
    "streamSettings": {
        "network": "tcp",
        "security": "tls",
        "tlsSettings": {
            "serverName": "$DOMAIN",
            "alpn": ["http/1.1", "h2"],
            "certificates": [
                {
                    "certificateFile": "$CERT_FILE",
                    "keyFile": "$KEY_FILE"
                }
            ]
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

trojanXTLSConfig() {
    cat > $CONFIG_FILE<<-EOF
{
  "inbounds": [{
    "port": $PORT,
    "protocol": "trojan",
    "settings": {
      "clients": [
        {
          "password": "$PASSWORD",
          "flow": "$FLOW"
        }
      ],
      "fallbacks": [
        {
              "alpn": "http/1.1",
              "dest": 80
          },
          {
              "alpn": "h2",
              "dest": 81
          }
      ]
    },
    "streamSettings": {
        "network": "tcp",
        "security": "xtls",
        "xtlsSettings": {
            "serverName": "$DOMAIN",
            "alpn": ["http/1.1", "h2"],
            "certificates": [
                {
                    "certificateFile": "$CERT_FILE",
                    "keyFile": "$KEY_FILE"
                }
            ]
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

vmessConfig() {
    local uuid="$(cat '/proc/sys/kernel/random/uuid')"
    local alterid=`shuf -i50-80 -n1`
    cat > $CONFIG_FILE<<-EOF
{
  "inbounds": [{
    "port": $PORT,
    "protocol": "vmess",
    "settings": {
      "clients": [
        {
          "id": "$uuid",
          "level": 1,
          "alterId": $alterid
        }
      ]
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

vmessKCPConfig() {
    local uuid="$(cat '/proc/sys/kernel/random/uuid')"
    local alterid=`shuf -i50-80 -n1`
    cat > $CONFIG_FILE<<-EOF
{
  "inbounds": [{
    "port": $PORT,
    "protocol": "vmess",
    "settings": {
      "clients": [
        {
          "id": "$uuid",
          "level": 1,
          "alterId": $alterid
        }
      ]
    },
    "streamSettings": {
        "network": "mkcp",
        "kcpSettings": {
            "uplinkCapacity": 100,
            "downlinkCapacity": 100,
            "congestion": true,
            "header": {
                "type": "$HEADER_TYPE"
            },
            "seed": "$SEED"
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

vmessTLSConfig() {
    local uuid="$(cat '/proc/sys/kernel/random/uuid')"
    cat > $CONFIG_FILE<<-EOF
{
  "inbounds": [{
    "port": $PORT,
    "protocol": "vmess",
    "settings": {
      "clients": [
        {
          "id": "$uuid",
          "level": 1,
          "alterId": 0
        }
      ],
      "disableInsecureEncryption": false
    },
    "streamSettings": {
        "network": "tcp",
        "security": "tls",
        "tlsSettings": {
            "serverName": "$DOMAIN",
            "alpn": ["http/1.1", "h2"],
            "certificates": [
                {
                    "certificateFile": "$CERT_FILE",
                    "keyFile": "$KEY_FILE"
                }
            ]
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

vmessWSConfig() {
    local uuid="$(cat '/proc/sys/kernel/random/uuid')"
    cat > $CONFIG_FILE<<-EOF
{
  "inbounds": [{
    "port": $XPORT,
    "listen": "127.0.0.1",
    "protocol": "vmess",
    "settings": {
      "clients": [
        {
          "id": "$uuid",
          "level": 1,
          "alterId": 0
        }
      ],
      "disableInsecureEncryption": false
    },
    "streamSettings": {
        "network": "ws",
        "wsSettings": {
            "path": "$WSPATH",
            "headers": {
                "Host": "$DOMAIN"
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

vlessTLSConfig() {
    local uuid="$(cat '/proc/sys/kernel/random/uuid')"
    cat > $CONFIG_FILE<<-EOF
{
  "inbounds": [{
    "port": $PORT,
    "protocol": "vless",
    "settings": {
      "clients": [
        {
          "id": "$uuid",
          "level": 0
        }
      ],
      "decryption": "none",
      "fallbacks": [
          {
              "alpn": "http/1.1",
              "dest": 80
          },
          {
              "alpn": "h2",
              "dest": 81
          }
      ]
    },
    "streamSettings": {
        "network": "tcp",
        "security": "tls",
        "tlsSettings": {
            "serverName": "$DOMAIN",
            "alpn": ["http/1.1", "h2"],
            "certificates": [
                {
                    "certificateFile": "$CERT_FILE",
                    "keyFile": "$KEY_FILE"
                }
            ]
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

vlessXTLSConfig() {
    local uuid="$(cat '/proc/sys/kernel/random/uuid')"
    cat > $CONFIG_FILE<<-EOF
{
  "inbounds": [{
    "port": $PORT,
    "protocol": "vless",
    "settings": {
      "clients": [
        {
          "id": "$uuid",
          "flow": "$FLOW",
          "level": 0
        }
      ],
      "decryption": "none",
      "fallbacks": [
          {
              "alpn": "http/1.1",
              "dest": 80
          },
          {
              "alpn": "h2",
              "dest": 81
          }
      ]
    },
    "streamSettings": {
        "network": "tcp",
        "security": "xtls",
        "xtlsSettings": {
            "serverName": "$DOMAIN",
            "alpn": ["http/1.1", "h2"],
            "certificates": [
                {
                    "certificateFile": "$CERT_FILE",
                    "keyFile": "$KEY_FILE"
                }
            ]
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

vlessWSConfig() {
    local uuid="$(cat '/proc/sys/kernel/random/uuid')"
    cat > $CONFIG_FILE<<-EOF
{
  "inbounds": [{
    "port": $XPORT,
    "listen": "127.0.0.1",
    "protocol": "vless",
    "settings": {
        "clients": [
            {
                "id": "$uuid",
                "level": 0
            }
        ],
        "decryption": "none"
    },
    "streamSettings": {
        "network": "ws",
        "security": "none",
        "wsSettings": {
            "path": "$WSPATH",
            "headers": {
                "Host": "$DOMAIN"
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

vlessKCPConfig() {
    local uuid="$(cat '/proc/sys/kernel/random/uuid')"
    cat > $CONFIG_FILE<<-EOF
{
  "inbounds": [{
    "port": $PORT,
    "protocol": "vless",
    "settings": {
      "clients": [
        {
          "id": "$uuid",
          "level": 0
        }
      ],
      "decryption": "none"
    },
    "streamSettings": {
        "streamSettings": {
            "network": "mkcp",
            "kcpSettings": {
                "uplinkCapacity": 100,
                "downlinkCapacity": 100,
                "congestion": true,
                "header": {
                    "type": "$HEADER_TYPE"
                },
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
        colorecho $RED " unzip install fail , please check network"
        exit 1
    fi

    installNginx
    setFirewall
    if [[ "$TLS" = "true" || "$XTLS" = "true" ]]; then
        getCert
    fi
    configNginx

    colorecho $BLUE " install Xray..."
    getVersion
    RETVAL="$?"
    if [[ $RETVAL == 0 ]]; then
        colorecho $BLUE " Xray the Latest ${CUR_VER} installed "
    elif [[ $RETVAL == 3 ]]; then
        exit 1
    else
        colorecho $BLUE " install Xray ${NEW_VER} , framework $(archAffix)"
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
        echo " to activate BBR module, system will restart after 30 seconds"
        echo
        echo -e " You can cancel restart by press ctrl + c, input ${RED}reboot${PLAIN} after a while to restart system"
        sleep 30
        reboot
    fi
}

update() {
    res=`status`
    if [[ $res -lt 2 ]]; then
        colorecho $RED " Xray is not installed, please install it first!"
        return
    fi

    getVersion
    RETVAL="$?"
    if [[ $RETVAL == 0 ]]; then
        colorecho $BLUE " Xray the Latest ${CUR_VER} installed "
    elif [[ $RETVAL == 3 ]]; then
        exit 1
    else
        colorecho $BLUE " install Xray ${NEW_VER} , framework $(archAffix)"
        installXray
        stop
        start

        colorecho $GREEN "  the Latest Xray install success!"
    fi
}

uninstall() {
    res=`status`
    if [[ $res -lt 2 ]]; then
        colorecho $RED " Xray is not installed, please install it first!"
        return
    fi

    echo ""
    read -p " Confirm to uninstall Xray ？[y/n]:" answer
    if [[ "${answer,,}" = "y" ]]; then
        domain=`grep Host $CONFIG_FILE | cut -d: -f2 | tr -d \",' '`
        if [[ "$domain" = "" ]]; then
            domain=`grep serverName $CONFIG_FILE | cut -d: -f2 | tr -d \",' '`
        fi

        stop
        systemctl disable xray
        rm -rf /etc/systemd/system/xray.service
        rm -rf /usr/local/bin/xray
        rm -rf /usr/local/etc/xray

        if [[ "$BT" = "false" ]]; then
            systemctl disable nginx
            $CMD_REMOVE nginx
            if [[ "$PMT" = "apt" ]]; then
                $CMD_REMOVE nginx-common
            fi
            rm -rf /etc/nginx/nginx.conf
            if [[ -f /etc/nginx/nginx.conf.bak ]]; then
                mv /etc/nginx/nginx.conf.bak /etc/nginx/nginx.conf
            fi
        fi
        if [[ "$domain" != "" ]]; then
            rm -rf ${NGINX_CONF_PATH}${domain}.conf
        fi
        [[ -f ~/.acme.sh/acme.sh ]] && ~/.acme.sh/acme.sh --uninstall
        colorecho $GREEN " Xray uninstalled success"
    fi
}

start() {
    res=`status`
    if [[ $res -lt 2 ]]; then
        colorecho $RED " Xray is not installed, please install it first!"
        return
    fi
    stopNginx
    startNginx
    systemctl restart xray
    sleep 2

    port=`grep port $CONFIG_FILE| head -n 1| cut -d: -f2| tr -d \",' '`
    res=`ss -nutlp| grep ${port} | grep -i xray`
    if [[ "$res" = "" ]]; then
        colorecho $RED " Xray started fail , please check log or check port is occupied!"
    else
        colorecho $BLUE " Xray started success"
    fi
}

stop() {
    stopNginx
    systemctl stop xray
    colorecho $BLUE " Xray stopped success"
}


restart() {
    res=`status`
    if [[ $res -lt 2 ]]; then
        colorecho $RED " Xray is not installed, please install it first!"
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
        port=`grep -i ssl $NGINX_CONF_PATH${domain}.conf| head -n1 | awk '{print $2}'`
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
            flow="no"
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
    echo -e "   ${BLUE}port(port):${PLAIN}${RED}${port}${PLAIN}"
    echo -e "   ${BLUE}id(uuid):${PLAIN}${RED}${uid}${PLAIN}"
    echo -e "   ${BLUE}extra id(alterid):${PLAIN} ${RED}${alterid}${PLAIN}"
    echo -e "   ${BLUE}crypt method(security):${PLAIN} ${RED}auto${PLAIN}"
    echo -e "   ${BLUE}transfer protocol (network):${PLAIN} ${RED}${network}${PLAIN}"
    echo
    echo -e "   ${BLUE}vmess connection:${PLAIN} $RED$link$PLAIN"
}

outputVmessKCP() {
    echo -e "   ${BLUE}IP(address): ${PLAIN} ${RED}${IP}${PLAIN}"
    echo -e "   ${BLUE}port(port):${PLAIN}${RED}${port}${PLAIN}"
    echo -e "   ${BLUE}id(uuid):${PLAIN}${RED}${uid}${PLAIN}"
    echo -e "   ${BLUE}extra id(alterid):${PLAIN} ${RED}${alterid}${PLAIN}"
    echo -e "   ${BLUE}crypt method(security):${PLAIN} ${RED}auto${PLAIN}"
    echo -e "   ${BLUE}transfer protocol (network):${PLAIN} ${RED}${network}${PLAIN}"
    echo -e "   ${BLUE}Camouflage type(type):${PLAIN} ${RED}${type}${PLAIN}"
    echo -e "   ${BLUE}mkcp seed:${PLAIN} ${RED}${seed}${PLAIN}"
}

outputTrojan() {
    if [[ "$xtls" = "true" ]]; then
        echo -e "   ${BLUE}IP/domain name(address): ${PLAIN} ${RED}${domain}${PLAIN}"
        echo -e "   ${BLUE}port(port):${PLAIN}${RED}${port}${PLAIN}"
        echo -e "   ${BLUE}password(password):${PLAIN}${RED}${password}${PLAIN}"
        echo -e "   ${BLUE}flow control (flow):${PLAIN}$RED$flow${PLAIN}"
        echo -e "   ${BLUE}cypher(encryption):${PLAIN} ${RED}none${PLAIN}"
        echo -e "   ${BLUE}transfer protocol (network):${PLAIN} ${RED}${network}${PLAIN}"
        echo -e "   ${BLUE}base security transfer(tls):${PLAIN}${RED}XTLS${PLAIN}"
    else
        echo -e "   ${BLUE}IP/domain name(address): ${PLAIN} ${RED}${domain}${PLAIN}"
        echo -e "   ${BLUE}port(port):${PLAIN}${RED}${port}${PLAIN}"
        echo -e "   ${BLUE}password(password):${PLAIN}${RED}${password}${PLAIN}"
        echo -e "   ${BLUE}transfer protocol (network):${PLAIN} ${RED}${network}${PLAIN}"
        echo -e "   ${BLUE}base security transfer(tls):${PLAIN}${RED}TLS${PLAIN}"
    fi
}

outputVmessTLS() {
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
  \"path\":\"\",
  \"tls\":\"tls\"
}"
    link=`echo -n ${raw} | base64 -w 0`
    link="vmess://${link}"
    echo -e "   ${BLUE}IP(address): ${PLAIN} ${RED}${IP}${PLAIN}"
    echo -e "   ${BLUE}port(port):${PLAIN}${RED}${port}${PLAIN}"
    echo -e "   ${BLUE}id(uuid):${PLAIN}${RED}${uid}${PLAIN}"
    echo -e "   ${BLUE}extra id(alterid):${PLAIN} ${RED}${alterid}${PLAIN}"
    echo -e "   ${BLUE}crypt method(security):${PLAIN} ${RED}none${PLAIN}"
    echo -e "   ${BLUE}transfer protocol (network):${PLAIN} ${RED}${network}${PLAIN}"
    echo -e "   ${BLUE}Camouflage domain name/主机名(host)/SNI/peer名称:${PLAIN}${RED}${domain}${PLAIN}"
    echo -e "   ${BLUE}base security transfer(tls):${PLAIN}${RED}TLS${PLAIN}"
    echo
    echo -e "   ${BLUE}vmess connection: ${PLAIN}$RED$link$PLAIN"
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
    echo -e "   ${BLUE}port(port):${PLAIN}${RED}${port}${PLAIN}"
    echo -e "   ${BLUE}id(uuid):${PLAIN}${RED}${uid}${PLAIN}"
    echo -e "   ${BLUE}extra id(alterid):${PLAIN} ${RED}${alterid}${PLAIN}"
    echo -e "   ${BLUE}crypt method(security):${PLAIN} ${RED}none${PLAIN}"
    echo -e "   ${BLUE}transfer protocol (network):${PLAIN} ${RED}${network}${PLAIN}"
    echo -e "   ${BLUE}Camouflage type(type):${PLAIN}${RED}none$PLAIN"
    echo -e "   ${BLUE}Camouflage domain name/主机名(host)/SNI/peer名称:${PLAIN}${RED}${domain}${PLAIN}"
    echo -e "   ${BLUE}path(path):${PLAIN}${RED}${wspath}${PLAIN}"
    echo -e "   ${BLUE}base security transfer(tls):${PLAIN}${RED}TLS${PLAIN}"
    echo
    echo -e "   ${BLUE}vmess connection:${PLAIN} $RED$link$PLAIN"
}

showInfo() {
    res=`status`
    if [[ $res -lt 2 ]]; then
        colorecho $RED " Xrayis not installed, please install it first!"
        return
    fi

    echo ""
    echo -n -e " ${BLUE}Xray running status:${PLAIN}"
    statusText
    echo -e " ${BLUE}Xray config file: ${PLAIN} ${RED}${CONFIG_FILE}${PLAIN}"
    colorecho $BLUE " Xray config info:"

    getConfigFileInfo

    echo -e "   ${BLUE} protocol: ${PLAIN} ${RED}${protocol}${PLAIN}"
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
            echo -e "   ${BLUE}port(port):${PLAIN}${RED}${port}${PLAIN}"
            echo -e "   ${BLUE}id(uuid):${PLAIN}${RED}${uid}${PLAIN}"
            echo -e "   ${BLUE}cypher(encryption):${PLAIN} ${RED}none${PLAIN}"
            echo -e "   ${BLUE}transfer protocol (network):${PLAIN} ${RED}${network}${PLAIN}"
            echo -e "   ${BLUE}Camouflage type(type):${PLAIN} ${RED}${type}${PLAIN}"
            echo -e "   ${BLUE}mkcp seed:${PLAIN} ${RED}${seed}${PLAIN}"
            return 0
        fi
        if [[ "$xtls" = "true" ]]; then
            echo -e " ${BLUE}IP(address): ${PLAIN} ${RED}${IP}${PLAIN}"
            echo -e " ${BLUE}port(port):${PLAIN}${RED}${port}${PLAIN}"
            echo -e " ${BLUE}id(uuid):${PLAIN}${RED}${uid}${PLAIN}"
            echo -e " ${BLUE}flow control (flow):${PLAIN}$RED$flow${PLAIN}"
            echo -e " ${BLUE}cypher(encryption):${PLAIN} ${RED}none${PLAIN}"
            echo -e " ${BLUE}transfer protocol (network):${PLAIN} ${RED}${network}${PLAIN}"
            echo -e " ${BLUE}Camouflage type(type):${PLAIN}${RED}none$PLAIN"
            echo -e " ${BLUE}Camouflage domain name/主机名(host)/SNI/peer名称:${PLAIN}${RED}${domain}${PLAIN}"
            echo -e " ${BLUE}base security transfer(tls):${PLAIN}${RED}XTLS${PLAIN}"
        elif [[ "$ws" = "false" ]]; then
            echo -e " ${BLUE}IP(address):  ${PLAIN}${RED}${IP}${PLAIN}"
            echo -e " ${BLUE}port(port):${PLAIN}${RED}${port}${PLAIN}"
            echo -e " ${BLUE}id(uuid):${PLAIN}${RED}${uid}${PLAIN}"
            echo -e " ${BLUE}flow control (flow):${PLAIN}$RED$flow${PLAIN}"
            echo -e " ${BLUE}cypher(encryption):${PLAIN} ${RED}none${PLAIN}"
            echo -e " ${BLUE}transfer protocol (network):${PLAIN} ${RED}${network}${PLAIN}"
            echo -e " ${BLUE}Camouflage type(type):${PLAIN}${RED}none$PLAIN"
            echo -e " ${BLUE}Camouflage domain name/主机名(host)/SNI/peer名称:${PLAIN}${RED}${domain}${PLAIN}"
            echo -e " ${BLUE}base security transfer(tls):${PLAIN}${RED}TLS${PLAIN}"
        else
            echo -e " ${BLUE}IP(address): ${PLAIN} ${RED}${IP}${PLAIN}"
            echo -e " ${BLUE}port(port):${PLAIN}${RED}${port}${PLAIN}"
            echo -e " ${BLUE}id(uuid):${PLAIN}${RED}${uid}${PLAIN}"
            echo -e " ${BLUE}flow control (flow):${PLAIN}$RED$flow${PLAIN}"
            echo -e " ${BLUE}cypher(encryption):${PLAIN} ${RED}none${PLAIN}"
            echo -e " ${BLUE}transfer protocol (network):${PLAIN} ${RED}${network}${PLAIN}"
            echo -e " ${BLUE}Camouflage type(type):${PLAIN}${RED}none$PLAIN"
            echo -e " ${BLUE}Camouflage domain name/主机名(host)/SNI/peer名称:${PLAIN}${RED}${domain}${PLAIN}"
            echo -e " ${BLUE}path(path):${PLAIN}${RED}${wspath}${PLAIN}"
            echo -e " ${BLUE}base security transfer(tls):${PLAIN}${RED}TLS${PLAIN}"
        fi
    fi
}

showLog() {
    res=`status`
    if [[ $res -lt 2 ]]; then
        colorecho $RED " Xrayis not installed, please install it first!"
        return
    fi

    journalctl -xen -u xray --no-pager
}

menu() {
    clear
    echo "#############################################################"
    echo -e "#                     ${RED}Xray一键install 脚本${PLAIN}                      #"
    echo -e "# ${GREEN} author${PLAIN}:  network tiaoyue(hijk)                                      #"
    echo -e "# ${GREEN} network address${PLAIN}: https://hijk.art                                    #"
    echo -e "# ${GREEN} club${PLAIN}: https://hijk.club                                   #"
    echo -e "# ${GREEN}TG group${PLAIN}: https://t.me/hijkclub                               #"
    echo -e "# ${GREEN}Youtube channel${PLAIN}: https://youtube.com/channel/UCYTB--VsObzepVJtc9yvUxQ #"
    echo "#############################################################"
    echo -e "  ${GREEN}1.${PLAIN}   install Xray-VMESS"
    echo -e "  ${GREEN}2.${PLAIN}   install Xray-${BLUE}VMESS+mKCP${PLAIN}"
    echo -e "  ${GREEN}3.${PLAIN}   install Xray-VMESS+TCP+TLS"
    echo -e "  ${GREEN}4.${PLAIN}   install Xray-${BLUE}VMESS+WS+TLS${PLAIN}${RED}( tuijian)${PLAIN}"
    echo -e "  ${GREEN}5.${PLAIN}   install Xray-${BLUE}VLESS+mKCP${PLAIN}"
    echo -e "  ${GREEN}6.${PLAIN}   install Xray-VLESS+TCP+TLS"
    echo -e "  ${GREEN}7.${PLAIN}   install Xray-${BLUE}VLESS+WS+TLS${PLAIN}${RED}(can use cdn)${PLAIN}"
    echo -e "  ${GREEN}8.${PLAIN}   install Xray-${BLUE}VLESS+TCP+XTLS${PLAIN}${RED}( tuijian)${PLAIN}"
    echo -e "  ${GREEN}9.${PLAIN}   install ${BLUE}trojan${PLAIN}${RED}( tuijian)${PLAIN}"
    echo -e "  ${GREEN}10.${PLAIN}  install ${BLUE}trojan+XTLS${PLAIN}${RED}( tuijian)${PLAIN}"
    echo " -------------"
    echo -e "  ${GREEN}11.${PLAIN}  update Xray"
    echo -e "  ${GREEN}12.  ${RED} uninstall Xray${PLAIN}"
    echo " -------------"
    echo -e "  ${GREEN}13.${PLAIN}   start  Xray"
    echo -e "  ${GREEN}14.${PLAIN}   restart  Xray"
    echo -e "  ${GREEN}15.${PLAIN}   stop Xray"
    echo " -------------"
    echo -e "  ${GREEN}16.${PLAIN}   view Xray configuration"
    echo -e "  ${GREEN}17.${PLAIN}   view Xray log "
    echo " -------------"
    echo -e "  ${GREEN}0.${PLAIN}     quit"
    echo -n "   present status:"
    statusText
    echo

    read -p "   please select operation[0-17]:" answer
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
            colorecho $RED " please select correct operation!"
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
        echo "  parameter error"
        echo "  usage: `basename $0` [menu|update|uninstall|start|restart|stop|showInfo|showLog]"
        ;;
esac
