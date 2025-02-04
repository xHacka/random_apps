## Install

### Setup

> Note: Project is meant to be served on domain instead of seperate routes, routes are untested and subdomains is just fun 🤔

```bash
sudo su
apt update
apt upgrade
apt install nginx git -y # Probably missing things
cd /var/www
git clone https://github.com/xHacka/random_apps.git
cd random_apps
rm -rf .git*
sed -i 's/example.com/YOURDOMAIN.TLD/g' ./random_apps/conf/nginx/*.conf
sed -i 's/example.com/YOURDOMAIN.TLD/g' ./random_apps/random_apps/settings.py
bash ./random_apps/conf/scripts/init.sh
chown -R www-data:www-data /var/www
 DJANGO_SUPERUSER_PASSWORD="supersecurepassword" ./venv/bin/python ./random_apps/manage.py createsuperuser --noinput --username superuser --email let@me.in
```

> Tip: If you place space before the command it will not go into the history, but probably still better to enter password when it prompts

### Firewall

Current rules will look like (if using Oracle Cloud VPS)
```bash
iptables -L -n -v --line-numbers # Show all rules using iptables

Chain INPUT (policy ACCEPT 0 packets, 0 bytes)
num   pkts bytes target     prot opt in     out     source               destination
1     203K  467M ACCEPT     0    --  *      *       0.0.0.0/0            0.0.0.0/0            state RELATED,ESTABLISHED
2        2   168 ACCEPT     1    --  *      *       0.0.0.0/0            0.0.0.0/0
3     1656  164K ACCEPT     0    --  lo     *       0.0.0.0/0            0.0.0.0/0
4        0     0 ACCEPT     17   --  *      *       0.0.0.0/0            0.0.0.0/0            udp spt:123
5     2222  133K ACCEPT     6    --  *      *       0.0.0.0/0            0.0.0.0/0            state NEW tcp dpt:22
6      922  104K REJECT     0    --  *      *       0.0.0.0/0            0.0.0.0/0            reject-with icmp-host-prohibited
```

Add following rules to enable HTTP, HTTPs and 4444 just for fun!
```bash
iptables -I INPUT 6 -p tcp --dport 80 -j ACCEPT
iptables -I INPUT 6 -p tcp --dport 443 -j ACCEPT
iptables -I INPUT 6 -p tcp --dport 4444 -j ACCEPT
```

Do mind that same ingress rules need to be added in your instance VNC Security List

![image](https://github.com/user-attachments/assets/a9b4cd46-1861-4255-b3e6-decfb1140fc1)

### SSL

If you need SSL quick and easy way is to just use CertBot, instructions: [https://certbot.eff.org/instructions?ws=nginx&os=pip](https://certbot.eff.org/instructions?ws=nginx&os=pip)

If you're doing personal project or don't care about legimacy too much you could use [https://joker.com](https://joker.com) to buy cheap domains. CertBot is easy to setup and is least trusted SSL AFAIK.

## Apps

### Scarecrow

Simple html

### b64app

Simple base64 encoder and decoder, with a dash of SQL.

### Uploader

Somewhat simple prettified PHP upload server, maybe not the most secure too.

### pod_diagnostics

Can be used to list saved files (txt,pdf) and download them.
`/data` endpoint can receive pdf that has been compressed with gzip and encoded with base64, then save it as pdf and as text.

> Note: Not included, futute TODO
