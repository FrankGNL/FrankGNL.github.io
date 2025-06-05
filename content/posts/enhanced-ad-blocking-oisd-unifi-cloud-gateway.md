+++
date = '2024-05-09T07:58:34+02:00'
draft = false
title = 'Master Ad Blocking with Unifi Cloud Gateway + OISD Lists'
tags = ["Unifi", "DNS", "Ad Blocking", "Controld", "Ubiquiti"]
description = "Streamline ad blocking transition from Control D to Unifi Cloud Gateway. Utilize OISD lists for optimal DNS filtering. Boost network security."
images = ["https://cdn-images-1.medium.com/max/1600/1*q9Zs0_86-2rskBvMgSrf1w@2x.jpeg"]
slug = "enhanced-ad-blocking-oisd-unifi-cloud-gateway"
+++

Exploring the transition from Control D to Unifi Cloud Gateway for ad-blocking with OISD lists. Understand the inner workings of Unifi’s DNS filtering system and how to leverage OISD domain blocklists efficiently.

![](https://cdn-images-1.medium.com/max/1600/1*q9Zs0_86-2rskBvMgSrf1w@2x.jpeg)

## The reason

I’ve been a longtime user of  [Control D](https://www.controld.com/), primarily for bypassing geo-restricted video services and blocking ads for all users on my home network. In recent years, Control D has introduced community-based ad block lists. After trying many of them and receiving complaints from my partner, I settled on  [OISD](https://oisd.nl/).

One of my main issues with Control D is occasional slow DNS responses and, once or twice a month, complete service outages. This might be an issue on my end, but I wanted to address it.

Last month, I switched from my Fritzbox router to a Unifi Cloud Gateway, which also supports adblocking. I decided to give this new adblocking feature a try so that I can stop using Control D, as I no longer need it for bypassing geo-restricted video services.

## Investigate how UCG is working with Ad blocking

Within the Unifi Network settings under  **Settings**  >>  **Security**, you can enable ad blocking for specific networks:

![](https://cdn-images-1.medium.com/max/1600/1*x84t40LbGHkAP5O16keVAQ@2x.jpeg)

The Unifi Cloud Gateway (UCG) runs on a Unix-based operating system, enabling the use of standard tools like  _grep_,  _vim_,  _find_,  _cron_,  _sed_, etc.

On the UCG, you can verify that DNS filtering is active for three networks using the  _ps_  command:

```bash
root@Router:~# ps aux | grep dns  
root. 1215. 0.2. 0.5 1452968 17840 ? S<l. 11:15. 0:57 /usr/sbin/dnscrypt-proxy -config /run/dnscrypt-proxy.toml  
root. 1251. 0.0. 0.0. 0. 0 ? S. 11:15. 0:00 [dns_thread]  
nobody. 2466. 0.0. 0.0. 9080. 2900 ? S<. 11:15. 0:07 /usr/sbin/dnsmasq  — conf-dir=/run/dnsmasq.conf.d/  — pid-file=/run/dnsmasq.pid  
root. 2492. 0.0. 0.0. 8948. 1308 ? S<. 11:15. 0:00 /usr/sbin/dnsmasq  — conf-dir=/run/dnsmasq.conf.d/  — pid-file=/run/dnsmasq.pid  
nobody. 4269. 0.0. 0.0. 8948. 2504 ? S<. 11:15. 0:00 /usr/sbin/dnsmasq  — conf-file=/run/dns.conf.d/dnsmasq-ppp0.conf  — pid-file=/run/dnsmasq-ppp0.pid  
nobody. 33076. 0.0. 0.0. 29188. 1212 ? S<. 12:01. 0:01 dnsmasq -r /run/dnsfilter/dns-172.31.4.161-resolv.conf -C /run/dnsfilter/dns-172.31.4.161-conf.conf  — pid-file=/run/dnsfilter/dns-172.31.4.161.pid  
nobody. 33084. 0.1. 0.6. 29188 21044 ? S<. 12:01. 0:28 dnsmasq -r /run/dnsfilter/dns-172.31.4.193-resolv.conf -C /run/dnsfilter/dns-172.31.4.193-conf.conf  — pid-file=/run/dnsfilter/dns-172.31.4.193.pid  
nobody. 33091. 0.0. 0.6. 29188 21036 ? S<. 12:01. 0:05 dnsmasq -r /run/dnsfilter/dns-172.31.4.1-resolv.conf -C /run/dnsfilter/dns-172.31.4.1-conf.conf  — pid-file=/run/dnsfilter/dns-172.31.4.1.pid  
root. 44750. 0.0. 0.3 240596 11628 ? S<l. 12:19. 0:00 /sbin/utm_dns_filter_capture -I br0 br2 br3 -V 6  
root. 238514. 0.0. 0.0. 4924. 692 pts/0. S+. 18:23. 0:00 grep  — color dns
```
The output displays processes related to dnsmasq, indicating DNS filtering is functioning on these networks.

There are two configuration files:

-   dns resolver
-   dns filtering

### DNS Resolver

The content of the resolv.conf is:
```bash
root@Router:~# cat /run/dnsfilter/dns-172.31.4.1-resolv.conf  
nameserver 203.0.113.1
```
The IP address 203.0.113.1 corresponds to a dedicated DNS filtering interface created by Unifi, as shown in the network interface details:
```bash
root@Router:~# ifconfig  
dnsfilter: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>. mtu 1500  
	inet 203.0.113.1. netmask 255.255.255.0. broadcast 0.0.0.0  
	inet6 fe80::7475:5ff:fed3:2a93. prefixlen 64. scopeid 0x20<link>  
	inet6 2001:db8:1000::1. prefixlen 64. scopeid 0x0<global>  
	ether 96:72:03:90:fc:59. txqueuelen 1000. (Ethernet)  
	RX packets 11056. bytes 1425993 (1.3 MiB)  
	RX errors 0. dropped 0. overruns 0. frame 0  
	TX packets 13638. bytes 1676404 (1.5 MiB)  
	TX errors 0. dropped 0 overruns 0. carrier 0. collisions 0
```
Each network where DNS filtering is enabled has its own interface, like dnsfilter.

To redirect DNS requests to the filtering interface (**203.0.113.1**), Unifi uses iptables rules:
```bash
root@Router:~# iptables -L -t nat | grep 203.0.113.1  
DNAT. tcp.  —  172.31.4.0/27. anywhere. tcp dpt:domain to:203.0.113.1:53  
DNAT. udp.  —  172.31.4.0/27. anywhere. udp dpt:domain to:203.0.113.1:53
```
These iptables rules ensure that DNS requests from the specified networks are forwarded to the DNS filtering interface.

Now that we understand how Unifi implements ad blocking, the next question is: which domains are being blocked?

### DNS Filtering

Let’s start by examining the configuration file to understand which lists are currently active:
```bash
root@Router:~# cat /run/dnsfilter/dns-172.31.4.1-conf.conf  
```
## Configuration of DNS Forwarder  
```bash
interface=dnsfilter0  
no-dhcp-interface=dnsfilter0  
no-negcache  
conf-file=/run/dnsfilter/dns-172.31.4.1-ads.list  
conf-file=/run/dnsfilter/dns-172.31.4.1-black.list  
conf-file=/run/dnsfilter/dns-172.31.4.1-white.list
```
Currently, both the  **black** and  **white**  lists are empty. However, we may add domains to them in the future. The primary list used for blocking domains is the  **ads.list**.

Now, let’s examine the domains that are being blocked by the  **ads.list**:
```bash
root@Router:~# tail -n10 /run/dnsfilter/dns-172.31.4.1-ads.list  
address=/www.rodepaudie.com/#  
address=/dflinity.org/#  
address=/steofenore.cyou/#  
address=/clinicservicecare.com/#  
address=/na1uren00n41.store/#  
address=/www.b7d643c5c9cf4e4092783ef022a69fdf.vistvx.pl/#  
address=/hotjar.com/#  
address=/w55c.net/#  
address=/crypto-group.org/#  
address=/ezonn.com/#  
address=/navi56.ru/#
```
But where does Unifi get this list from? If we search the entire filesystem for the ads.list, we will discover the bash script responsible for populating this list.
```bash
root@Router:/usr/share/ubios-udapi-server/utm# grep -Ril 'ads.list' /  
/mnt/.rofs/usr/share/ubios-udapi-server/ips/bin/getsig.sh  
/mnt/.rofs/usr/share/ubios-udapi-server/utm/ads.list  
/mnt/.rofs/usr/share/ubios-udapi-server/utm/adsblockipv4.list  
/mnt/.rofs/usr/share/ubios-udapi-server/utm/adsblockipv6.list  
/mnt/.rofs/usr/share/ubios-udapi-server/utm/bin/ubios-dns-filter-ads.sh  
/mnt/.rofs/usr/share/ubios-udapi-server/utm/bin/ubios-dns-filter-category.sh  
/mnt/.rofs/usr/share/ubios-udapi-server/utm/bin/ubios-dns-filter-whitelist.sh
```
All six files seem really interesting. Let’s start with the sh scripts.
```bash
root@Router:/usr/share/ubios-udapi-server/utm# cat /mnt/.rofs/usr/share/ubios-udapi-server/utm/bin/ubios-dns-filter-ads.sh  
```
```bash
#######################################  
# Update DNS database.  
#  
# ARGUMENTS:  
# None  
#  
# RETURN:  
# 0 - Success (file is valid)  
# 1 - Fail  
# 2 - Already up-to-date  
#######################################  
update_dns_reputation() {  
    USER_AGENT="model/${DEVICEMODEL} version/${DEVICEVERSION} device_id/${DEVICE_ID}"  
  
    log "Ads start update."  
  
    OUTPUT="${ADSRUNPREFIX}/ads.list.gz"  
    URL="${UPDATEURL}/dns/ads.list.gz"  
  
    download_and_validate_file "${USER_AGENT}" "${URL}" "${URL}.hash" "${OUTPUT}"  
    RC=$?  
    if [ "${RC}" -ne "0" ]; then  
        log "The download will be retried on the next execution, skipping."  
        return ${RC}  
    fi  
  
    /bin/gzip -d "${OUTPUT}" -c >"${ADSRUNPREFIX}/ads.list.tmp"  
    GZRC=$?  
    if [ "${GZRC}" -ne "0" ]; then  
        log "${TYPE} extraction failed. Return code: ${GZRC}"  
        log "The update will be retried on the next execution, skipping."  
        return 1  
    fi  
    mv "${ADSRUNPREFIX}/ads.list.tmp" "${ADSRUNPREFIX}/ads.list"  
  
    log "Ads database extracted."  
    while IFS= read -r DOMAIN; do  
        # Ignore own domains  
        [[ "$DOMAIN" == *.ui.com ]] ||  
            [[ "$DOMAIN" == *.ubnt.com ]] && continue  
  
        echo "address=/$DOMAIN/#" >>"${ADSRUNPREFIX}/adsblockipv6.list.tmp"  
        echo "address=/$DOMAIN/#" >>"${ADSRUNPREFIX}/adsblockipv4.list.tmp"  
    done <"${ADSRUNPREFIX}/ads.list"  
  
    mv "${ADSRUNPREFIX}/adsblockipv4.list.tmp" "${ADSRUNPREFIX}/adsblockipv4.list"  
    mv "${ADSRUNPREFIX}/adsblockipv6.list.tmp" "${ADSRUNPREFIX}/adsblockipv6.list"  
  
    # Update completed, save to the Persistent disk  
    cp "${ADSRUNPREFIX}/ads.list" "${ADSFIRMWAREPREFIX}/ads.list"  
    cp "${ADSRUNPREFIX}/adsblockipv4.list" "${ADSFIRMWAREPREFIX}/adsblockipv4.list"  
    cp "${ADSRUNPREFIX}/adsblockipv6.list" "${ADSFIRMWAREPREFIX}/adsblockipv6.list"  
  
    # Restart utm_dns_filter_capture  
    if [ -s /run/utm_dns_filter_capture.pid ]; then  
        UTM_DNS_FILTER_CAPTURE_PID=$(cat /run/utm_dns_filter_capture.pid)  
        log "utm_dns_filter_capture PID file found, restart service."  
        if ! /bin/kill -SIGTERM "${UTM_DNS_FILTER_CAPTURE_PID}" >/dev/null 2>&1; then  
            log "utm_dns_filter_capture fail to sent signal."  
        fi  
    fi  
  
    rm -f "${OUTPUT}" 2>&1  
    log "Ads update finished."  
    return 0  
}
```
Yes, we found the script we were looking for. Unifi retrieves the list from the following location:  _https://assets.unifi-ai.com/ads.list.gz_. The script extracts the file and copies the content to  **adsblockipv4.list**  and  **adsblockipv6.list**.

Afterward, it kills the dnsfilter process, prompting the system to restart the process.

The next question is: how often is this list being updated? Let’s perform another  _grep_.
```bash
root@Router:/usr/share/ubios-udapi-server/utm# grep -Ril 'getsig.sh' /  
/etc/cron.d/ips-service-alien  
/etc/cron.d/ips-service-tor  
/etc/cron.d/ips-service-ads  
/etc/cron.d/ips-service-rules
```
Interesting. There are cronjobs that initiate this process:
```bash
root@Router:/usr/share/ubios-udapi-server/utm# cat /etc/cron.d/ips-service-ads  
MAILTO=""  
0 */24. * * * root /usr/share/ubios-udapi-server/ips/bin/getsig.sh 'ads' 'xx:xx:xx:xx:xx:xx' 'UDRULT.ipq5322.v3.2.12.7765dbb.240126.0152' 'UDRULT' 'a748' 'splay'
```
So, does it start the process every day at 00:00?

Upon further examination of the script, I discovered that the  **splay**  option introduces a random sleep

### How we use OISD as domain blocking list

You can find all the lists on the  [OISD](https://oisd.nl/)  website, including the comprehensive OISD big list:

![](https://cdn-images-1.medium.com/max/1600/0*GtGjUrQnUXHgNlhx.png)

We’re particularly interested in the  **dnsmasq2**  file since Unifi utilizes DNSMasq version 2.86.
```bash
root@Router:~# df -hT  
Filesystem. Type. Size. Used Avail Use% Mounted on  
udev. devtmpfs. 1.5G. 0. 1.5G. 0% /dev  
tmpfs. tmpfs. 296M. 107M. 189M. 37% /run  
/dev/disk/by-partlabel/root. ext4. 2.0G. 1.2G. 688M. 63% /boot/firmware  
/dev/loop0. squashfs. 568M. 568M. 0 100% /mnt/.rofs  
/dev/disk/by-partlabel/overlay. ext4. 9.3G. 1.3G. 7.6G. 15% /mnt/.rwfs  
overlayfs-root. overlay. 9.3G. 1.3G. 7.6G. 15% /  
/dev/disk/by-partlabel/log. ext4. 974M. 101M. 807M. 12% /var/log  
/dev/disk/by-partlabel/persistent ext4. 2.0G. 128M. 1.7G. 7% /persistent  
tmpfs. tmpfs. 1.5G. 28K. 1.5G. 1% /dev/shm  
tmpfs. tmpfs. 5.0M. 0. 5.0M. 0% /run/lock  
tmpfs. tmpfs. 738M. 44K. 738M. 1% /tmp  
tmpfs. tmpfs. 16M. 0. 16M. 0% /var/log/ulog  
tmpfs. tmpfs. 64M. 1.4M. 63M. 3% /var/opt/unifi/tmp
```
All data mounted on the  **/persistent**  volume (as the name suggests) will be preserved during firmware updates, reboots, and other operations.

I’ve developed a script that accomplishes the following tasks:

-   Downloads the  **dnsmasq2**  file from oisd.nl.
-   - Modifies the file to match the syntax of the original file.
-   - Copies the content to  **adsblockipv4.list**  and  **adsblockipv6.list**.
-   - Restarts the  **utm_dns_filter_capture**.
-   - Restarts  **dnsmasq**.

### Download and alter the dnsmasq2 file from oisd.nl

Here’s an example layout of the downloaded file:
```
# Version: 202405081506  
# Title: oisd small  
# Description: Block. Don't break.  
# Syntax: DNSMasq ver 2.86 and above  
# Entries: 48515  
# Last modified: 2024–05–08T15:06:31+0000  
# Expires: 1 hours  
# License: https://github.com/sjhgvr/oisd/blob/main/LICENSE  
# Maintainer: Stephan van Ruth  
# Homepage: https://oisd.nl  
# Contact: contact@oisd.nl  
  
local=/0-02.net/  
local=/0.101tubeporn.com/  
local=/0.code.cotsta.ru/  
local=/000.gaysexe.free.fr/  
local=/000free.us/  
local=/000tristanprod.free.fr/  
local=/000webhostapp.com/  
local=/002777.xyz/  
local=/00280181d0.com/  
local=/00518b6f0c.com/

curl -s -o "${BASE}"/dnsmasq2 https://big.oisd.nl/dnsmasq2  
  
sed -i '/^$/d' "${BASE}"/dnsmasq2 #removes all empty lines  
sed -i '/^#/d' "${BASE}"/dnsmasq2 #removes all lines starting wwith #  
sed -i 's/local=/address=/g' "${BASE}"/dnsmasq2 #replace local with address  
sed -i s/$/#/ "${BASE}"/dnsmasq2 #add # after ther last /

Here’s a formatted display of the result:

address=/0-02.net/#  
address=/0.101tubeporn.com/#  
address=/0.code.cotsta.ru/#  
address=/000.gaysexe.free.fr/#  
address=/000free.us/#  
address=/000tristanprod.free.fr/#  
address=/000webhostapp.com/#  
address=/002777.xyz/#  
address=/00280181d0.com/#  
address=/00518b6f0c.com/#
```
### Copy the content to adsblockipv4.list and adsblockipv6.list

To copy the content over to the  **adsblockipv4.list**  and  **adsblockipv6.list**  files, you can use the following commands:
```bash
cat "${BASE}"/dnsmasq2 > /run/utm/adsblockipv4.list  
cat "${BASE}"/dnsmasq2 > /run/utm/adsblockipv6.list
```
Super easy, be that is needed to fill the file  **/run/dnsfilter/dns-172.31.4.1-ads.list**

### Restart utm_dns_filter_capture

```bash
# Restart utm_dns_filter_capture  
if [ -s /run/utm_dns_filter_capture.pid ]; then  
    UTM_DNS_FILTER_CAPTURE_PID=$(cat /run/utm_dns_filter_capture.pid)  
    log "utm_dns_filter_capture PID file found, restart service."  
    if ! /bin/kill -SIGTERM "${UTM_DNS_FILTER_CAPTURE_PID}" >/dev/null 2>&1; then  
        log "utm_dns_filter_capture fail to sent signal."  
    fi  
fi
```
In this script snippet inspired by UniFi, we’re checking for the  **utm_dns_filter_capture**  process by its PID (Process ID). If the process is found, the script terminates it. Subsequently, the system automatically restarts the daemon.

### Restart dnsmasq

Finally, we need to restart DNSMasq to load the updated list and enable domain blocking.
```bash
restartdnsfilter() {  
    for killdns in $(cat /run/dnsfilter/*.pid 2>/dev/null); do  
        kill -9 "${killdns}"  
    done  
  
    if [ -f "/run/dnsfilter/dnsfilter" ]; then  
        sleep 5  
  
        for restartns in $(cat /run/dnsfilter/dnsfilter); do  
            ip netns exec "${restartns}" dnsmasq -r /run/dnsfilter/"${restartns}"-resolv.conf -C /run/dnsfilter/"${restartns}"-conf.conf --pid-file=/run/dnsfilter/"${restartns}".pid  
        done  
    fi  
}  
  
restartdnsfilter
```
This section of the script is also adapted from the Unifi script. Similarly, it terminates the process, but the key distinction is that it initiates the process independently rather than relying on the system to do so.

### the complete script

Putting it all together will make the following script:
```bash
#!/bin/bash  
  
BASE="/persistent/scripts"  
  
log() {  
    echo "$*"  
    /usr/bin/logger -t "ads" "$*"  
}  
  
backupDate=$(date +%s)  
  
restartdnsfilter() {  
    for killdns in $(cat /run/dnsfilter/*.pid 2>/dev/null); do  
        kill -9 "${killdns}"  
    done  
  
    if [ -f "/run/dnsfilter/dnsfilter" ]; then  
        sleep 5  
  
        for restartns in $(cat /run/dnsfilter/dnsfilter); do  
            ip netns exec "${restartns}" dnsmasq -r /run/dnsfilter/"${restartns}"-resolv.conf -C /run/dnsfilter/"${restartns}"-conf.conf --pid-file=/run/dnsfilter/"${restartns}".pid  
        done  
    fi  
}  
  
log "Start updating ads block list"  
  
curl -s -o "${BASE}"/dnsmasq2 https://big.oisd.nl/dnsmasq2  
  
sed -i '/^$/d' "${BASE}"/dnsmasq2  
sed -i '/^#/d' "${BASE}"/dnsmasq2  
sed -i 's/local=/address=/g' "${BASE}"/dnsmasq2  
sed -i s/$/#/ "${BASE}"/dnsmasq2  
  
cp /run/utm/adsblockipv4.list /run/utm/adsblockipv4.${backupDate}.list  
cp /run/utm/adsblockipv6.list /run/utm/adsblockipv6.${backupDate}.list  
  
cp "${BASE}"/dnsmasq2 /run/utm/adsblockipv4.list  
cp "${BASE}"/dnsmasq2 /run/utm/adsblockipv6.list  
  
rm -rf "${BASE}"/dnsmasq2  
  
# Restart utm_dns_filter_capture  
if [ -s /run/utm_dns_filter_capture.pid ]; then  
    UTM_DNS_FILTER_CAPTURE_PID=$(cat /run/utm_dns_filter_capture.pid)  
    log "utm_dns_filter_capture PID file found, restart service."  
    if ! /bin/kill -SIGTERM "${UTM_DNS_FILTER_CAPTURE_PID}" >/dev/null 2>&1; then  
        log "utm_dns_filter_capture fail to sent signal."  
    fi  
fi  
  
sleep 20  
  
restartdnsfilter  
  
log "OISD Updated"
```
### Automate the script to run during the night

The last part is to run this script every night. This as well is the easy part
```bash
root@Router:~# cat /etc/cron.d/ips-service-ads  
MAILTO=""  
0 */24. * * * root /usr/share/ubios-udapi-server/ips/bin/getsig.sh 'ads' 'xx:xx:xx:xx:xx:xx' 'UDRULT.ipq5322.v3.2.12.7765dbb.240126.0152' 'UDRULT' 'a748' 'splay' && /persistent/scripts/oisd.sh
```
Next step is to make the script runabale:
```bash
root@Router:~# chmod u+x /persistent/scripts/oisd.sh
```
This line grants permission to the script owner (root) to execute the script.

I added the new script at the end with a random timer using splay and the && operator. This setup ensures that our script will run only if the first part executes successfully.

**NOTE: Please be aware that after every reboot or firmware update, the cronjob adjustments will be reset.**

### Testing

After manually running the script or waiting until the next day, we can test if it is working. This test should be conducted from a network where ad blocking has been enabled.
```bash
Server:		172.31.4.193  
Address:	172.31.4.193#53  
  
Name:	zzztest.oisd.nl  
Address: 0.0.0.0
```
