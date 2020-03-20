# Zeek Cluster Setup for Dovehawk.io

The Dovehawk Zeek module can be run in a cluster with a central manager and many remote worker's each monitoring their own local interface.  You can also use a cluster locally to distribute bandwidth automatically to distribute load for monitoring traffic even up to the 10-20Gbs range on sufficient hardware.

We recommend reviewing the [Zeek Cluster](https://docs.zeek.org/en/stable/cluster/) which recommends 1 core per 250Mbs of peak traffic and methods to distribute traffic to multiple  worker hardware. 

You can also use Dovehawk on cloud servers using a cluster where taps and span ports are not available, cluster workers can monitor a local network port.

DoveHawk from version 1.01.01 supports the transparent cluster to have a single manager download indicators and distribute them to all workers automatically rather than each worker downloading the signatures.

# Requirements

Root ssh access is required for remote workers.

Zeek requires the same OS type, dependent libraries and Zeek version across the manager and workers.


## Remote Workers: Setup ssh keys for root logins

### On manager:

zeek-manager# ssh-keygen 
 Generating public/private rsa key pair. 
 Enter file in which to save the key (/root/.ssh/id_rsa): [ Press Enter ] 
 Enter passphrase (empty for no passphrase): [ Press Enter ] 
 Enter same passphrase again: [ Press Enter ] 
 Your identification has been saved in /root/.ssh/id_rsa. 
 Your public key has been saved in /root/.ssh/id_rsa.pub. 

Copy public key from id_rsa.pub to the workers /root/.ssh/authorized_keys

ssh manually into each node to add to knownhosts entry.

### Allow root to login on workers

grep Root /etc/ssh/sshd_config 
 PermitRootLogin yes

### Restart ssh on workers

/etc/init.d/ssh restart

or

service sshd restart

## All: Install dovehawk module on Manager

See INSTALL.md


## Setup your cluster:

Note: to use a single standalone server and still use zeekctl, leave this file unchanged.

Edit /usr/local/zeek/etc/node.cfg::
[manager]
type=manager
host=10.100.1.69

[logger]
type=logger
host=10.100.1.69
 
[proxy-1]
type=proxy
host=10.100.1.69
 
[worker-1]
type=worker
host=10.100.2.249
interface=eth0
 

[worker-2]
type=worker
host=10.100.2.73
interface=eth0


[worker-3]
type=worker
host=10.100.1.71
interface=eth0


[worker-4]
type=worker
host=10.100.1.69
interface=eth0


## All:  Deploy and Run Dovehawk on workers:

/usr/local/zeek/bin/zeekctl deploy

Check status:

/usr/local/zeek/bin/zeekctl status

Stop:

/usr/local/zeek/bin/zeekctl stop

Restart / read latest signatures:

/usr/local/zeek/bin/zeekctl restart


## All: Logs viewing:

/usr/local/zeek/logs or /usr/local/zeek/spool

## All: Cron

To keep everything running and also force the reimport of content signatures:

*/5 * * * * /usr/local/zeek/bin/zeekctl cron
1 22 * * * /usr/local/zeek/bin/zeekctl deploy  > /dev/null 2>&1

