# Dovehawk Zeek Module

Adversary Threat Hunting with Zeek (formerly Bro IDS) and MISP.


## Requirements

MISP: Version 2.5 includes the Zeek datamodel required to handle content signatures.

Zeek NSM: tested with version version >= 3.1.1.

Curl: command line tool for accessing web content, tested with curl 7.54.0.


## Quick Start - No install

Download latest release from GitHub

Edit config.zeek and add your MISP API key, your MISP_URL and optional Slack Web Hook URL.

Locally launch Zeek: zeek -i en0 path_to_dovehawk


## Quick Start - Install package using zeek package manager.

zpkg install https://github.com/tylabs/dovehawk

Run package to get local directory: zeek -i en0 dovehawk

Edit config.zeek and add your MISP API key, your MISP_URL and optional Slack Web Hook URL.

Run: zeek -i en0 dovehawk



## Detailed Install

Install zeek: brew install zeek / yum install zeek

Install zkg (Zeek package manager): sudo pip install zkg

Setup zkg: zkg autoconfig

zkg install https://github.com/tylabs/dovehawk

check the install: zeek -i en0 dovehawk

edit config.zeek to include your MISP API key, MISP URL and optional Slack Web Hook.

edit zeekctl local config: /usr/local/share/zeek/site/local.zeek:

add: @load [FULL PATH]/dovehawk #ie  /usr/local/Cellar/zeek/3.1.1/share/zeek/site/dovehawk/

check eth interface setting: /usr/local/etc/node.cfg

run: zeekctl deploy

cronjob add: */5 * * * * /usr/local/bin/zeekctl cron

restart zeek: /usr/local/bin/zeekctl restart

cronjob to restart zeek to reimport signatures: 1 */4 * * * /usr/local/bin/zeekctl restart


## Monitoring and context

The zeek module outputs hits to the console, logs to file, and could send metadata to another web hook.


## Usage

If running zeek directly, reference the dovehawk folder:

sudo zeek -i en1 [FULL PATH]/dovehawk

If running using the zeekctl interface, edit the local.zeek configuration file in /usr/local/zeek/share/zeek/site and, at the bottom, add the line:

@load [FULL PATH]/dovehawk

then run the zeekctl deploy sequence to have the scripts installed.


## Zeek Tips

When running locally (ie running Zeek on the same system you are generating traffic from), you may need to use the -C option to ignore checksum validation.


## Optionally Disable local logging

Add "Log::default_writer=Log::WRITER_NONE" to the command.

zeek -i en0 dovehawk Log::default_writer=Log::WRITER_NONE


## Zeek Health and Clusters

Depending on the bandwidth - the NETSTATS info will show if dropped packets are occuring, you may with to add additional worker nodes to process traffic in a distributed fashion. Follow the CLUSTER.md instructions for details on local or remote clusters.


## Maintenance

For long term monitoring, if not disabling logs as above, use zeekctl to launch, rotate logs, and restart after crashes.



