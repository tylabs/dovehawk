# Dovehawk Zeek Module

Adversary Threat Hunting with Zeek (formerly Bro IDS) and MISP.


## Requirements

MISP: Version 2.5 includes the Zeek datamodel required to handle content signatures.

Zeek NSM: tested with version version >2.5.3.

Curl: command line tool for accessing web content, tested with curl 7.54.0.


## Quick Start - No install

Download latest release from GitHub

Edit config.bro and add your MISP API key, your MISP_URL and optional Slack Web Hook URL.

Locally launch Zeek: bro -i en0 path_to_dovehawk


## Quick Start - Install package using bro package manager.

bro-pkg install https://github.com/tylabs/dovehawk

Run package to get local directory: bro -i en0 dovehawk

Edit config.bro and add your MISP API key, your MISP_URL and optional Slack Web Hook URL.

Run: bro -i en0 dovehawk



## Detailed Install

Install bro: brew install bro / yum install bro

Install bro-pkg: sudo pip install bro-pkg

Setup bro-pkg: bro-pkg autoconfig

bro-pkg install https://github.com/tylabs/dovehawk

check the install: bro -i en0 dovehawk

edit misp_config.bro to include your MISP API key, MISP URL and optional Slack Web Hook.

edit broctl local config: /usr/local/share/bro/site/local.bro:

add: @load [FULL PATH]/dovehawk #ie  /usr/local/Cellar/bro/2.5.4/share/bro/site/dovehawk/

check eth interface setting: /usr/local/etc/node.cfg

run: broctl deploy

cronjob add: */5 * * * * /usr/local/bin/broctl cron

restart bro: /usr/local/bin/broctl restart

cronjob to restart bro to reimport signatures: 1 */4 * * * /usr/local/bin/broctl restart


## Monitoring and context

The bro module outputs hits to the console, logs to file, and could send metadata to another web hook.


## Usage

If running bro directly, reference the dovehawk folder:

sudo bro -i en1 [FULL PATH]/dovehawk

If running using the broctl interface, edit the local.bro configuration file in /usr/local/bro/share/bro/site and, at the bottom, add the line:

@load [FULL PATH]/dovehawk

then run the broctl deploy sequence to have the scripts installed.


## Zeek Tips

When running locally (ie running Zeek on the same system you are generating traffic from), you may need to use the -C option to ignore checksum validation.


## Optionally Disable local logging

Add "Log::default_writer=Log::WRITER_NONE" to the command.

bro -i en0 dovehawk Log::default_writer=Log::WRITER_NONE


## Zeek Health and Clusters

Depending on the bandwidth - the NETSTATS info will show if dropped packets are occuring, you may with to add additional worker nodes to process traffic in a distributed fashion. Follow the CLUSTER.md instructions for details on local or remote clusters.


## Maintenance

For long term monitoring, if not disabling logs as above, use broctl to launch, rotate logs, and restart after crashes.



