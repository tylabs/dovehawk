# Dovehawk Bro Module

Threat Hunting with Bro and MISP


## Requirements

MISP: Version 2.4.94 includes the Bro datamodel required to handle content signatures.

Bro IDS: tested with version version 2.5.4.

Curl: command line tool for accessing web content, tested with curl 7.54.0.


## Quick Start - No install

Download latest release from GitHub

Edit misp_config.bro and add your MISP API key, your MISP_URL and optional Slack Web Hook URL.

Locally launch bro: bro -i en0 path_to_dovehawk


## Quick Start - Install package

bro-pkg install https://github.com/tylabs/dovehawk

Run package to get local directory: bro -i en0 dovehawk

Edit misp_config.bro and add your MISP API key, your MISP_URL and optional Slack Web Hook URL.

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


## BRO Tips

When running locally (ie running Bro on the same system you are generating traffic from), you may need to use the -C option to ignore checksum validation.


## Optional Disable local logging

Add "Log::default_writer=Log::WRITER_NONE" to the command.

bro -i en0 dovehawk Log::default_writer=Log::WRITER_NONE


## Maintenance

For long term monitoring, if not disabling logs as above, use broctl to launch, rotate logs, and restart after crashes.



