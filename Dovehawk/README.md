# Dovehawk Bro Module

Threat Hunting with Bro and MISP


This modules uses the the built-in Bro Intelligence Framework to load and monitor signatures from MISP automatically. Indicators are downloaded from MISP every 6 hours and hits, called sightings are reported back to MISP immediately. The module also includes a customized version of Jan Grashoefer's expiration code to remove indicators after 7 hours after they are deleted from MISP.


Indicators are downloaded automatically every 6 hours.  Indicators should expire after 7 hours if removed from MISP.


Indicators are downloaded and read into memory.  Content signatures in signatures.sig which is not yet automatically downloaded.  MISP does not yet support bro content signatures, this module will be updated for downloading those when available.


## Official Source

https://dovehawk.io/ (coming soon)

https://github.com/tylabs/dovehawk/


## Requirements

Bro IDS: tested with version version 2.5.4.

Curl: command line tool for accessing web content, tested with curl 7.54.0.


## Quick Start

Rename misp_config.bro.default to misp_config.bro. Edit misp_config.bro and add your MISP API key and URLs for the Bro Export and Sightings.



## Related Projects

http://www.misp-project.org/ MISP

https://www.bro.org Bro IDS


## Monitoring and context

The bro module outputs hits to the console, logs to file, and could send metadata to another web hook.


## Usage

If running bro directly, reference the Dovehawk folder:

sudo bro -i en1 [FULL PATH]/Dovehawk

If running using the broctl interface, edit the local.bro configuration file in /usr/local/bro/share/bro/site and, at the bottom, add the line:

@load [FULL PATH]/Dovehawk

then run the broctl deploy sequence to have the scripts installed.


## BRO Tips

When running locally (ie running Bro on the same system you are generating traffic from), you may need to use the -C option to ignore checksum validation.


## Optional Disable local logging

Add "Log::default_writer=Log::WRITER_NONE" to the command.

bro -i en0 Dovehawk Log::default_writer=Log::WRITER_NONE


## Maintenance

For long term monitoring, if not disabling logs as above, use broctl to launch, rotate logs, and restart after crashes.



# Special Thanks

CanCyber.org for their support in releasing a generic MISP version of their Bro Module as open source.

Developers: Michael Kortekaas (original module), Tyler McLellan @tylabs (MISP combined import and sightings)


# License

Copyright 2018 Cancyber Inc., Michael Kortekaas @mrkortek, Tyler McLellan @tylabs

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

