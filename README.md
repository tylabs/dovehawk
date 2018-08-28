# Dovehawk Bro Module

Threat Hunting with Bro and MISP


This module uses the the built-in Bro Intelligence Framework to load and monitor signatures from MISP automatically. Indicators are downloaded from MISP every 6 hours and hits, called sightings, are reported back to MISP immediately. The module also includes a customized version of Jan Grashoefer's expiration code to remove indicators after 7 hours after they are deleted from MISP.


Indicators are downloaded automatically every 6 hours.  Indicators should expire after 7 hours if removed from MISP.


Indicators are downloaded and read into memory.  Content signatures in signatures.sig are MISP Network Activity->bro items downloaded from MISP.  Bro must be restarted to ingest the content signatures.  To do this automatically we recommend restarting bro using broctl and a restart cron described in included file INSTALL.md


## Screencaps

### Dovehawk Downloads Indicators From MISP

![Dovehawk signature download](https://dovehawk.io/images/dovehawk_launch.png "Dovehawk startup")

### Dovehawk Sighting Uploaded

![Dovehawk hit and sighting upload](https://dovehawk.io/images/dovehawk_hit.png "Dovehawk hit")

### MISP Sighting

![MISP sightings](https://dovehawk.io/images/misp_sightings.png "MISP Sightings")


## Official Source

https://dovehawk.io/

https://github.com/tylabs/dovehawk/


## Related Projects

http://www.misp-project.org/ MISP

https://www.bro.org/ Bro IDS


# Special Thanks

CanCyber.org for their support in releasing a generic MISP version of their Bro Module as open source.

Developers: Michael Kortekaas (original module), Tyler McLellan @tylabs (MISP combined import and sightings)

The entire MISP team and Alexandre Dulaunoy for adding the bro datatype to MISP.


# License

Copyright 2018 Cancyber Inc., Michael Kortekaas @mrkortek, Tyler McLellan @tylabs

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

