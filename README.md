# Dovehawk Bro Module

Threat Hunting with Bro and MISP


This module uses the the built-in Bro Intelligence Framework to load and monitor signatures from MISP automatically. Indicators are downloaded from MISP every 6 hours and hits, called sightings, are reported back to MISP immediately. The module also includes a customized version of Jan Grashoefer's expiration code to remove indicators after they are deleted from MISP.


Indicators are downloaded and read into memory.  Content signatures in signatures.sig are MISP Network Activity->bro items downloaded from MISP.  The event text should start with "MISP:".  Bro must be restarted to ingest the content signatures.  To do this automatically we recommend restarting bro using broctl and a restart cron described in included file INSTALL.md


Optional Slack.com web hook reporting.


## Screencaps

### Dovehawk Downloads Indicators From MISP

![Dovehawk signature download](https://dovehawk.io/images/dovehawk_launch.png "Dovehawk startup")

### Dovehawk Sighting Uploaded

![Dovehawk hit and sighting upload](https://dovehawk.io/images/dovehawk_hit.png "Dovehawk hit")

### MISP Sighting

![MISP sightings](https://dovehawk.io/images/misp_sightings.png "MISP Sightings")


### Slack Web Hook

![Slack Web Hook](https://dovehawk.io/images/slack_hit.png "Slack Output")


### Intel Item Expiration

![Items expiring](https://dovehawk.io/images/expire.png "Expiration")


## Sample Content Signature

```bro
signature eicar_test_content {
  ip-proto == tcp
  payload /.*X5O\!P%@AP\[4\\PZX54\(P\^\)7CC\)7\}\$EICAR\-STANDARD\-ANTIVIRUS\-TEST\-FILE\!\$H\+H\*/
  event "MISP: eicar test file in TCP plain text"
}
```
*Note: Bro's default setting is to buffer the (first 1024 bytes of a TCP connection)[https://www.bro.org/sphinx-git/frameworks/signatures.html] so signature's should be written with that in mind.*

## Indicator Expiration

Indicators are downloaded automatically every 6 hours and are assigned an expiry of 6.5 hours.  A check for expired indicators occurs every 4 hours to cleanup any expired indicators between downloads.  As indicators are reingested the expiration time is reset to 6.5 hours.  A message is now printed for each expired indicator.

If an indicator is hit after expiration but before the cleanup, it will trigger a hit/sighting, but the indicator is then deleted immediately so no further hits will occur.

Intervals are set in dovehawk.bro.

### Setting for expired indicator cleanup (should be less then signature_refresh_period)

```bro
redef Intel::item_expiration = 4 hr
```


### Setting for MISP download interval

```bro
global signature_refresh_period = 6hr &redef;
```


### Setting for indicator expiration: (should be slightly more than signature_refresh_period)

```bro
$expire = 6.5 hr,
```


## Official Source

<https://dovehawk.io/>

<https://github.com/tylabs/dovehawk/>


## Related Projects

<http://www.misp-project.org/> MISP

<https://www.bro.org/> Bro IDS


# Special Thanks

[CanCyber.org](https://cancyber.org) for their support in releasing a generic MISP version of their Bro Module as open source.

Developers: Michael Kortekaas [@mrkortek](https://twitter.com/mrkortek) (original module), Tyler McLellan [@tylabs](https://twitter.com/tylabs) (MISP combined import and sightings)

The entire MISP team and Alexandre Dulaunoy [@adulau](https://twitter.com/adulau) for adding the bro datatype to MISP.


# License

Copyright &copy; 2018 [Cancyber Inc.](https://cancyber.org/), Michael Kortekaas [@mrkortek](https://twitter.com/mrkortek), Tyler McLellan [@tylabs](https://twitter.com/tylabs)

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

