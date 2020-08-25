# Dovehawk Content Signatures - Sig events should have "MISP:" prefix


signature eicar_test_content {
  ip-proto == tcp
  payload /.*X5O\!P%@AP\[4\\PZX54\(P\^\)7CC\)7\}\$EICAR\-STANDARD\-ANTIVIRUS\-TEST\-FILE\!\$H\+H\*/
  event "MISP: eicar test file in TCP"
}

signature gh0st {
  ip-proto == tcp
  payload /^Gh0st/
  tcp-state originator
  event "MISP: Gh0stRat header in tcp"
}

# Plugx Variants
signature plugx_http {
  ip-proto == tcp
  tcp-state established,originator
  payload /POST /
  http-request-header /.{2,32}: 61456/
  event "MISP: PLUGX Beacon HTTP "  
}

# China chopper https://www.fireeye.com/blog/threat-research/2013/08/breaking-down-the-china-chopper-web-shell-part-ii.html
signature chopper_http_post {
  ip-proto == tcp
  tcp-state established,originator
  payload /POST /
  http-request-header /X-Forwarded-For/
  payload /.*FromBase64String/
  event "MISP: China Chopper POST"  
}