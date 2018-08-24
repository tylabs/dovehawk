# Dovehawk Content Signatures - Sig events should have "MISP:" prefix

signature eicar_test_content {
  ip-proto == tcp
  payload /.*X5O\!P%@AP\[4\\PZX54\(P\^\)7CC\)7\}\$EICAR\-STANDARD\-ANTIVIRUS\-TEST\-FILE\!\$H\+H\*/
  event "MISP: eicar test file in TCP"
}


signature cancyber_test_content {
  ip-proto == tcp
  payload /.*991CANCYBER_TEST_BAD_SIGNATURE991/
  event "MISP: test content in TCP"
}
