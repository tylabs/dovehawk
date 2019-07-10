module dovehawk;

redef Intel::item_expiration = 4.5 hr;

export { 

	global APIKEY = "===your misp key from Event Actions->Automation==="; 
	global MISP_URL = "https://yourmispsite.com/"; #attributes/bro/download/all
	global SLACK_URL = ""; #optional web hook for Slack

	# Maximum number of hits per indicator item before suppressing remote alerts
	global MAX_HITS: int = 100;

	# Cap dns queries and inbound hits (scans) (-1 for don't cap)
	global MAX_DNS_HITS: int = 2;
	global MAX_SCAN_HITS: int = 2;

	#ignore hits in SSL certificate when domains don't match the sni host
	global IGNORE_SNI_MISMATCH: bool = T;

	global signature_refresh_period = 4hr  &redef;


}
