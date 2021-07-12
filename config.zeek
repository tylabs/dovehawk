module dovehawk;

redef Intel::item_expiration = 4.5 hr;

export { 

	global APIKEY = "===your misp key from Event Actions->Automation==="; 
	global MISP_URL = "https://yourmispsite.com/"; #script will append attributes/text/download/zeek
	global SLACK_URL = ""; #optional web hook for Slack
	global SIG_PREFIX = "MISP:"; #prefix for our signatures to hook alerts
	global MISP_ATTRIBUTE_URL = "attributes/bro/download/all"; #misp url for zeek export
	global CURL_INSECURE: bool = F; #set to T to ignore curl certificate errors


	# Maximum number of hits per indicator item before suppressing remote alerts
	global MAX_HITS: int = 100;

	# Cap dns queries and inbound hits (scans) (-1 for don't cap)
	global MAX_DNS_HITS: int = 2;
	global MAX_SCAN_HITS: int = 2;

	#ignore hits in SSL certificate when domains don't match the sni host
	global IGNORE_SNI_MISMATCH: bool = T;

	#skip signature download if recent
	global SKIP_SIGNATURE_DOWNLOAD: bool = T;
	global CLUSTER_ID = "dovehawk"; #source name for MISP sightings



}
