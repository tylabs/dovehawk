##! Dovehawk Zeek Module V 1.01.002  2019 08 02 @tylabs dovehawk.io
# This module downloads Zeek Intelligence Framework items and Signature Framework Zeek items from MISP.
# Sightings are reported back to MISP and optionally to a Slack webhook.
# This script could be easily modified to send hits to a central database / web dashboard or to add in indicators from other sources.


module dovehawk;

@load ../config.bro
@load ./dovehawk_expire.bro

@load-sigs ../signatures/signatures.sig

@load frameworks/intel/seen
@load base/frameworks/intel
@load frameworks/intel/do_notice
@load base/utils/directions-and-hosts


export {
	global DH_VERSION = "1.01.002";

	#removed randomness added to internal + double_to_interval(rand(1200))
	global load_signatures: function();
	global register_hit: function(hitvalue: string, desc: string);
	global slack_hit: function(hitvalue: string, desc: string);

}



# Modelled on the original function from ActiveHTTP but they stripped out the newlines and joined
# everything together. Need to keep the original string vector to process individual lines.
# Original Source: https://github.com/bro/bro/blob/master/scripts/base/utils/active-http.bro

function request2curl(r: ActiveHTTP::Request, bodyfile: string, headersfile: string): string
{
	local cmd = fmt("curl --header \"Authorization: %s\" -s -g -o \"%s\" -D \"%s\" -X \"%s\"",
			str_shell_escape(dovehawk::APIKEY),
	                str_shell_escape(bodyfile),
	                str_shell_escape(headersfile),
	                str_shell_escape(r$method));


	cmd = fmt("%s -m %.0f", cmd, r$max_time);

	if ( r?$client_data )
		cmd = fmt("%s -d @-", cmd);

	if ( r?$addl_curl_args )
		cmd = fmt("%s %s", cmd, r$addl_curl_args);

	cmd = fmt("%s \"%s\"", cmd, str_shell_escape(r$url));
	# Make sure file will exist even if curl did not write one.
	cmd = fmt("%s && touch %s", cmd, str_shell_escape(bodyfile));

	return cmd;
}

function strings_request(req: ActiveHTTP::Request): string_vec
{
	local tmpfile     = "/tmp/zeek-activehttp-" + unique_id("");
	local bodyfile    = fmt("%s_body", tmpfile);
	local headersfile = fmt("%s_headers", tmpfile);

	local cmd = request2curl(req, bodyfile, headersfile);
	local stdin_data = req?$client_data ? req$client_data : "";
	
	return when ( local result = Exec::run([$cmd=cmd, $stdin=stdin_data, $read_files=set(bodyfile, headersfile)]) )
	{
		# If there is no response line then nothing else will work either.
		if ( ! (result?$files && headersfile in result$files) )
		{
			print "download error 1";
			Reporter::error(fmt("There was a failure when requesting \"%s\" with ActiveHTTP.", req$url));
			return vector();  # Empty string vector indicates failure
		}
		
		return result$files[bodyfile];
	}
}


# SIGNATURE DOWNLOAD FUNCTIONS
function load_sigs_misp() {
	local request: ActiveHTTP::Request = [
		$url = MISP_URL + "attributes/text/download/zeek"
	];
	local fname = "signatures.sig";

	local check = "find " + @DIR + "/../signatures/" + fname + " -mmin +60 | egrep .";
	when ( local r = Exec::run([$cmd=check]) )
	{
        	if (r$exit_code != 0) {
			print "INFO: file is recent not updating: " + fname;
			return;
        	}


		print "Downloading Signatures...";
		when ( local lines = strings_request(request) ) {
			if (|lines| >= 0 ) {
				print "Updating File " + fname;
				# Directory variable appends period for some reason
				# but guard that it may not exist in future.
				local tmp_fname = @DIR + "/../signatures/." + fname;
				local final_fname = @DIR + "/../signatures/" + fname;
				local f = open(tmp_fname);
				local cnt = 0;
				enable_raw_output(f);
				print f,"# Dovehawk.io Content Signatures - Sig events should have \"MISP:\" prefix\n\n";

				for (line in lines) {
					# don't write lines with double ## at start
					if (|lines[line]| >= 1 && lines[line][0] != "#" && lines[line][1] != "#") {
						print f,gsub(lines[line], /\x0d/, "") + "\n"; #remove extra newlines Zeek doesn't like
						if (sub_bytes(lines[line], 0, 10) == "signature ")
							cnt += 1;
					}
				}
			
				close(f);
			
				if (unlink(final_fname)) {
					if (rename(tmp_fname,final_fname)) {
						print "    Finished Updating File: " + fname;
					} else {
						print "ERROR: Could not rename tmp file for signature update: " + tmp_fname;
					}
				} else {
					print "WARNING: Could not unlink file for signature update: " + final_fname;
				}
				print fmt("    Signatures file contains: %d signatures", |cnt|);

			} else {
				print "WARNING: Signature update download failed";
			}
		}
	}

}


# INDICATOR DOWNLOAD FUNCTIONS - Note that
# total line count for signature downloads includes possible comments - output stored in stdout.log to
# be used for verification checking if necessary.

# Special option to load all the hash strings combined as a single file
function load_all_misp() {
	local request: ActiveHTTP::Request = [
		$url = MISP_URL + "attributes/bro/download/all"
	];

    print "Downloading Indicators...";
	
    when ( local lines = strings_request(request) ) {
		if (|lines| > 0 ) {
			print "Processing Indicators...";
			print fmt("Number of Indicators %d", |lines|);
	
			local domaincnt = 0;
			local ipcnt = 0;
			local subnetcnt = 0;
			local urlcnt = 0;
			local softwarecnt = 0;
			local emailcnt = 0;
			local usercnt = 0;
			local hashcnt = 0;
			local filenamecnt = 0;
		
			
			for (line in lines) {
				local sig = strip(lines[line]);

				#local parts: string_array;
				local parts = split_string(sig, /\t/);


				# check for lines starting with # to ignore comments
				if (|parts| > 3 && parts[0][0] != "#") {
					local zero: int = 0;
					local dh_meta : Intel::MetaData = [
						$source = "MISP",
						$do_notice = T,
						$expire = Intel::item_expiration,
						$desc = parts[3],
						$url = parts[4],
						$hits = zero
					];
					local item : Intel::Item = [
						$indicator = parts[0],
						$indicator_type = Intel::DOMAIN,
						$meta = dh_meta
					];


					if (parts[1] == "Intel::ADDR") {
						item$indicator_type = Intel::ADDR;
						ipcnt += 1;
					} else if (parts[1] == "Intel::SUBNET") {
						item$indicator_type = Intel::SUBNET;
						subnetcnt += 1;
					} else if (parts[1] == "Intel::URL") {
						item$indicator_type = Intel::URL;
						urlcnt += 1;
					} else if (parts[1] == "Intel::SOFTWARE") {
						item$indicator_type = Intel::SOFTWARE;
						softwarecnt += 1;
					} else if (parts[1] == "Intel::EMAIL") {
						item$indicator_type = Intel::EMAIL;
						emailcnt += 1;
					} else if (parts[1] == "Intel::USER_NAME") {
						item$indicator_type = Intel::USER_NAME;
						usercnt += 1;
					} else if (parts[1] == "Intel::CERT_HASH") {
						item$indicator_type = Intel::FILE_HASH; #cert hash isn't really implemented
						hashcnt += 1;
					} else if (parts[1] == "Intel::PUBKEY_HASH") {
						item$indicator_type = Intel::FILE_HASH;
						hashcnt += 1;
					} else if (parts[1] == "Intel::FILE_HASH") {
						item$indicator_type = Intel::FILE_HASH;
						hashcnt += 1;
					} else if (parts[1] == "Intel::FILE_NAME") {
						item$indicator_type = Intel::FILE_NAME;
						filenamecnt += 1;
					} else if (parts[1] == "Intel::DOMAIN")
						domaincnt += 1;
					else
						next;

					Intel::insert(item);
				}
			}

			print " Intel Indicator Counts:";
			print fmt("    Intel::DOMAIN:    %d", domaincnt);
			print fmt("    Intel::ADDR:        %d", ipcnt);
			print fmt("    Intel::URL:        %d", urlcnt);
			print fmt("    Intel::SUBNET:    %d", subnetcnt);
			print fmt("    Intel::SOFTWARE:  %d", softwarecnt);
			print fmt("    Intel::EMAIL:     %d", emailcnt);
			print fmt("    Intel::USER_NAME: %d", usercnt);
			print fmt("    Intel::FILE_HASH: %d", hashcnt);
			print fmt("    Intel::FILE_NAME: %d",filenamecnt);
			print "Finished Processing Indicators";


		} else {
			print "indicator download error";
		}
    }
}






# SIGHTINGS FUNCTIONS
function register_hit(hitvalue: string, desc: string) {
    local url_string = MISP_URL + "sightings/add/";
    local post_data = fmt("{\"source\": \"dovehawk.io\", \"value\": \"%s\"}", hitvalue);
    #print post_data;

    local request: ActiveHTTP::Request = [
	$url=url_string,
	$method="POST",
	$client_data=post_data,
	$addl_curl_args = fmt("--header \"Authorization: %s\" --header \"Content-Type: application/json\" --header \"Accept: application/json\"", str_shell_escape(dovehawk::APIKEY))
    ];
	
    when ( local resp = ActiveHTTP::request(request) ) {
		
		if (resp$code == 200) {
			#print "  Sighting added";
			print fmt("  Sighting Result ===> %s", resp$body);
		} else {
			#print "  Sighting failed, item not found.";
			print fmt("  Sighting FAILED ===> %s", resp);
		}
    }
	
}





function slack_hit(hitvalue: string, desc: string) {
    local url_string = SLACK_URL;
    if (SLACK_URL == "")
    	return;
    local post_data = fmt("{\"text\": \"%s\", \"attachments\": \"%s\"}", escape_string(desc), escape_string(desc));
    #print post_data;

    local request: ActiveHTTP::Request = [
	$url=url_string,
	$method="POST",
	$client_data=post_data,
	$addl_curl_args = " --header \"Content-Type: application/json\" --header \"Accept: application/json\""
    ];
	
    when ( local resp = ActiveHTTP::request(request) ) {
		
		if (resp$code == 200) {
			#print "  Slack web hook success";
		} else {
			#print "  Slack web hook FAILED";
		}
    }
	
}





function startup_intel() {
	# WARNING: network_time function seems to return 0 until after Zeek is fully initialized
	local zero: int = 0;
	local startup_meta : Intel::MetaData = [
		$source = "MISP",
		$do_notice = T,
		$expire = -1 min,
		$last_update = network_time(),
		$url = "",
		$hits = zero,
		$desc = "local dummy item"

	];
	
	local item : Intel::Item = [
		$indicator = "",
		$indicator_type = Intel::DOMAIN,
		$meta = startup_meta
	];
	
	# IMPORTANT: Need at least one registered otherwise item_expired hook may not be called.
	# This fake intel item MUST be setup in order for the expiry feature to work properly.
	# The expiry hook seems to be removed before the load_signatures function is called
	# unless an item exists.
	item$indicator = "www.fakedovehawkurl.zzz";
	Intel::insert(item);
	
}



event do_reload_signatures() {
@if( /^2\./ in bro_version() )
	if (bro_is_terminating()) {

		print "Zeek Terminating - Cancelling Scheduled Signature Downloads";
	} else {

		load_signatures();
		
		schedule signature_refresh_period { do_reload_signatures() };

	}
@else
	if (zeek_is_terminating()) {
		print "Zeek Terminating - Cancelling Scheduled Signature Downloads";
	} else {

		load_signatures();
		
		schedule signature_refresh_period { do_reload_signatures() };
	}

@endif

}


function load_signatures() {

	print fmt("Downloading Signatures %s [%s]", strftime("%Y/%m/%d %H:%M:%S", network_time()), DH_VERSION);

	# print health - dropped packets may mean - the -C option is needed or a cluster to handle the bandwidth
	local ns = get_net_stats();
	print fmt("NETSTATS: pkts_dropped=%d  pkts_recvd=%d  pkts_link=%d  bytes_recvd=%d", ns$pkts_dropped, ns$pkts_recvd, ns$pkts_link, ns$bytes_recvd);

	slack_hit("", fmt("%s: Dovehawk: Zeek %s Downloading Signatures %s [%s]. pkts_dropped=%d  pkts_recvd=%d  pkts_link=%d  bytes_recvd=%d", gethostname(), bro_version(), strftime("%Y/%m/%d %H:%M:%S", network_time()), DH_VERSION, ns$pkts_dropped, ns$pkts_recvd, ns$pkts_link, ns$bytes_recvd));
	
	print fmt("Local Directory: %s", @DIR);
	print fmt("MISP Server: %s", MISP_URL);

	if (MISP_URL == "https://yourmispsite.com/" || MISP_URL == "") {
		print "Please edit misp_config.bro to include your MISP API key and URL";
		exit(1);
	}
		
	# Load all contains all MISP Zeek output combined
	load_all_misp();

	# Download Zeek content signatures MISP->Network Activity->Zeek items
	load_sigs_misp();
	
	# Force output into stdout.log when using broctl
	flush_all();
}


event signature_match(state: signature_state, msg: string, data: string)
{

	local sig_id = state$sig_id;
	
	# Ensure this is a MISP signature
	if (strstr(msg,"MISP:") == 0) {
		return;
	}
		
	local src_addr: addr;
	local src_port: port;
	local dst_addr: addr;
	local dst_port: port;
	local di = NO_DIRECTION;


	if ( state$is_orig )
	{
		src_addr = state$conn$id$orig_h;
		src_port = state$conn$id$orig_p;
		dst_addr = state$conn$id$resp_h;
		dst_port = state$conn$id$resp_p;
	}
	else
	{
		src_addr = state$conn$id$resp_h;
		src_port = state$conn$id$resp_p;
		dst_addr = state$conn$id$orig_h;
		dst_port = state$conn$id$orig_p;
	}
	
	local hit = "ZEEK";
	if (state$conn?$uid) {
		hit += fmt("|uid:%s",state$conn$uid);
	}
	if (state$conn?$http && state$conn$http?$ts) {
		hit += fmt("|ts:%f",state$conn$http$ts);
	}
	
	hit += fmt("|orig_h:%s|orig_p:%s|resp_h:%s|resp_p:%s",src_addr,src_port,dst_addr,dst_port);


	local conn = state$conn;

	if (Site::is_local_addr(conn$id$orig_h) || Site::is_private_addr(conn$id$orig_h) ) {
		di = OUTBOUND;
	} else if (Site::is_local_addr(conn$id$resp_h) || Site::is_private_addr(conn$id$resp_h) ) {
		di = INBOUND;
	}


	if (di == OUTBOUND) {
		hit += "|d:OUTBOUND";
	} else if (di == INBOUND) {
		hit += "|d:INBOUND";
	}

	if (conn?$service) {
		hit += "|service:";
		local service = conn$service;
		local servicename: string = "";
		for ( ser in service ) {
			servicename += fmt("%s,",ser);
		}
		if (|servicename| > 0) {
			hit += cut_tail(servicename, 1);
		}
	}

	if (conn?$orig) {
		local orig = conn$orig;
		if (orig?$size) {
			hit += fmt("|orig:%s",orig$size);
		}
		if (orig?$num_pkts) {
			hit += fmt("|o_pkts:%s",orig$num_pkts);
		}
		if (orig?$num_bytes_ip) {
			hit += fmt("|o_bytes:%s",orig$num_bytes_ip);
		}
		if (orig?$state) {
			hit += fmt("|o_state:%s",orig$state);
		}
	}

	if (conn?$resp) {
		local resp = conn$resp;
		if (resp?$size) {
			hit += fmt("|resp:%s",resp$size);
		}
		if (resp?$num_pkts) {
			hit += fmt("|r_pkts:%s",resp$num_pkts);
		}
		if (resp?$num_bytes_ip) {
			hit += fmt("|r_bytes:%s",resp$num_bytes_ip);
		}
		if (resp?$state) {
			hit += fmt("|r_state:%s",resp$state);
		}
	}

	if (conn?$start_time) {
		hit += fmt("|start_time:%s",conn$start_time);
	}

	if (conn?$duration) {
		hit += fmt("|duration:%s",conn$duration);
	}

	if (conn?$http) {
		local http = conn$http;
		if (http?$host) {
			hit += fmt("|host:%s",http$host);
		}
		if (http?$uri) {
			hit += fmt("|uri:%s",http$uri);
		}
		if (http?$method) {
			hit += fmt("|method:%s",http$method);
		}
	}

	if (conn?$ssl) {
		local ssl = conn$ssl;
		if (ssl?$server_name) {
			hit += fmt("|sni:%s",ssl$server_name);
			if (ssl?$issuer) {
				hit += fmt("|issuer:%s",ssl$issuer);
			}
		}

		if (conn?$smtp) {
			local smtp = conn$smtp;
			if (smtp?$from) {
				hit += fmt("|from:%s",smtp$from);
			}
			if (smtp?$subject) {
				hit += fmt("|subject:%s",smtp$subject);
			}
			if (smtp?$rcptto) {
				hit += fmt("|to:%s",smtp$rcptto);
			}
		}

		if (conn?$dns) {
			local dns = conn$dns;
			if (dns?$qtype_name) {
				hit += fmt("|q:%s",dns$qtype_name);
			}
			if (dns?$answers) {
				hit += fmt("|answers:%s",dns$answers);
			}
		}
	}


	hit += "|sigid:" + sig_id + "|msg:" + msg;
	
	# This should always be true but check just in case
	if (|hit| < 1800) {
		# Trim the matched data down to fit the sql hit structure limit
		if ( (|data| + |hit|) > 2000 )
			data = fmt("%s...", sub_bytes(data, 0, 2000-|hit|));

		hit += "|data:" + data;
	}
	
	register_hit("%" + sig_id + "%", hit); #%wildcards required for search

	print "Content Signature Hit ===> " + sig_id;
	print "   Metadata ===> " + hit;
	slack_hit(msg, hit);

}

# version 3 will deprecate some of the bro_ functions
@if( /^2\./ in bro_version() )
event bro_init()
{
	#run signature downloads on the manager only. indicators are automatically shared to workers
	if ( Cluster::is_enabled() && Cluster::local_node_type() == Cluster::MANAGER ) {
		startup_intel();
		event do_reload_signatures();
	} else if ( !Cluster::is_enabled() ) {
		startup_intel();
		schedule signature_refresh_period {do_reload_signatures()};
	}
}
@else
event zeek_init()
{
	#run signature downloads on the manager only. indicators are automatically shared to workers
	if ( Cluster::is_enabled() && Cluster::local_node_type() == Cluster::MANAGER ) {
		startup_intel();
		event do_reload_signatures();
	} else if ( !Cluster::is_enabled() ) {
		startup_intel();
		schedule signature_refresh_period {do_reload_signatures()};
	}
}
@endif


event file_new(f: fa_file)
{
	Files::add_analyzer(f, Files::ANALYZER_MD5);
	Files::add_analyzer(f, Files::ANALYZER_SHA1);
	Files::add_analyzer(f, Files::ANALYZER_SHA256);
}

