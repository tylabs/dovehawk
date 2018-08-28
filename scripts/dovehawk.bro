# Dovehawk Bro Module V 1.00.000  2018 08 23

module dovehawk;

@load ../misp_config.bro
@load ./dovehawk_expire.bro

@load-sigs ../signatures/signatures.sig

@load frameworks/intel/seen
@load frameworks/intel/do_notice

redef Intel::item_expiration = 7hr;

export {
	global DH_VERSION = "1.00.000";

	global dh_meta : Intel::MetaData = [
		$source = "MISP",
		$do_notice = T,
		$dh_expire = 7hr,
		$desc = "",
		$url = ""
	];
	
	global signature_refresh_period = 6hr &redef;
	global load_signatures: function();
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
	local tmpfile     = "/tmp/bro-activehttp-" + unique_id("");
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
		$url = MISP_URL + "attributes/text/download/bro"
	];
	local fname = "signatures.sig";

	print "Downloading Signatures...";
	when ( local lines = strings_request(request) ) {
		if (|lines| >= 0 ) {
			print "Updating File " + fname;
			# Directory variable appends period for some reason
			# but guard that it may not exist in future.
			local tmp_fname = @DIR + "/../signatures/." + fname;
			local final_fname = @DIR + "/../signatures/" + fname;
			local f = open(tmp_fname);
			enable_raw_output(f);
			print f,"# Dovehawk.io Content Signatures - Sig events should have \"MISP:\" prefix\n\n";

			for (line in lines) {
				print f,gsub(lines[line], /\x0d/, "") + "\n"; #remove extra newlines bro doesn't like
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
			print fmt("    Signatures file contains: %d lines", |lines|);

		} else {
			print "WARNING: Signature update download failed";
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

				if (|parts| > 3) {
					local item : Intel::Item = [
						$indicator = parts[0],
						$indicator_type = Intel::DOMAIN,
						$meta = dh_meta
					];

					item$meta$desc = parts[4];
					item$meta$url = parts[5];


					#For debugging print the items
					##print fmt("   %s=%s", parts[1], parts[0]);




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
			print fmt("    Intel::IP:        %d", ipcnt);
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
    local post_data = fmt("{\"value\": \"%s\"}", hitvalue);

    local request: ActiveHTTP::Request = [
	$url=url_string,
	$method="POST",
	$client_data=post_data,
	$addl_curl_args = fmt("--header \"Authorization: %s\" --header \"Content-Type: application/json\" --header \"Accept: application/json\"", str_shell_escape(dovehawk::APIKEY))
    ];
	
    when ( local resp = ActiveHTTP::request(request) ) {
		
		if (resp$code == 200) {
			print fmt("  Sighting Result ===> %s", resp$body);
		} else {
			print fmt("  Sighting FAILED ===> %s", resp);
		}
    }
	
}

# Need to check info variables for null since they are all optional
# Use a | separator since this is not as likely to be part of the data
# Hit data should be kept below 1000 bytes or it will be rejected

hook Notice::policy(n: Notice::Info) &priority=3 {
	if (n$note == Intel::Notice) {
		# Each notice contains an email section with the meta source included
		# Check on this value to ensure only hits are registered
		local isDT = F;
		for (ebs in n$email_body_sections) {
			if (strstr(n$email_body_sections[ebs],"MISP") > 1) {
				isDT = T;
				break;
			}
		}
		
		if (! isDT) {
			return;
		}
	
		local hit = "BRO";
		if (n?$uid) {
			hit += fmt("|uid:%s",n$uid);
		}
		if (n?$ts) {
			hit += fmt("|ts:%f",n$ts);
		}
		
		if (n?$id) {
			hit += fmt("|orig_h:%s|orig_p:%s|resp_h:%s|resp_p:%s",n$id$orig_h,n$id$orig_p,n$id$resp_h,n$id$resp_p);
		} else {
			if (n?$src) {
				hit += fmt("|src:%s",n$src);
			}
			if (n?$dst) {
				hit += fmt("|dst:%s",n$dst);
			}
			if (n?$p) {
				hit += fmt("|p:%s",n$p);
			}
		}
		
		if (n?$fuid) {
			hit += fmt("|fuid:%s",n$fuid);
		}
		if (n?$msg) {
			hit += "|msg:" + n$msg;
		}
		register_hit(n$sub, hit);
		print "Intel Signature Hit ===> " + n$sub;
		print "   Metadata ===> " + hit;

	}
}



event do_reload_signatures() {
	if (bro_is_terminating()) {
		print "Bro Terminating - Cancelling Scheduled Signature Downloads";
	} else {
		load_signatures();
		
		schedule signature_refresh_period { do_reload_signatures() };
	}
}


function load_signatures() {
	print fmt("Downloading Signatures %s", strftime("%Y/%m/%d %H:%M:%S", network_time()));
	
	print fmt("Local Directory: %s", @DIR);
	print fmt("MISP Server: %s", MISP_URL);
	
	# Need to force update this each time to ensure it's not a static constant or zero
	dh_meta$dh_last_update = network_time();
	
	# Load all contains all MISP bro output combined
	load_all_misp();

	# Download bro content signatures MISP->Network Activity->bro items
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
	
	local hit = "BRO";
	if (state$conn?$uid) {
		hit += fmt("|uid:%s",state$conn$uid);
	}
	if (state$conn?$http && state$conn$http?$ts) {
		hit += fmt("|ts:%f",state$conn$http$ts);
	}
	
	hit += fmt("|orig_h:%s|orig_p:%s|resp_h:%s|resp_p:%s",src_addr,src_port,dst_addr,dst_port);
	
	hit += "|sigid:" + sig_id + "|msg:" + msg;
	
	# This should always be true but check just in case
	if (|hit| < 800) {
		# Trim the matched data down to fit the sql hit structure limit
		if ( (|data| + |hit|) > 900 )
			data = fmt("%s...", sub_bytes(data, 0, 900-|hit|));

		hit += "|data:" + data;
	}
	
	register_hit(state$sig_id,hit);

	print "Content Signature Hit ===> " + state$sig_id;
}


event bro_init()
{
	schedule signature_refresh_period { do_reload_signatures() };
}


event file_new(f: fa_file)
{
	Files::add_analyzer(f, Files::ANALYZER_MD5);
	Files::add_analyzer(f, Files::ANALYZER_SHA1);
	Files::add_analyzer(f, Files::ANALYZER_SHA256);
}

