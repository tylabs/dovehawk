##! Dovehawk Zeek Module - Intel Framework Extension V 1.01.002  2019 08 02 @tylabs
# dovehawk.io
#
##! This script adds per item expiration for MISP intel items. This 
# version does not reset the base time when hits are detected. It is based
# on the intel-extensions package that is Copyright (c) 2016 by Jan Grashoefer
# https://github.com/J-Gras/intel-extensions

@load base/frameworks/intel
@load base/utils/directions-and-hosts
@load frameworks/intel/seen


module Intel;

export {
	## Default expiration interval for single intelligence items
	## A negative value disables expiration for these items.
	const per_item_expiration = -1min &redef;

	redef record MetaData += {
		expire: interval &default = per_item_expiration;

		## Internal value tracks time of item creation, last update.
		last_update: time  &default = network_time();

		hits:        int      &default = 0;
		dns_hits:        int      &default = 0;
		scan_hits:        int      &default = 0;


	};

}

@load ./dovehawk.bro


hook extend_match(info: Info, s: Seen, items: set[Item])
{
	local matches = |items|;
	for ( item in items )
	{
		local meta = item$meta;
		local conn = s$conn;
		local di = NO_DIRECTION;

		#print fmt("extend match: %s",item$indicator);
		#print meta;

		if (meta$source != "MISP") {
			next;
		}


		if ( meta$expire > 0 sec && meta$last_update + meta$expire < network_time() )
		{
			# Item already expired
			--matches;
			print fmt("Removing Expired Intel Item: %s",item$indicator);
			flush_all();
			remove(item, T);
			next;
		}

		if (Site::is_local_addr(conn$id$orig_h) || Site::is_private_addr(conn$id$orig_h) ) {
			di = OUTBOUND;
		} else if (Site::is_local_addr(conn$id$resp_h) || Site::is_private_addr(conn$id$resp_h) ) {
			di = INBOUND;
		}

		local services = |conn$service|;

		if (s$indicator_type == Intel::ADDR && di == INBOUND && services == 0) {
			item$meta$scan_hits += 1;
		}

		if (s$indicator_type == Intel::DOMAIN && s$where == DNS::IN_REQUEST) {
			item$meta$dns_hits += 1;
		}

		item$meta$hits += 1;
		insert(item);
		#print fmt("hits for item %d", item$meta$hits);

		# caps on low confidence network activity - dns requests and scans

		if (dovehawk::MAX_HITS > 0 && item$meta$hits > dovehawk::MAX_HITS) {
			print fmt("Suppressing Excessive hits for Intel Item That Hit: %s %d times", item$indicator, item$meta$hits);
			next;
		}
			
		if (dovehawk::MAX_DNS_HITS > 0 && item$meta$dns_hits > dovehawk::MAX_DNS_HITS) {
			print fmt("Suppressing Excessive hits for Intel Item That Hit In DNS Request: %s %d times", item$indicator, item$meta$dns_hits);
			next;
		}
		if (dovehawk::MAX_SCAN_HITS > 0 && item$meta$scan_hits > dovehawk::MAX_SCAN_HITS) {
			print fmt("Suppressing Excessive hits for Intel Item That Hit Inbound Scan: %s %d times", item$indicator, item$meta$scan_hits);
			next;
		}


		#trigger intel notice here instead of policy to have access to the metadata

		local hit = "ZEEK";
		if (info?$uid) {
			hit += fmt("|uid:%s",info$uid);
		}
		if (info?$ts) {
			hit += fmt("|ts:%f",info$ts);
		}
		
		if (info?$id) {
			hit += fmt("|orig_h:%s|orig_p:%s|resp_h:%s|resp_p:%s",info$id$orig_h,info$id$orig_p,info$id$resp_h,info$id$resp_p);
		}
		
		if (s?$fuid) {
			hit += fmt("|fuid:%s",s$fuid);
		}
		if (s?$where) {
			hit += fmt("|msg: Intel hit %s at %s", s$indicator, s$where);
		}
		hit += fmt(" [%s]",meta$desc);
		hit += fmt(" (%s)",meta$url);


		# extended service information 2019 06 17 add packet sizes, http url, smtp envelope and https sni

		if (s?$node) {
			hit += fmt("|node:%s",s$node);
		}

		if (di == OUTBOUND) {
			hit += "|d:OUTBOUND";
		} else if (di == INBOUND) {
			hit += "|d:INBOUND";
		}


		if (conn?$service) {
			hit += "|service:";
			local service = conn$service;
			for ( ser in service ) {
				hit += fmt("%s,",ser);
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
				#check for domain mismatch for CloudFlare situations where multiple domains are on the same certificate
				if (dovehawk::IGNORE_SNI_MISMATCH && s$where == X509::IN_CERT && (string_cat("www", ssl$server_name) != item$indicator && ssl$server_name != item$indicator && ssl$server_name != string_cat("www", item$indicator) ) ) {
					next;
				}
			}
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


		dovehawk::register_hit(item$indicator, hit);
		dovehawk::slack_hit(item$indicator, hit);
		print "Intel Signature Hit ===> " + item$indicator;
		print "   Metadata ===> " + hit;

	}
	
	if ( matches < 1 ) {
		break;
	}
}




hook item_expired(indicator: string, indicator_type: Type, metas: set[MetaData])
{

	#print fmt("hook item_expired: %s",indicator);
	for ( meta in metas )
	{
		if (meta$source != "MISP") {
			next;
		}
	
		# Check for expired items
		if ( meta$expire > 0 sec && meta$last_update + meta$expire < network_time() )
		{
			# Recreate the item from the indicator and meta
			local item: Intel::Item = [
				$indicator = indicator,
				$indicator_type = indicator_type,
				$meta = meta
			];
		
			print fmt("Removing Expired Intel Item: %s",indicator);
			flush_all();
			remove(item, T);
		}
	}
}
