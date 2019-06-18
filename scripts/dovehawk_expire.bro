##! Dovehawk Zeek Module - Intel Framework Extension V 1.00.003  2019 06 17 @tylabs
# dovehawk.io
#
##! This script adds per item expiration for MISP intel items. This 
# version does not reset the base time when hits are detected. It is based
# on the intel-extensions package that is Copyright (c) 2016 by Jan Grashoefer
# https://github.com/J-Gras/intel-extensions

@load base/frameworks/intel

module Intel;

export {
	## Default expiration interval for single intelligence items
	## A negative value disables expiration for these items.
	const per_item_expiration = -1min &redef;

	redef record MetaData += {
		expire: interval &default = per_item_expiration;

		## Internal value tracks time of item creation, last update.
		last_update: time  &default = network_time();
	};

}

@load ./dovehawk.bro


hook extend_match(info: Info, s: Seen, items: set[Item])
{
	local matches = |items|;
	for ( item in items )
	{
		local meta = item$meta;
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


		#trigger intel notice here instead of policy to have access to the metadata

	
		local hit = "BRO";
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


		local conn = s$conn;

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
		}

		if (conn?$resp) {
			local resp = conn$resp;
			if (resp?$size) {
				hit += fmt("|resp:%s",resp$size);
			}
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
