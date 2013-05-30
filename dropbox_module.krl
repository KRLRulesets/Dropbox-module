ruleset dropbox_module {
  meta {
    name "Dropbox module"
    description <<
Functions and actions for using Dropbox from a KRl ruleset. 
    >>
    author "Phil Windley"
    logging off

    config using app_key, app_secret, access_token, access_token_secret

    provides create_oauth_header_value, raw_core_api_call, core_api_call, get_request_token, get_access_token, generate_authorization_url, decode_content
  }

  global {
    dropbox_base_url = "https://api.dropbox.com/1";

    create_oauth_header_value = function(key, key_secret, token, token_secret) {
       'OAuth oauth_version="1.0", oauth_signature_method="PLAINTEXT", oauth_consumer_key="'+ 
       key +
       (token => '", oauth_token="'+token+'", ' | '", ') +
       'oauth_signature="' +
       key_secret +
       '&' +
       token_secret +
       '"'; //" 
    }

    raw_core_api_call = function(method) {
      http:get(dropbox_base_url+method, 
               {},
               {"Authorization" : create_oauth_header_value(app_key, 
	                                                    app_secret, 
							    access_token, 
							    access_token_secret)
	       });
    }

    core_api_call = function(method) {
      result = raw_core_api_call(method);
      result{'content'}.decode();
    }

    get_request_token = defaction() {
      http:post(dropbox_base_url+"/oauth/request_token") with
        body = {} and
        headers = {"Authorization" : create_oauth_header_value(app_key, app_secret)
		  } and
        autoraise = "request_token"
    }


    get_access_token = defaction(request_token, request_token_secret) {
      http:post(dropbox_base_url+"/oauth/access_token") with
        body = {} and
        headers = {"Authorization" : create_oauth_header_value(app_key, 
	                                                       app_secret, 
							       request_token, 
							       request_token_secret)
		  } and
        autoraise = "access_token"		   

    }

    generate_authorization_url = function(oauth_token) {
      callback = 'http://' + meta:host() + '/blue/event/oauth/response/' + meta:rid() + '/' + math:random(999999);
      "https://www.dropbox.com/1/oauth/authorize?oauth_token=" + oauth_token + "&oauth_callback=" + callback;
    }

    is_authorized = function {
        account_info_result = raw_core_api_call('/account/info');
	account_info_result{'status_code'} eq '200';
    }	

    decode_content = function(content) {
      content.split(re/&/).map(function(x){x.split(re/=/)}).collect(function(a){a[0]}).map(function(k,v){a = v[0];a[1]})
    }
  }


}