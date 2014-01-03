ruleset dropbox_module_example {
  meta {
    name "Dropbox module example"
    description <<
Shows how to use the Dropbox module
>>
    author "Phil Windley"
    logging on

    sharing on
    key dropbox {
       "app_key" : "b010gf6m599rrtx",
       "app_secret" : "uqftxkv9qni4vpz"
    }      


    use module a169x701 alias CloudRain
//    use module b16x5 alias dropbox_keys
    use module b16x0 alias dropbox with
         app_key = keys:dropbox('app_key') and	   
         app_secret = keys:dropbox('app_secret')

    key aws {
       "AWSAccessKey": "0GEYA8DTVCB3XHM819R2",
       "AWSSecretKey": "I4TrjKcflLnchhsEzjlNju/s9EHiqdOScbyqGgn+"
    }
    
    use module a41x174 alias AWSS3
      with AWSKeys = keys:aws()


    provides dropbox_get_file

  }

  global {

    my_tokens = {'access_token' : ent:access_token,
              	 'access_token_secret' : ent: access_token_secret
	     	};

    authorized = dropbox:is_authorized(my_tokens);

    dropbox_get_file = function(filename, chunk) {
      chunk_size = 100;
      first_byte_offset = chunk * chunk_size;
      last_byte_offset = first_byte_offset + (chunk_size-1);

      value_debug = "Tokens: " + my_tokens.encode() + "\n" +
                     "Dropbox keys" + keys:dropbox('app_key') + " ; " + keys:dropbox("app_secret") + "\n" +
                     "Header: " + dropbox:return_header(my_tokens);

      value_info = dropbox:core_api_call('/metadata/sandbox/?list=true', my_tokens);

      itemURL    = AWSS3:makeAwsUrl("install.kynetx.com/bigtag","logo.jpg");

      aws_values = {
	'itemURL' : itemURL,
        'status': 'success',
	'test_descriptions' : test_desc
      };

      getItemValue = http:get(itemURL).pick("$.content");

      value = getItemValue;

//      raw_value = (dropbox:raw_file_api_call('/files/sandbox/'+filename, my_tokens));
//      value = raw_value.pick("$.content");
      
 //          http:get('https://api-content.dropbox.com/1/files/sandbox/' + filename,
 //      	          {},
 //          	 {"Authorization" : create_oauth_header_value(
 //       	          		       keys:dropbox('app_key'),
 //       	         		       keys:dropbox('app_secret'),
 //       	         		       my_tokens{'access_token'}, 
 //       	 			       my_tokens{'access_token_secret'}) //,
 // //                   "Range" : 'bytes=' + first_byte_offset + '-' + last_byte_offset
 //                });

      value

     }


  }

  rule get_request_token { 
    select when web cloudAppSelected

    if(not authorized) then {
      dropbox:get_request_token();	   
    }  

    fired{
      log "<<<<<<<<<<<<<<<<<<<<<<<<<<<>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>";
      log "Tokens: " + my_tokens.encode();
      log "Header: " + dropbox:return_header(my_tokens);
      log "<<<<<<<<<<<<<<<<<<<<<<<<<<<>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>";
    }
  }

  rule process_request_token {
    select when http post label "request_token"
    pre {
      tokens = event:attr("status_code") eq '200' => dropbox:decode_content(event:attr('content')) | {};

      url = dropbox:generate_authorization_url(tokens{'oauth_token'} || 'NO_TOKEN');
      my_html = <<
<div style="margin: 0px 0px 20px 20px">
<a href="#{url}" class="btn btn-large btn-primary">Click to Link to Dropbox<a>
</div>
>>;
    }
    {
//      notify("Link to Dropbox", tokens.encode() + '<br/>' + url) with sticky=true;
      CloudRain:createLoadPanel("Link to Dropbox", {}, my_html);
    }
    always {
      log "<<<<<<<<<<<<<<<<<<<<<<<<<<<>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>";
      log "Tokens: " + tokens.encode();
      log "Callback URL: " + url;
      log "Event attrs: " + event:attrs().encode();
      log "<<<<<<<<<<<<<<<<<<<<<<<<<<<>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>";
      set ent:request_token_secret tokens{'oauth_token_secret'};
      set ent:request_token tokens{'oauth_token'};
      last;
    }
  }
 
  rule get_access_token {
    select when oauth response
    if(not authorized) then {
      dropbox:get_access_token(ent:request_token, ent:request_token_secret);
    }    
  }


  rule process_access_token {
    select when http post label "access_token"
    pre {
      tokens = dropbox:decode_content(event:attr('content'));
      url = "https://squaretag.kynetx.com/app.html#!/app/#{meta:rid()}/show";
      js = <<
<html>
<head>
  <meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
  <title></title>
  <META HTTP-EQUIV="Refresh" CONTENT="0;#{url}">
  <meta name="robots" content="noindex"/>
  <link rel="canonical" href="#{url}"/>
</head>
<body>
<p>
You are being redirected to <a href="#{url}">#{url}</a>
</p>
<script type="text/javascript">
window.location = #{url};
</script>

</body>
</html>
>>;
    }
    send_raw("text/html")
        with content= js
    always {
      log "<<<<<<<<<<<<<<<<<<<<<<<<<<<>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>";
      log meta:ruleName() + " Tokens: " + tokens.encode();
      log "<<<<<<<<<<<<<<<<<<<<<<<<<<<>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>";
      set ent:dropbox_uid tokens{'uid'};
      set ent:access_token_secret tokens{'oauth_token_secret'};
      set ent:access_token tokens{'oauth_token'};
      last;
    }
  }
 

  rule show_account_info { 
    select when web cloudAppSelected
    pre {
      
      account_info = dropbox:core_api_call('/account/info', my_tokens);
      name = account_info{'display_name'};
      uid = account_info{'uid'};

      metadata = dropbox:core_api_call('/metadata/sandbox/?list=true', my_tokens);
      files = metadata{'contents'}.isnull() => ""
                                             | metadata{'contents'}.map(function(x){x{'path'}}).join('<br/>');

      my_html = <<
<div style="margin: 0px 0px 20px 20px">
<p>Your Dropbox name is #{name} and your UID is #{uid}.</p>

<p>Files:<br/>#{files}</p>

</div>
>>;

  // <p>Token: #{ent:access_token}; Secret: #{ent:access_token_secret}</p>

    }
    if(authorized) then
    {
      CloudRain:createLoadPanel("Dropbox Account Info", {}, my_html);
    }

    fired {
      log "<<<<<<<<<<<<<<<<<<<<<<<<<<<>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>";
      log meta:ruleName() + " Toens: " + my_tokens.encode();
      log "Account info: " + name + " " + "uid";
      log "files: " + files;
      log "<<<<<<<<<<<<<<<<<<<<<<<<<<<>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>";
    }
  }

}