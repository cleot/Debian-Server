vcl 4.0;
#import std;

# Default backend definition. Set this to point to your content server.
# https://github.com/nicolargo/varnish-nginx-wordpress/blob/master/varnish/varnish4-wordpress
# https://github.com/cleot/varnish-wordpress-with-mobile/blob/master/default.vcl

/* iclude device detection */
include "devicedetect.vcl";
sub vcl_recv { call devicedetect; }

backend apache {
    .host = "37.120.177.165";
    .port = "81";
    .connect_timeout = 600s;
    .first_byte_timeout = 600s;
    .between_bytes_timeout = 600s;
    .max_connections = 800;

        .probe = {
        /* What url to check against */
        .url = "/";
        /* Timeout for how long to wait back end to answer */
        .timeout = 2s;
        /* How often to check.  */
        .interval = 10s;
        /* How many is the max value for checks */
        .window = 5;
        /* If 3 out of 5 succeed consider healthy, otherwise mark as sick */
        .threshold = 3;
     }
}

backend nginx {
    .host = "37.120.177.165";
    .port = "8080";
    .connect_timeout = 600s;
    .first_byte_timeout = 600s;
    .between_bytes_timeout = 600s;
    .max_connections = 800;

        .probe = {
        /* What url to check against */
        .url = "/";
        /* Timeout for how long to wait back end to answer */
        .timeout = 2s;
        /* How often to check.  */
        .interval = 10s;
        /* How many is the max value for checks */
        .window = 5;
        /* If 3 out of 5 succeed consider healthy, otherwise mark as sick */
        .threshold = 3;
     }
}

# Only allow purging from specific IPs
#acl purge {
#    "localhost";
#    "127.0.0.1";
#}

# This function is used when a request is send by a HTTP client (Browser) 
sub vcl_recv {

    /* I only want to cache my/wifes Wordpress sites, also w/ www, otherwise pass on */
#       if(!(req.http.host ~ "(www\.)?domain\.com") &&
#       !(req.http.host ~ "sub.domain.net") &&
#       !(req.http.host ~ "(www\.)?domain\.com") &&
#       !(req.http.host ~ "(www\.)?domain\.com") &&
#       !(req.http.host ~ "(www\.)?domain\.com") &&
#       !(req.http.host ~ "(www\.)?domain\.com") &&
#       !(req.http.host ~ "(www\.)?domain\.com")) {
#           return (pass);
#       }


    # set backend
    set req.backend_hint = apache;
 
    if (req.http.host == "v1.example.com") {
        set req.backend_hint = nginx;
    }

    if (req.http.host == "live.example.com") {
        set req.backend_hint = nginx;
    }

    if (req.http.host == "app.example.com") {
        set req.backend_hint = nginx;
    }


    # Normalize the header, remove the port (in case you're testing this on various TCP ports)
    set req.http.Host = regsub(req.http.Host, ":[0-9]+", "");

    /* Set client ip to headers */
    if (req.restarts == 0) {
        if (req.http.x-forwarded-for) {
            set req.http.X-Forwarded-For =
            req.http.X-Forwarded-For + ", " + client.ip;
        } else {
            set req.http.X-Forwarded-For = client.ip;
        }
    }

    # Allow purging from localhost
    if (req.method == "PURGE") {
        if (client.ip != "127.0.0.1")
         {
            return(synth(405, "This IP is not allowed to send PURGE requests."));
        } 

        # If allowed, do a cache_lookup -> vlc_hit() or vlc_miss()
        ban("req.http.host == " +req.http.host+" && req.url ~ "+req.url);
        return (purge);
    }

    /* Any other method/type, forward without even looking of the content */
    if (req.method != "GET" &&
        req.method != "HEAD" &&
        req.method != "PUT" && 
        req.method != "TRACE" &&
        req.method != "OPTIONS" &&
        req.method != "DELETE") {
            return (pass);
    }

    # Post requests will not be cached
    if (req.http.Authorization || req.method == "POST") {
        return (pass);
    }
	# PHPMYADMIN
 	if (req.http.host == "phpmyadmin.v1.example.com") {
	return(pass);
	}

    # --- Wordpress specific configuration
    
    # Did not cache the RSS feed
    if (req.url ~ "/feed") {
        return (pass);
    }

    # Blitz hack
        if (req.url ~ "/mu-.*") {
                return (pass);
        }

    
    # Did not cache the admin and login pages
    if (req.url ~ "/wp-(login|admin)") {
        return (pass);
    }

    /* if logged in, pass, otherwise remove cookie */
    if (req.http.cookie) {
        if (req.http.cookie ~ "(wordpress_logged_in)") {
                return(pass);
        } else {
                unset req.http.cookie;
        }
    }
	
    # Remove has_js and CloudFlare/Google Analytics __* cookies.
    set req.http.Cookie = regsuball(req.http.Cookie, "(^|;\s*)(_[_a-z]+|has_js)=[^;]*", "");

    # Remove any Google Analytics based cookies
    set req.http.Cookie = regsuball(req.http.Cookie, "__utm.=[^;]+(; )?", "");

    # Remove the Quant Capital cookies (added by some plugin, all __qca)
    set req.http.Cookie = regsuball(req.http.Cookie, "__qc.=[^;]+(; )?", "");

    # Remove the wp-settings-1 cookie
    set req.http.Cookie = regsuball(req.http.Cookie, "wp-settings-1=[^;]+(; )?", "");

    # Remove the wp-settings-time-1 cookie
    set req.http.Cookie = regsuball(req.http.Cookie, "wp-settings-time-1=[^;]+(; )?", "");

    # Remove the wp test cookie
    set req.http.Cookie = regsuball(req.http.Cookie, "wordpress_test_cookie=[^;]+(; )?", "");

    # Are there cookies left with only spaces or that are empty?
    if (req.http.cookie ~ "^ *$") {
            unset req.http.cookie;
    }
    
    # Cache the following files extensions 
    if (req.url ~ "\.(css|js|png|gif|jp(e)?g|swf|ico)") {
        unset req.http.cookie;
    }

    # Normalize Accept-Encoding header and compression
    # https://www.varnish-cache.org/docs/3.0/tutorial/vary.html
    if (req.http.Accept-Encoding) {
        # Do no compress compressed files...
        if (req.url ~ "\.(jpg|png|gif|gz|tgz|bz2|tbz|mp3|ogg)$") {
                unset req.http.Accept-Encoding;
        } elsif (req.http.Accept-Encoding ~ "gzip") {
                set req.http.Accept-Encoding = "gzip";
        } elsif (req.http.Accept-Encoding ~ "deflate") {
                set req.http.Accept-Encoding = "deflate";
        } else {
            unset req.http.Accept-Encoding;
        }
    }

    # Check the cookies for wordpress-specific items
    if (req.http.Cookie ~ "wordpress_" || req.http.Cookie ~ "comment_") {
        return (pass);
    }
    if (!req.http.cookie) {
        unset req.http.cookie;
    }
    
    # --- End of Wordpress specific configuration

    # Did not cache HTTP authentication and HTTP Cookie
    if (req.http.Authorization || req.http.Cookie) {
        # Not cacheable by default
        return (pass);
    }

    # Cache all others requests
    return (hash);
}

sub append_ua {
    if ((req.http.X-UA-Device) && (req.method == "GET")) {
        # if there are existing GET arguments;
        if (req.url ~ "\?") {
            set req.http.X-get-devicetype = "&devicetype=" + req.http.X-UA-Device;
        } else {
            set req.http.X-get-devicetype = "?devicetype=" + req.http.X-UA-Device;
        }
        set req.url = req.url + req.http.X-get-devicetype;
        unset req.http.X-get-devicetype;
    }
}
 
sub vcl_pipe {
    return (pipe);
}
 
# do this after vcl_hash, so all Vary-ants can be purged in one go. (avoid ban()ing)
sub vcl_miss { call append_ua; }
sub vcl_pass { call append_ua; }
 
# This function is used when a request is sent by our backend (Nginx server)
sub vcl_backend_response {

    if (bereq.http.X-UA-Device) {
        if (!beresp.http.Vary) { # no Vary at all
            set beresp.http.Vary = "X-UA-Device";
        } elseif (beresp.http.Vary !~ "X-UA-Device") { # add to existing Vary
            set beresp.http.Vary = beresp.http.Vary + ", X-UA-Device";
        }

        # if the backend returns a redirect (think missing trailing slash),
        # we will potentially show the extra address to the client. we
        # don't want that.  if the backend reorders the get parameters, you
        # may need to be smarter here. (? and & ordering)

        if (beresp.status == 301 || beresp.status == 302 || beresp.status == 303) {
            set beresp.http.location = regsub(beresp.http.location, "[?&]devicetype=.*$", "");
        }
    }
    set beresp.http.X-UA-Device = bereq.http.X-UA-Device;

    # Remove some headers we never want to see
    unset beresp.http.Server;
    unset beresp.http.X-Powered-By;
    set beresp.http.X-Backend = beresp.backend.name;

    # For static content strip all backend cookies
    if (bereq.url ~ "\.(css|js|png|gif|jp(e?)g)|swf|ico") {
        unset beresp.http.cookie;
    }

    # Only allow cookies to be set if we're in admin area
    if (beresp.http.Set-Cookie && bereq.url !~ "^/wp-(login|admin)") {
            unset beresp.http.Set-Cookie;
        }

    # don't cache response to posted requests or those with basic auth
    if ( bereq.method == "POST" || bereq.http.Authorization ) {
            set beresp.uncacheable = true;
        set beresp.ttl = 120s;
        return (deliver);
        }
 
        # don't cache search results
    if ( bereq.url ~ "\?s=" ){
        set beresp.uncacheable = true;
                set beresp.ttl = 120s;
                return (deliver);
    }
    
    # only cache status ok
    if ( beresp.status != 200 ) {
        set beresp.uncacheable = true;
                set beresp.ttl = 120s;
                return (deliver);
    }

    # A TTL of 24h
    set beresp.ttl = 24h;
    # Define the default grace period to serve cached content
    set beresp.grace = 30s;
    
    return (deliver);
}



# The routine when we deliver the HTTP request to the user
# Last chance to modify headers that are sent to the client
sub vcl_deliver {
    if (obj.hits > 0) { 
        set resp.http.X-Cache = "cached";
    } else {
        set resp.http.x-Cache = "uncached";
    }

    if ((req.http.X-UA-Device) && (resp.http.Vary)) {
        set resp.http.Vary = regsub(resp.http.Vary, "X-UA-Device", "User-Agent");
    }

    # Remove some headers: PHP version
    unset resp.http.X-Powered-By;

    # Remove some headers: Apache version & OS
    unset resp.http.Server;

    return (deliver);
}

 #The data on which the hashing will take place
sub vcl_hash {
  
  hash_data(req.url);
  if (req.http.host) {
      hash_data(req.http.host);
  } else {
      hash_data(server.ip);
  }

    return (lookup);
}

sub vcl_init {
    return (ok);
}
 
sub vcl_fini {
    return (ok);
}
