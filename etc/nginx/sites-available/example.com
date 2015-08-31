# redirect wildcard

server {
    listen 443 ssl;
    ssl on;
    server_name *.example.com;
    return 301 https://www.example.com$request_uri;

    ssl_certificate /etc/ssl/private/example.com/ssl-bundle.crt;
    ssl_certificate_key /etc/ssl/private/example.com/ssl.key;
    ssl_protocols TLSv1.2 TLSv1.1 TLSv1;
    ssl_ciphers EECDH+AESGCM:EDH+AESGCM:EECDH:EDH:!MD5:!RC4:!LOW:!MEDIUM:!CAMELLIA:!ECDSA:!DES:!DSS:!3DES:!NULL;
    ssl_prefer_server_ciphers on;
    ssl_dhparam /etc/ssl/private/dhparam.pem;
    ssl_ecdh_curve secp384r1;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    port_in_redirect off;
    client_header_buffer_size 64k;
    large_client_header_buffers 4 64k;
}

server {
    listen 80;
    server_name *.example.com;
    return 301 https://www.example.com$request_uri;
    client_header_buffer_size 64k;
    large_client_header_buffers 4 64k;
    }


# http to https
server {
    listen 80;
    server_name www.example.com example.com;
    return 301 https://www.example.com$request_uri;
    client_header_buffer_size 64k;
    large_client_header_buffers 4 64k;
    }

# redirect to www
server {

    listen 443 ssl;
    ssl on;
    server_name example.com;
    return 301 https://www.example.com$request_uri;

    ssl_certificate /etc/ssl/private/example.com/ssl-bundle.crt;
    ssl_certificate_key /etc/ssl/private/example.com/ssl.key;
    ssl_protocols TLSv1.2 TLSv1.1 TLSv1;
    ssl_ciphers EECDH+AESGCM:EDH+AESGCM:EECDH:EDH:!MD5:!RC4:!LOW:!MEDIUM:!CAMELLIA:!ECDSA:!DES:!DSS:!3DES:!NULL;
    ssl_prefer_server_ciphers on;
    ssl_dhparam /etc/ssl/private/dhparam.pem;
    ssl_ecdh_curve secp384r1;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    port_in_redirect off;
    client_header_buffer_size 64k;
    large_client_header_buffers 4 64k;
}

# www.example.com
server {

    listen 443 ssl;
    ssl on;
    server_name www.example.com;

    ssl_certificate /etc/ssl/private/example.com/ssl-bundle.crt;
    ssl_certificate_key /etc/ssl/private/example.com/ssl.key;
    ssl_protocols TLSv1.2 TLSv1.1 TLSv1;
    ssl_ciphers EECDH+AESGCM:EDH+AESGCM:EECDH:EDH:!MD5:!RC4:!LOW:!MEDIUM:!CAMELLIA:!ECDSA:!DES:!DSS:!3DES:!NULL;
    ssl_prefer_server_ciphers on;
    ssl_dhparam /etc/ssl/private/dhparam.pem;
    ssl_ecdh_curve secp384r1;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    port_in_redirect off;
    client_header_buffer_size 64k;
    large_client_header_buffers 4 64k;
    add_header powered-by XXXXXXXXXXXX.COM;
  
    	#nginx proxy --> VARNISH --> apache2 --> fastcgi
    	location / {
	    proxy_pass http://127.0.0.1:8888;
            proxy_set_header X-Real-IP  $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto https;
            proxy_set_header X-Forwarded-Port 443;
            proxy_set_header Host $host;
            proxy_redirect     off; 
    	}

	#nginx proxy --> APACHE2 --> fastcgi
	#location / {
        #    proxy_pass http://127.0.0.1:81;
        #    proxy_set_header X-Real-IP  $remote_addr;
        #    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        #    proxy_set_header X-Forwarded-Proto https;
        #    proxy_set_header X-Forwarded-Port 443;
        #    proxy_set_header Host $host;
        #    proxy_redirect     off; 
    	#}   
}
