# Nginx-Hardenening
Nginx webserver hardening

```
apt install nginx nginx-extras -y
```

```
nano /etc/nginx/nginx.conf
  worker_rlimit_nofile 65535;
  events {
        worker_connections 65535;
        multi_accept on;
}
```
### Change logformat
```
nano /etc/nginx/nginx.conf
http {
    log_format login_failure '$remote_addr - $remote_user [$time_local] '
                         '"$request" $status $body_bytes_sent '
                         '"$http_referer" "$http_user_agent"';
     server_tokens off;

     client_body_buffer_size 1K;
     client_header_buffer_size 1k;
     client_max_body_size 1k;
     large_client_header_buffers 2 1k;
 }
```

### Hardening WebServer
we enable opensource WAF - modsecurity - to protect our web app.
```
nano sites-available/soar.conf
  server {

    listen 80 default_server;
    server_name _;
    return 301 https://$host$request_uri;

}

server {
       listen 443 default_server ssl;
       listen [::]:443 default_server ssl;

       server_name _ ;
       access_log /var/log/nginx/access.log;
       error_log  /var/log/nginx/error.log error;

       add_header X-Content-Type-Options: nosniff;
       add_header X-Frame-Options SAMEORIGIN always;
       add_header X-XSS-Protection "1; mode=block";

       access_log /var/log/nginx/login_failure.log login_failure;

       ssl_protocols TLSv1.2 TLSv1.3;
       ssl_certificate /etc/ssl/webserver/webserver.crt;
       ssl_certificate_key /etc/ssl/webserver/webserver.key;
       ssl_dhparam /etc/ssl/certs/dhparam.pem;	
       
       ssl_session_cache shared:SSL:10m;
       ssl_session_timeout 10m;
       ssl_prefer_server_ciphers on;
       ssl_ciphers 'ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256!aNULL:!eNULL:!EXPORT:!DES:!RC4:!3DES:!MD5:!PSK';
       
       modsecurity on;
       modsecurity_rules_file /etc/nginx/modsec/main.conf;
	
       location / {
    	      proxy_pass https://127.0.0.1:8080 ;
   	        proxy_buffering off;

            proxy_http_version 1.1;
            proxy_set_header Connection "Keep-Alive";
            proxy_set_header Proxy-Connection "Keep-Alive";

			      proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-Host $host;
            proxy_set_header X-Forwarded-Port $server_port;
			      proxy_set_header X-Forwarded-Host $server_name;
       }

}
```
### Banned User IP Address after 5 failed login.
```
apt install -y fail2ban
```

```
nano /etc/fail2ban/filter.d/nginx-login.conf
    [Definition]
    failregex = ^<HOST>.*"(GET|POST).*HTTP.*" 401
    ignoreregex =

nano /etc/fail2ban/jail.d/nginx-login.conf
    [nginx-login]
    enabled = true
    filter = nginx-login
    port = http,https
    logpath = /var/log/nginx/login_failure.log
    maxretry = 5
    bantime = 120

systemctl restart nginx fail2ban
fail2ban-client status nginx-login

```

### Kernel Tunning 
```
# Avoid a smurf attack
net.ipv4.icmp_echo_ignore_broadcasts = 1
 
# Turn on protection for bad icmp error messages
net.ipv4.icmp_ignore_bogus_error_responses = 1
 
# Turn on syncookies for SYN flood attack protection
net.ipv4.tcp_syncookies = 1
 
# Turn on and log spoofed, source routed, and redirect packets
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
 
# No source routed packets here
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
 
# Turn on reverse path filtering
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
 
# Make sure no one can alter the routing tables
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
 
# Don't act as a router
net.ipv4.ip_forward = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
 
# Turn on execshild
kernel.exec-shield = 1
kernel.randomize_va_space = 1
 
# Tuen IPv6
net.ipv6.conf.default.router_solicitations = 0
net.ipv6.conf.default.accept_ra_rtr_pref = 0
net.ipv6.conf.default.accept_ra_pinfo = 0
net.ipv6.conf.default.accept_ra_defrtr = 0
net.ipv6.conf.default.autoconf = 0
net.ipv6.conf.default.dad_transmits = 0
net.ipv6.conf.default.max_addresses = 1
 
# Increase system IP port limits
net.ipv4.ip_local_port_range = 2000 65000
 
# Increase TCP max buffer size setable using setsockopt()
net.ipv4.tcp_rmem = 4096 87380 8388608
net.ipv4.tcp_wmem = 4096 87380 8388608

net.core.rmem_max = 8388608
net.core.wmem_max = 8388608
net.core.netdev_max_backlog = 5000
net.ipv4.tcp_window_scaling = 1
```
