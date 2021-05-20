# Nginx IP2Location module



### Description

The Nginx IP2Location module enables user to easily perform client's IP to geographical location lookup by using IP2Location database.

The IP2Location database can be downloaded from https://lite.ip2location.com (Free) or https://www.ip2location.com (Commercial).



### Installation

1. Download IP2location C library from https://github.com/chrislim2888/IP2Location-C-Library

2. Compile and install IP2Location C library.

3. Download IP2Location module and decompress the package.

   ```bash
   wget https://github.com/ip2location/ip2location-nginx/archive/master.zip
   unzip master.zip
   rm master.zip
   ```

   

4. Download the latest Nginx source code from https://nginx.org/en/download.html

   ```bash
   wget https://nginx.org/download/nginx-x.y.z.tar.gz
   ```

   

5. Decompress and go into Nginx source directory.

   ```bash
   tar xvfz nginx-x.y.z.tar.gz
   cd nginx-x.y.z
   ```

   

6. Re-compile Nginx from source to include this module.

   **Static Module**

   ```bash
   ./configure --add-module=/absolute/path/to/nginx-ip2location-master
   make
   make install
   ```

   **Dynamic Module**

   ```bash
   ./configure --add-dynamic-module=/absolute/path/to/nginx-ip2location-master
   make
   make install
   ```



### Nginx Configuration

Insert the configuration below to your `nginx.conf`.

```
Syntax      : load_module modules/ngx_http_ip2location_module.so;
Default     : -
Context     : main
Description : Load IP2Location Nginx module if it was compiled as dynamic.
```

```
Syntax      : ip2location_database path
Default     : none
Context     : http
Description : The absolute path to IP2Location BIN database.
```

```
Syntax      : ip2location_proxy_recursive on|off
Default     : off
Context     : http
Description : Enable recursive search in the x-forwarded-for headers.
```

```
Syntax      : ip2location_proxy cidr|address
Default     : none
Context     : http
Description : Set a list of proxies to translate x-forwarded-for headers for.
```



**Example:**

```nginx
http {
	...
	
	ip2location_database			/usr/share/ip2location/DB6.BIN;
	ip2location_proxy_recursive		on;
	ip2location_proxy				192.168.1.0/24;
}
```



### Variables

The following variables will be made available in Nginx:

```nginx
$ip2location_country_short
$ip2location_country_long
$ip2location_region
$ip2location_city
$ip2location_isp
$ip2location_latitude
$ip2location_longitude
$ip2location_domain
$ip2location_zipcode
$ip2location_timezone
$ip2location_netspeed
$ip2location_iddcode
$ip2location_areacode
$ip2location_weatherstationcode
$ip2location_weatherstationname
$ip2location_mcc
$ip2location_mnc
$ip2location_elevation
$ip2location_usagetype
$ip2location_addresstype
$ip2location_category
```



### Usage Example

##### Add Server Variables

```nginx
server {
	listen 80 default_server;
	root /var/www;
	index index.html index.php;

    access_log /var/log/nginx/access.log;
    error_log /var/log/nginx/error.log;

	server_name _;

	location / {
		try_files $uri $uri/ =404;
	}

	location ~ \.php$ {
		fastcgi_pass php-fpm-sock;
		fastcgi_index index.php;
		include fastcgi.conf;

		fastcgi_param IP2LOCATION_COUNTRY_SHORT       $ip2location_country_short;
		fastcgi_param IP2LOCATION_COUNTRY_LONG        $ip2location_country_long;
        fastcgi_param IP2LOCATION_REGION              $ip2location_region;
        fastcgi_param IP2LOCATION_CITY                $ip2location_city;
        fastcgi_param IP2LOCATION_ISP                 $ip2location_isp;
	}
}
```



##### Block Single Country

```nginx
if ( $ip2location_country_short = 'US' ) {
    return 444;
}
```



##### Block Multiple Countries

```nginx
map $ip2location_country_short $blacklist_country {
	default no;
	AU yes;
	IN yes;
	NG yes;
}

server {
    ...
        
	if ( $blacklist_country = yes ) {
		return 444;
	}
}
```



### IPv4 BIN vs IPv6 BIN

Use the IPv4 BIN file if you just need to query IPv4 addresses.

If you query an IPv6 address using the IPv4 BIN, you'll see the INVALID_IP_ADDRESS error.

Use the IPv6 BIN file if you need to query BOTH IPv4 and IPv6 addresses.



### Support
Please visit us at https://www.ip2location.com for services and databases we offer.

For support, please email us at support@ip2location.com
