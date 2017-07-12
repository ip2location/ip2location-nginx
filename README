Nginx IP2Location module
------------------------

Description:
------------

The Nginx IP2Location module enables user to easily perform client's IP to geographical location lookup by using IP2Location database.

The IP2Location database can be downloaded from http://lite.ip2location.com (Free) or http://www.ip2location.com (Commercial).


Installation:
------------

1. Download IP2location C library from http://www.ip2location.com/developers/c

2. Change the path to IP2Location library in "ngx_http_ip2location_module.c".

3. Re-compile Nginx from source to include this module. Add the below directive into the compile of Nginx:

   ```
   ./configure --add-module=/absolute/path/to/nginx-ip2location-VERSION
   make
   make install
   ```




Nginx Configuration
-----

Insert the configuration below to your `nginx.conf`.

```
Syntax:  ip2location on|off
Default: off
Context: http, server, location
Description: Enable or disable IP2Location Nginx module.
```

```
Syntax:  ip2location_database path
Default: none
Context: http
Description: The absolute path to IP2Location BIN database.
```

```
Syntax:  ip2location_access_type file_io|shared_memory|cache_memory
Default: shared_memory
Context: http
Description: Set the method used for lookup.
```

```
Syntax:  ip2location_proxy cidr|address
Default: none
Context: http
Description: Set a list of proxies to translate x-forwarded-for headers for.
```

```
Syntax:  ip2location_proxy_recursive on|off
Default: off
Context: http
Description: Enable recursive search in the x-forwarded-for headers.
```

## Variables

The following variables will be made available in Nginx:

	ip2location_country_short
	ip2location_country_long
	ip2location_region
	ip2location_city
	ip2location_isp
	ip2location_latitude
	ip2location_longitude
	ip2location_domain
	ip2location_zipcode
	ip2location_timezone
	ip2location_netspeed
	ip2location_iddcode
	ip2location_areacode
	ip2location_weatherstationcode
	ip2location_weatherstationname
	ip2location_mcc
	ip2location_mnc
	ip2location_elevation
	ip2location_usagetype


Support
-------
Please visit us at http://www.ip2location.com for services and databases we offer.

For support, please email us at support@ip2location.com
