/*
 * IP2Location Nginx module is distributed under MIT license
 * Copyright (c) 2013-2020 IP2Location.com. support at ip2location dot com
 *
 * This module is free software; you can redistribute it and/or
 * modify it under the terms of the MIT license
 */
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <IP2Location.h>

typedef struct {
	IP2Location			*handler;
	ngx_int_t			access_type;
	ngx_array_t			*proxies;
	ngx_flag_t			proxy_recursive;
} ngx_http_ip2location_conf_t;

typedef struct {
	ngx_str_t	*name;
	uintptr_t	data;
} ngx_http_ip2location_var_t;

static ngx_int_t ngx_http_ip2location_add_variables(ngx_conf_t *cf);
static ngx_int_t ngx_http_ip2location_get_str_value(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_ip2location_get_float_value(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
static IP2LocationRecord *ngx_http_ip2location_get_records(ngx_http_request_t *r);
static void *ngx_http_ip2location_create_conf(ngx_conf_t *cf);
static char *ngx_http_ip2location_init_conf(ngx_conf_t *cf, void *conf);
static char *ngx_http_ip2location_database(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_ip2location_access_type(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_ip2location_proxy(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_ip2location_cidr_value(ngx_conf_t *cf, ngx_str_t *net, ngx_cidr_t *cidr);
static void ngx_http_ip2location_cleanup(void *data);

static ngx_command_t ngx_http_ip2location_commands[] = {
	{
		ngx_string("ip2location_database"),
		NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE12,
		ngx_http_ip2location_database,
		NGX_HTTP_MAIN_CONF_OFFSET,
		0,
		NULL
	},
	{
		ngx_string("ip2location_access_type"),
		NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE12,
		ngx_http_ip2location_access_type,
		NGX_HTTP_MAIN_CONF_OFFSET,
		offsetof(ngx_http_ip2location_conf_t, access_type),
		NULL
	},
	{
		ngx_string("ip2location_proxy"),
		NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
		ngx_http_ip2location_proxy,
		NGX_HTTP_MAIN_CONF_OFFSET,
		0,
		NULL
	},
	{
		ngx_string("ip2location_proxy_recursive"),
		NGX_HTTP_MAIN_CONF|NGX_CONF_FLAG,
		ngx_conf_set_flag_slot,
		NGX_HTTP_MAIN_CONF_OFFSET,
		offsetof(ngx_http_ip2location_conf_t, proxy_recursive),
		NULL
	},
	ngx_null_command
};

static ngx_http_module_t ngx_http_ip2location_module_ctx = {
	ngx_http_ip2location_add_variables,	/* preconfiguration */
	NULL,								/* postconfiguration */
	ngx_http_ip2location_create_conf,	/* create main configuration */
	ngx_http_ip2location_init_conf,		/* init main configuration */
	NULL,								/* create server configuration */
	NULL,								/* merge server configuration */
	NULL,								/* create location configuration */
	NULL								/* merge location configuration */
};


ngx_module_t ngx_http_ip2location_module = {
	NGX_MODULE_V1,
	&ngx_http_ip2location_module_ctx,	/* module context */
	ngx_http_ip2location_commands,		/* module directives */
	NGX_HTTP_MODULE,					/* module type */
	NULL,								/* init master */
	NULL,								/* init module */
	NULL,								/* init process */
	NULL,								/* init thread */
	NULL,								/* exit thread */
	NULL,								/* exit process */
	NULL,								/* exit master */
	NGX_MODULE_V1_PADDING
};

static ngx_http_variable_t
ngx_http_ip2location_vars[] = {
	{
		ngx_string("ip2location_country_short"), NULL,
		ngx_http_ip2location_get_str_value,
		offsetof(IP2LocationRecord, country_short),
		0, 0
	},
	{
		ngx_string("ip2location_country_long"), NULL,
		ngx_http_ip2location_get_str_value,
		offsetof(IP2LocationRecord, country_long),
		0, 0
	},
	{
		ngx_string("ip2location_region"), NULL,
		ngx_http_ip2location_get_str_value,
		offsetof(IP2LocationRecord, region),
		0, 0
	},
	{
		ngx_string("ip2location_city"), NULL,
		ngx_http_ip2location_get_str_value,
		offsetof(IP2LocationRecord, city),
		0, 0
	},
	{
		ngx_string("ip2location_isp"), NULL,
		ngx_http_ip2location_get_str_value,
		offsetof(IP2LocationRecord, isp),
		0, 0
	},
	{
		ngx_string("ip2location_latitude"), NULL,
		ngx_http_ip2location_get_float_value,
		offsetof(IP2LocationRecord, latitude),
		0, 0
	},
	{
		ngx_string("ip2location_longitude"), NULL,
		ngx_http_ip2location_get_float_value,
		offsetof(IP2LocationRecord, longitude),
		0, 0
	},
	{
		ngx_string("ip2location_domain"), NULL,
		ngx_http_ip2location_get_str_value,
		offsetof(IP2LocationRecord, domain),
		0, 0
	},
	{
		ngx_string("ip2location_zipcode"), NULL,
		ngx_http_ip2location_get_str_value,
		offsetof(IP2LocationRecord, zipcode),
		0, 0
	},
	{
		ngx_string("ip2location_timezone"), NULL,
		ngx_http_ip2location_get_str_value,
		offsetof(IP2LocationRecord, timezone),
		0, 0
	},
	{
		ngx_string("ip2location_netspeed"), NULL,
		ngx_http_ip2location_get_str_value,
		offsetof(IP2LocationRecord, netspeed),
		0, 0
	},
	{
		ngx_string("ip2location_iddcode"), NULL,
		ngx_http_ip2location_get_str_value,
		offsetof(IP2LocationRecord, iddcode),
		0, 0
	},
	{
		ngx_string("ip2location_areacode"), NULL,
		ngx_http_ip2location_get_str_value,
		offsetof(IP2LocationRecord, areacode),
		0, 0
	},
	{
		ngx_string("ip2location_weatherstationcode"), NULL,
		ngx_http_ip2location_get_str_value,
		offsetof(IP2LocationRecord, weatherstationcode),
		0, 0
	},
	{
		ngx_string("ip2location_weatherstationname"), NULL,
		ngx_http_ip2location_get_str_value,
		offsetof(IP2LocationRecord, weatherstationname),
		0, 0
	},
	{
		ngx_string("ip2location_mcc"), NULL,
		ngx_http_ip2location_get_str_value,
		offsetof(IP2LocationRecord, mcc),
		0, 0
	},
	{
		ngx_string("ip2location_mnc"), NULL,
		ngx_http_ip2location_get_str_value,
		offsetof(IP2LocationRecord, mnc),
		0, 0
	},
	{
		ngx_string("ip2location_mobilebrand"), NULL,
		ngx_http_ip2location_get_str_value,
		offsetof(IP2LocationRecord, mobilebrand),
		0, 0
	},
	{
		ngx_string("ip2location_elevation"), NULL,
		ngx_http_ip2location_get_float_value,
		offsetof(IP2LocationRecord, elevation),
		0, 0
	},
	{
		ngx_string("ip2location_usagetype"), NULL,
		ngx_http_ip2location_get_str_value,
		offsetof(IP2LocationRecord, usagetype),
		0, 0
	},

	ngx_http_null_variable
};

static ngx_int_t
ngx_http_ip2location_get_str_value(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data)
{
	char				*val;
	size_t				len;
	IP2LocationRecord	*record;

	record = ngx_http_ip2location_get_records(r);

	if (record == NULL) {
		goto not_found;
	}

	val = *(char **) ((char *) record + data);
	if (val == NULL) {
		goto no_value;
	}

	len = ngx_strlen(val);
	v->data = ngx_pnalloc(r->pool, len);
	if (v->data == NULL) {
		IP2Location_free_record(record);
		return NGX_ERROR;
	}

	ngx_memcpy(v->data, val, len);

	v->len = len;
	v->valid = 1;
	v->no_cacheable = 0;
	v->not_found = 0;

	IP2Location_free_record(record);

	return NGX_OK;

no_value:

	IP2Location_free_record(record);

not_found:

	v->not_found = 1;

	return NGX_OK;
}


static ngx_int_t
ngx_http_ip2location_get_float_value(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data)
{
	float				val;
	IP2LocationRecord	*record;

	record = ngx_http_ip2location_get_records(r);
	if (record == NULL) {
		v->not_found = 1;
		return NGX_OK;
	}

	v->data = ngx_pnalloc(r->pool, NGX_INT64_LEN + 5);
	if (v->data == NULL) {
		IP2Location_free_record(record);
		return NGX_ERROR;
	}

	val = *(float *) ((char *) record + data);

	v->len = ngx_sprintf(v->data, "%.4f", val) - v->data;
	v->valid = 1;
	v->no_cacheable = 0;
	v->not_found = 0;

	IP2Location_free_record(record);

	return NGX_OK;
}

static IP2LocationRecord *
ngx_http_ip2location_get_records(ngx_http_request_t *r)
{
	ngx_http_ip2location_conf_t	*gcf;

	gcf = ngx_http_get_module_main_conf(r, ngx_http_ip2location_module);

	if (gcf->handler)
	{
		ngx_addr_t			addr;
		ngx_array_t			*xfwd;
		u_char				p[NGX_INET6_ADDRSTRLEN + 1];
		size_t				size;

		addr.sockaddr = r->connection->sockaddr;
		addr.socklen = r->connection->socklen;

		xfwd = &r->headers_in.x_forwarded_for;

		if (xfwd->nelts > 0 && gcf->proxies != NULL) {
			(void) ngx_http_get_forwarded_addr(r, &addr, xfwd, NULL, gcf->proxies, gcf->proxy_recursive);
		}

#if defined(nginx_version) && (nginx_version) >= 1005003
	size = ngx_sock_ntop(addr.sockaddr, addr.socklen, p, NGX_INET6_ADDRSTRLEN, 0);
#else
	size = ngx_sock_ntop(addr.sockaddr, p, NGX_INET6_ADDRSTRLEN, 0);
#endif

		p[size] = '\0';

		ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "IP address detected by IP2Location: %s", p);

		return IP2Location_get_all(gcf->handler, (char *)p);
	}
	
	return NULL;
}


static ngx_int_t
ngx_http_ip2location_add_variables(ngx_conf_t *cf)
{
	ngx_http_variable_t	*var, *v;

	for (v = ngx_http_ip2location_vars; v->name.len; v++) {
		var = ngx_http_add_variable(cf, &v->name, v->flags);

		if (var == NULL) {
			return NGX_ERROR;
		}

		var->get_handler = v->get_handler;
		var->data = v->data;
	}

	return NGX_OK;
}


static void *
ngx_http_ip2location_create_conf(ngx_conf_t *cf)
{
	ngx_pool_cleanup_t	 *cln;
	ngx_http_ip2location_conf_t	*conf;

	conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_ip2location_conf_t));
	if (conf == NULL) {
		return NULL;
	}

	conf->proxy_recursive = NGX_CONF_UNSET;

	cln = ngx_pool_cleanup_add(cf->pool, 0);
	if (cln == NULL) {
		return NULL;
	}

	cln->handler = ngx_http_ip2location_cleanup;
	cln->data = conf;

	return conf;
}


static char *
ngx_http_ip2location_init_conf(ngx_conf_t *cf, void *conf)
{
	ngx_http_ip2location_conf_t	*gcf = conf;

	ngx_conf_init_value(gcf->proxy_recursive, 0);

	return NGX_CONF_OK;
}


static char *
ngx_http_ip2location_database(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ngx_http_ip2location_conf_t	*gcf = conf;
	ngx_str_t					*value;

	if (gcf->handler) {
		return "Duplicated";
	}

	value = cf->args->elts;

	if (value[1].len == 0) {
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "No IP2Location database specified.");
		return NGX_CONF_ERROR;
	}

	// Open IP2Location BIN database
	gcf->handler = IP2Location_open((char *) value[1].data);

	if (gcf->handler == NULL) {
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "Unable to open database file \"%s\".", value[1].data);
		return NGX_CONF_ERROR;
	}

	if (IP2Location_open_mem(gcf->handler, gcf->access_type) == -1) {
		IP2Location_close(gcf->handler);
		
		ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "Unable to load database using \"%V\" access type.", &gcf->access_type);
		return NGX_CONF_ERROR;
	}

	return NGX_CONF_OK;
}

static char *
ngx_http_ip2location_access_type(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ngx_http_ip2location_conf_t	*gcf = conf;
	ngx_str_t					*value;

	value = cf->args->elts;

	if (ngx_strcasecmp((u_char *)"file_io", value[1].data) == 0) {
		gcf->access_type = IP2LOCATION_FILE_IO;
	} else if (ngx_strcasecmp((u_char *)"cache_memory", value[1].data) == 0) {
		gcf->access_type = IP2LOCATION_CACHE_MEMORY;
	} else if (ngx_strcasecmp((u_char *)"shared_memory", value[1].data) == 0) {
		gcf->access_type = IP2LOCATION_SHARED_MEMORY;
	} else {
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "Unkown access type \"%s\".", value[1].data);
		return NGX_CONF_ERROR;
	}

	return NGX_CONF_OK;
}

static char *
ngx_http_ip2location_proxy(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ngx_http_ip2location_conf_t	*gcf = conf;
	ngx_str_t					*value;
	ngx_cidr_t					cidr, *c;

	value = cf->args->elts;

	if (ngx_http_ip2location_cidr_value(cf, &value[1], &cidr) != NGX_OK) {
		return NGX_CONF_ERROR;
	}

	if (gcf->proxies == NULL) {
		gcf->proxies = ngx_array_create(cf->pool, 4, sizeof(ngx_cidr_t));
		if (gcf->proxies == NULL) {
			return NGX_CONF_ERROR;
		}
	}

	c = ngx_array_push(gcf->proxies);
	if (c == NULL) {
		return NGX_CONF_ERROR;
	}

	*c = cidr;

	return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_ip2location_cidr_value(ngx_conf_t *cf, ngx_str_t *net, ngx_cidr_t *cidr)
{
	ngx_int_t	rc;

	if (ngx_strcmp(net->data, "255.255.255.255") == 0) {
		cidr->family = AF_INET;
		cidr->u.in.addr = 0xffffffff;
		cidr->u.in.mask = 0xffffffff;

		return NGX_OK;
	}

	rc = ngx_ptocidr(net, cidr);

	if (rc == NGX_ERROR) {
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "Invalid network \"%V\"", net);
		return NGX_ERROR;
	}

	if (rc == NGX_DONE) {
		ngx_conf_log_error(NGX_LOG_WARN, cf, 0, "Low address bits of %V are meaningless", net);
	}

	return NGX_OK;
}


static void
ngx_http_ip2location_cleanup(void *data)
{
	ngx_http_ip2location_conf_t	*gcf = data;

	if (gcf->handler) {
		IP2Location_close(gcf->handler);

		if (gcf->access_type == IP2LOCATION_SHARED_MEMORY) {
			IP2Location_DB_del_shm();
		}

		gcf->handler = NULL;
	}
}
