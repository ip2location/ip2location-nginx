/*
 * COPYRIGHT (C) IP2LOCATION. ALL RIGHTS RESERVED.
 */

#include <nginx.h>
#include <ngx_http.h>
#include <float.h>

#include "IP2Location.h"

#define FLOAT_STRING_MAX_LEN (DBL_MAX_10_EXP + 2)

typedef struct {
    IP2LocationRecord	           *record;
    u_char                          not_found;
    u_char                          error;
} ngx_http_ip2location_ctx_t;

typedef struct {
    ngx_flag_t                       enabled;
} ngx_http_ip2location_loc_conf_t;


typedef struct {
    ngx_int_t                        access_type;
    ngx_str_t                        access_type_name;
    ngx_str_t                        filename;
    ngx_flag_t                       enabled;
    u_char                          *enable_file;
    ngx_uint_t                       enable_line;
    u_char                          *database_file;
    ngx_uint_t                       database_line;
    IP2Location                     *database;
    ngx_array_t                     *proxies;
    ngx_flag_t                      proxy_recursive;
} ngx_http_ip2location_main_conf_t;

typedef struct {
    ngx_cycle_t                      *cycle;
    ngx_http_ip2location_main_conf_t *main_cf;
} ngx_http_ip2location_clean_ctx_t;

static ngx_int_t
ngx_http_ip2location_init_process(ngx_cycle_t *cycle);

static void
ngx_http_ip2location_exit_process(ngx_cycle_t *cycle);

static void *
ngx_http_ip2location_create_main_conf(ngx_conf_t *cf);

static char *
ngx_http_ip2location_init_main_conf(ngx_conf_t *cf, void *conf);

static void *
ngx_http_ip2location_create_loc_conf(ngx_conf_t *cf);

static char *
ngx_http_ip2location_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);

static ngx_int_t
ngx_http_ip2location_add_variables(ngx_conf_t *cf);

static ngx_int_t
ngx_http_ip2location_get_str_value(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);

static ngx_int_t
ngx_http_ip2location_get_float_value(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);

static char *
ngx_http_ip2location_database(ngx_conf_t *cf, void *data, void *conf);

static char *
ngx_http_ip2location_access_type(ngx_conf_t *cf, void *data, void *conf);

static char *
ngx_http_ip2location_enable(ngx_conf_t *cf, void *data, void *conf);

static char *
ngx_http_ip2location_proxy(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_int_t
ngx_http_ip2location_cidr_value(ngx_conf_t *cf, ngx_str_t *net, ngx_cidr_t *cidr);

static ngx_conf_post_t ngx_http_ip2location_post_database = {ngx_http_ip2location_database};

static ngx_conf_post_t ngx_http_ip2location_post_enable = {ngx_http_ip2location_enable};

static ngx_conf_post_t ngx_http_ip2location_post_access_type = {ngx_http_ip2location_access_type};

static ngx_command_t  ngx_http_ip2location_commands[] = {

    {   ngx_string("ip2location_database"),
        NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_MAIN_CONF_OFFSET,
        offsetof(ngx_http_ip2location_main_conf_t, filename),
        &ngx_http_ip2location_post_database
    },

    {   ngx_string("ip2location"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF
        |NGX_CONF_TAKE1,
        ngx_conf_set_flag_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_ip2location_loc_conf_t, enabled),
        &ngx_http_ip2location_post_enable
    },

    {   ngx_string("ip2location_access_type"),
        NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_MAIN_CONF_OFFSET,
        offsetof(ngx_http_ip2location_main_conf_t, access_type_name),
        &ngx_http_ip2location_post_access_type
    },

    {   ngx_string("ip2location_proxy"),
        NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
        ngx_http_ip2location_proxy,
        NGX_HTTP_MAIN_CONF_OFFSET,
        0,
        NULL
    },

    {   ngx_string("ip2location_proxy_recursive"),
        NGX_HTTP_MAIN_CONF|NGX_CONF_FLAG,
        ngx_conf_set_flag_slot,
        NGX_HTTP_MAIN_CONF_OFFSET,
        offsetof(ngx_http_ip2location_main_conf_t, proxy_recursive),
        NULL
    },

    ngx_null_command
};

static ngx_http_module_t  ngx_http_ip2location_module_ctx = {
    ngx_http_ip2location_add_variables,
    NULL,

    ngx_http_ip2location_create_main_conf,
    ngx_http_ip2location_init_main_conf,

    NULL,
    NULL,

    ngx_http_ip2location_create_loc_conf,
    ngx_http_ip2location_merge_loc_conf
};

ngx_module_t  ngx_http_ip2location_module = {
    NGX_MODULE_V1,
    &ngx_http_ip2location_module_ctx,
    ngx_http_ip2location_commands,
    NGX_HTTP_MODULE,
    NULL,
    NULL,
    ngx_http_ip2location_init_process,
    NULL,
    NULL,
    ngx_http_ip2location_exit_process,
    NULL,
    NGX_MODULE_V1_PADDING
};

static ngx_http_variable_t ngx_http_ip2location_vars[] = {

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

    { ngx_null_string, NULL, NULL, 0, 0, 0 }
};


static ngx_int_t ngx_http_ip2location_init_process(ngx_cycle_t *cycle)
{
    ngx_http_ip2location_main_conf_t  *imcf;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, cycle->log, 0,
                   "ip2location init process");

    imcf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_ip2location_module);

    /* Open the database if it is not already open. */
    if ((imcf->enabled) && (imcf->database == NULL)) {
        if (imcf->filename.len == 0) {
            return NGX_OK;
        }

        imcf->database = IP2Location_open((char *)imcf->filename.data);

        if (imcf->database == NULL) {
            ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                          "can not open database file \"%V\" in %s:%ui",
                          &imcf->filename, imcf->database_file, imcf->database_line);
            return NGX_OK;
        }

        if (IP2Location_open_mem(imcf->database, imcf->access_type) < 0) {
            /* Close will delete the allocated database instance. */
            IP2Location_close(imcf->database);
            imcf->database = NULL;

            ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                          "can not load database file %V using \"%V\" access type in %s:%ui",
                          &imcf->filename, &imcf->access_type_name, imcf->database_file,
                          imcf->database_line);

            return NGX_OK;
        } else {
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, cycle->log, 0,
                           "ip2location opened database %V",
                           &imcf->filename);
        }
    }

    return NGX_OK;
}


static void ngx_http_ip2location_exit_process(ngx_cycle_t *cycle)
{
    ngx_http_ip2location_main_conf_t  *imcf;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, cycle->log, 0,
                   "ip2location exit process");

    imcf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_ip2location_module);

    if (imcf->database != NULL) {
        IP2Location_close(imcf->database);

        if (imcf->access_type == IP2LOCATION_SHARED_MEMORY) {
            IP2Location_DB_del_shm();
        }

        imcf->database = NULL;
    }
}


static void * ngx_http_ip2location_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_ip2location_main_conf_t  *imcf;

    imcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_ip2location_main_conf_t));
    if (imcf == NULL) {
        return NULL;
    }
    imcf->access_type = NGX_CONF_UNSET;

    return imcf;
}


void ngx_http_ip2location_cleanup(void *data)
{
    ngx_http_ip2location_clean_ctx_t *clean_ctx = data;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, clean_ctx->cycle->log, 0,
                   "ip2location cleanup");

    if (clean_ctx->main_cf->database != NULL) {
        IP2Location_close(clean_ctx->main_cf->database);

        if (clean_ctx->main_cf->access_type == IP2LOCATION_SHARED_MEMORY) {
            IP2Location_DB_del_shm();
        }

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, clean_ctx->cycle->log, 0,
                   "ip2location cleanup database closed");

        clean_ctx->main_cf->database = NULL;
    }
}


static char * ngx_http_ip2location_init_main_conf(ngx_conf_t *cf, void *data)
{
    ngx_http_ip2location_main_conf_t  *imcf = data;
    ngx_pool_cleanup_t                *cln;
    ngx_http_ip2location_clean_ctx_t  *clean_ctx;

    if (imcf->access_type == NGX_CONF_UNSET) {
        imcf->access_type = IP2LOCATION_SHARED_MEMORY;
    }

    if (imcf->enabled) {
        if (imcf->filename.len == 0) {
            ngx_log_error(
				NGX_LOG_EMERG, cf->log, 0, "ip2location enabled with no database specified in %s:%ui", imcf->enable_file, imcf->enable_line
			);

            return NGX_CONF_ERROR;
        }

        cln = ngx_pool_cleanup_add(cf->pool, 0);
        if (cln == NULL) {
            return NGX_CONF_ERROR;
        }

        clean_ctx = ngx_pcalloc(cf->cycle->pool, sizeof(ngx_http_ip2location_clean_ctx_t));
        if (clean_ctx == NULL) {
            return NGX_CONF_ERROR;
        }

        clean_ctx->cycle = cf->cycle;
        clean_ctx->main_cf = imcf;

        cln->data = clean_ctx;
        cln->handler = ngx_http_ip2location_cleanup;
    }

    return NGX_CONF_OK;
}


static void * ngx_http_ip2location_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_ip2location_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_ip2location_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }
    conf->enabled = NGX_CONF_UNSET;
    return conf;
}


static char * ngx_http_ip2location_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_ip2location_loc_conf_t  *prev = parent;
    ngx_http_ip2location_loc_conf_t  *conf = child;

    ngx_conf_merge_value(conf->enabled, prev->enabled, 0);

    return NGX_CONF_OK;
}


static char * ngx_http_ip2location_access_type(ngx_conf_t *cf, void *data, void *conf)
{
    ngx_http_ip2location_main_conf_t  *imcf;
    ngx_str_t                          value;

    imcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_ip2location_module);

    value = *((ngx_str_t *)conf);

    if (ngx_strcasecmp((u_char *)"file_io", value.data) == 0) {
        imcf->access_type = IP2LOCATION_FILE_IO;
    } else if (ngx_strcasecmp((u_char *)"cache_memory", value.data) == 0) {
        imcf->access_type = IP2LOCATION_CACHE_MEMORY;
    } else if (ngx_strcasecmp((u_char *)"shared_memory", value.data) == 0) {
        imcf->access_type = IP2LOCATION_SHARED_MEMORY;
    } else {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "unkown access type \"%V\"", &value);
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static char * ngx_http_ip2location_enable (ngx_conf_t *cf, void *data, void *conf)
{
    ngx_flag_t enabled = *((ngx_flag_t *)conf);
    ngx_http_ip2location_main_conf_t  *imcf;

    if (enabled) {
        imcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_ip2location_module);
        imcf->enabled = 1;
        imcf->enable_file = cf->conf_file->file.name.data;
        imcf->enable_line = cf->conf_file->line;
    }

    return NGX_CONF_OK;
}


static char * ngx_http_ip2location_database(ngx_conf_t *cf, void *data, void *conf)
{
    ngx_http_ip2location_main_conf_t  *imcf;

    imcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_ip2location_module);

    imcf->database_file = cf->conf_file->file.name.data;
    imcf->database_line = cf->conf_file->line;

    return NGX_CONF_OK;
}


static ngx_http_ip2location_ctx_t * ngx_http_ip2location_create_ctx(ngx_http_request_t *r)
{
    ngx_array_t                *xfwd;
    ngx_http_ip2location_ctx_t *ctx;
    ngx_pool_cleanup_t         *cln;
    ngx_http_ip2location_main_conf_t  *imcf;
    ngx_addr_t                  addr;
    u_char                      address[NGX_INET6_ADDRSTRLEN + 1];
    size_t                      size;

    ctx = ngx_http_get_module_ctx(r, ngx_http_ip2location_module);

    if (ctx) {
        return ctx;
    }

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_ip2location_ctx_t));

    if (ctx == NULL) {
        return NULL;
    }

    ngx_http_set_ctx(r, ctx, ngx_http_ip2location_module);

    imcf = ngx_http_get_module_main_conf(r, ngx_http_ip2location_module);
    addr.sockaddr = r->connection->sockaddr;
    addr.socklen = r->connection->socklen;

    xfwd = &r->headers_in.x_forwarded_for;

    if (xfwd->nelts > 0 && imcf->proxies != NULL) {
        (void) ngx_http_get_forwarded_addr(r, &addr, xfwd, NULL, imcf->proxies, imcf->proxy_recursive);
    }

#if defined(nginx_version) && (nginx_version) >= 1005003
    size = ngx_sock_ntop(addr.sockaddr, addr.socklen, address, NGX_INET6_ADDRSTRLEN, 0);
#else
    size = ngx_sock_ntop(addr.sockaddr, address, NGX_INET6_ADDRSTRLEN, 0);
#endif
    address[size] = '\0';

    ctx->record = IP2Location_get_all(imcf->database, (char *)address);

    if (ctx->record == NULL) {
        ctx->not_found = 1;
        return ctx;
    }


    cln = ngx_pool_cleanup_add(r->pool, 0);
    if (cln == NULL) {
        ngx_http_set_ctx(r, NULL, ngx_http_ip2location_module);
        IP2Location_free_record(ctx->record);
        return NULL;
    }


    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
                  "http ip2location record (%s):\n"
                  "       country short: %s\n"
                  "        country long: %s\n"
                  "              region: %s\n"
                  "                city: %s\n"
                  "                 isp: %s\n"
                  "            latitude: %f\n"
                  "           longitude: %f\n"
                  "              domain: %s\n"
                  "             zipcode: %s\n"
                  "            timezone: %s\n"
                  "            netspeed: %s\n"
                  "             iddcode: %s\n"
                  "            areacode: %s\n"
                  "  weatherstationcode: %s\n"
                  "  weatherstationname: %s\n"
                  "                 mcc: %s\n"
                  "                 mnc: %s\n"
                  "         mobilebrand: %s\n"
                  "           elevation: %f\n"
                  "           usagetype: %s\n",
                  address,
                  ctx->record->country_short,
                  ctx->record->country_long,
                  ctx->record->region,
                  ctx->record->city,
                  ctx->record->isp,
                  ctx->record->latitude,
                  ctx->record->longitude,
                  ctx->record->domain,
                  ctx->record->zipcode,
                  ctx->record->timezone,
                  ctx->record->netspeed,
                  ctx->record->iddcode,
                  ctx->record->areacode,
                  ctx->record->weatherstationcode,
                  ctx->record->weatherstationname,
                  ctx->record->mcc,
                  ctx->record->mnc,
                  ctx->record->mobilebrand,
                  ctx->record->elevation,
                  ctx->record->usagetype);

    cln->data = ctx->record;
    cln->handler = (ngx_pool_cleanup_pt) IP2Location_free_record;

    return ctx;
}


static ngx_int_t ngx_http_ip2location_get_str_value(ngx_http_request_t *r,
                                   ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_ip2location_ctx_t      *ctx;
    ngx_http_ip2location_loc_conf_t *ilcf;

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    ilcf = ngx_http_get_module_loc_conf(r, ngx_http_ip2location_module);
    if (!ilcf->enabled) {
        v->not_found = 1;
        return NGX_OK;
    }

    ctx = ngx_http_ip2location_create_ctx(r);

    if (ctx == NULL) {
        return NGX_ERROR;
    }

    if (ctx->not_found) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->data = *(u_char **) ((char *) ctx->record + data);

    if (ngx_strcmp(v->data, NOT_SUPPORTED) == 0
            || ngx_strcmp(v->data, INVALID_IPV4_ADDRESS) == 0 
            || ngx_strcmp(v->data, INVALID_IPV6_ADDRESS) == 0) {

        v->not_found = 1;
        return NGX_OK;
    }

    v->len = ngx_strlen(v->data);

    return NGX_OK;
}


static ngx_int_t ngx_http_ip2location_get_float_value(ngx_http_request_t *r,
                                     ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_ip2location_ctx_t *ctx;
    float                       value;

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    ctx = ngx_http_ip2location_create_ctx(r);

    if (ctx == NULL) {
        return NGX_ERROR;
    }

    if (ctx->not_found) {
        v->not_found = 1;
        return NGX_OK;
    }

    value = *(float*) ((char *) ctx->record + data);

    v->data = ngx_palloc(r->pool, FLOAT_STRING_MAX_LEN);
    if (v->data == NULL) {
        return NGX_ERROR;
    }

    v->len = ngx_snprintf((u_char*)v->data, FLOAT_STRING_MAX_LEN, "%.6f", value)
             - v->data;

    return NGX_OK;
}


static ngx_int_t ngx_http_ip2location_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var, *v;

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


static char * ngx_http_ip2location_proxy(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_ip2location_main_conf_t  *imcf = conf;
    ngx_str_t                         *value;
    ngx_cidr_t                        cidr, *c;

    value = cf->args->elts;

    if (ngx_http_ip2location_cidr_value(cf, &value[1], &cidr) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    if (imcf->proxies == NULL) {
        imcf->proxies = ngx_array_create(cf->pool, 4, sizeof(ngx_cidr_t));
        if (imcf->proxies == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    c = ngx_array_push(imcf->proxies);
    if (c == NULL) {
        return NGX_CONF_ERROR;
    }

    *c = cidr;

    return NGX_CONF_OK;
}


static ngx_int_t ngx_http_ip2location_cidr_value(ngx_conf_t *cf, ngx_str_t *net, ngx_cidr_t *cidr)
{
    ngx_int_t  rc;

    if (ngx_strcmp(net->data, "255.255.255.255") == 0) {
        cidr->family = AF_INET;
        cidr->u.in.addr = 0xffffffff;
        cidr->u.in.mask = 0xffffffff;

        return NGX_OK;
    }

    rc = ngx_ptocidr(net, cidr);

    if (rc == NGX_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid network \"%V\"", net);
        return NGX_ERROR;
    }

    if (rc == NGX_DONE) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0, "low address bits of %V are meaningless", net);
    }

    return NGX_OK;
}
