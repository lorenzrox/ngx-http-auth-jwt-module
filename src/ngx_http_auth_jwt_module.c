/*
 * Copyright (C) 2018 Tesla Government
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 *
 * https://github.com/TeslaGov/ngx-http-auth-jwt-module
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <jwt.h>

#include <jansson.h>

#include "ngx_http_auth_jwt_header_processing.h"
#include "ngx_http_auth_jwt_binary_converters.h"
#include "ngx_http_auth_jwt_string.h"

#include <stdio.h>
#include "hashset.h"

static const char *KEY_FILE_PATH = "/app/pub_key";

typedef struct
{
	ngx_array_t roles;
} ngx_http_auth_jwt_roles_t;

typedef struct
{
	ngx_str_t loginurl;
	ngx_str_t key;
	ngx_flag_t enabled;
	ngx_flag_t redirect;
	ngx_str_t validation_type;
	ngx_str_t algorithm;
	ngx_flag_t use_keyfile;
	ngx_str_t keyfile_path;
	ngx_flag_t validate_roles;
	ngx_str_t roles_grant;
	ngx_array_t *required_roles_source;
	ngx_array_t *required_roles;

} ngx_http_auth_jwt_loc_conf_t;

static ngx_int_t ngx_http_auth_jwt_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_auth_jwt_handler(ngx_http_request_t *r);
static void *ngx_http_auth_jwt_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_auth_jwt_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t ngx_http_auth_jwt_init_roles(ngx_conf_t *cf, ngx_http_auth_jwt_loc_conf_t *conf);
static char *get_jwt(ngx_http_request_t *r, ngx_str_t validation_type);
static ngx_flag_t validate_jwt_token_roles(ngx_http_request_t *r, const char *token_roles, ngx_array_t *required_roles_source);

static ngx_command_t ngx_http_auth_jwt_commands[] = {

	{ngx_string("auth_jwt_loginurl"),
	 NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
	 ngx_conf_set_str_slot,
	 NGX_HTTP_LOC_CONF_OFFSET,
	 offsetof(ngx_http_auth_jwt_loc_conf_t, loginurl),
	 NULL},

	{ngx_string("auth_jwt_key"),
	 NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
	 ngx_conf_set_str_slot,
	 NGX_HTTP_LOC_CONF_OFFSET,
	 offsetof(ngx_http_auth_jwt_loc_conf_t, key),
	 NULL},

	{ngx_string("auth_jwt_enabled"),
	 NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
	 ngx_conf_set_flag_slot,
	 NGX_HTTP_LOC_CONF_OFFSET,
	 offsetof(ngx_http_auth_jwt_loc_conf_t, enabled),
	 NULL},

	{ngx_string("auth_jwt_use_keyfile"),
	 NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
	 ngx_conf_set_flag_slot,
	 NGX_HTTP_LOC_CONF_OFFSET,
	 offsetof(ngx_http_auth_jwt_loc_conf_t, use_keyfile),
	 NULL},

	{ngx_string("auth_jwt_keyfile_path"),
	 NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
	 ngx_conf_set_str_slot,
	 NGX_HTTP_LOC_CONF_OFFSET,
	 offsetof(ngx_http_auth_jwt_loc_conf_t, keyfile_path),
	 NULL},

	{ngx_string("auth_jwt_redirect"),
	 NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
	 ngx_conf_set_flag_slot,
	 NGX_HTTP_LOC_CONF_OFFSET,
	 offsetof(ngx_http_auth_jwt_loc_conf_t, redirect),
	 NULL},

	{ngx_string("auth_jwt_validation_type"),
	 NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
	 ngx_conf_set_str_slot,
	 NGX_HTTP_LOC_CONF_OFFSET,
	 offsetof(ngx_http_auth_jwt_loc_conf_t, validation_type),
	 NULL},

	{ngx_string("auth_jwt_algorithm"),
	 NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
	 ngx_conf_set_str_slot,
	 NGX_HTTP_LOC_CONF_OFFSET,
	 offsetof(ngx_http_auth_jwt_loc_conf_t, algorithm),
	 NULL},

	{ngx_string("auth_jwt_validate_roles"),
	 NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
	 ngx_conf_set_flag_slot,
	 NGX_HTTP_LOC_CONF_OFFSET,
	 offsetof(ngx_http_auth_jwt_loc_conf_t, validate_roles),
	 NULL},

	{ngx_string("auth_jwt_roles_grant"),
	 NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
	 ngx_conf_set_str_slot,
	 NGX_HTTP_LOC_CONF_OFFSET,
	 offsetof(ngx_http_auth_jwt_loc_conf_t, roles_grant),
	 NULL},

	{ngx_string("auth_jwt_required_role"),
	 NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
	 ngx_conf_set_str_array_slot,
	 NGX_HTTP_LOC_CONF_OFFSET,
	 offsetof(ngx_http_auth_jwt_loc_conf_t, required_roles_source),
	 NULL},

	ngx_null_command};

static ngx_http_module_t ngx_http_auth_jwt_module_ctx = {
	NULL,					/* preconfiguration */
	ngx_http_auth_jwt_init, /* postconfiguration */

	NULL, /* create main configuration */
	NULL, /* init main configuration */

	NULL, /* create server configuration */
	NULL, /* merge server configuration */

	ngx_http_auth_jwt_create_loc_conf, /* create location configuration */
	ngx_http_auth_jwt_merge_loc_conf   /* merge location configuration */
};

ngx_module_t ngx_http_auth_jwt_module = {
	NGX_MODULE_V1,
	&ngx_http_auth_jwt_module_ctx, /* module context */
	ngx_http_auth_jwt_commands,	   /* module directives */
	NGX_HTTP_MODULE,			   /* module type */
	NULL,						   /* init master */
	NULL,						   /* init module */
	NULL,						   /* init process */
	NULL,						   /* init thread */
	NULL,						   /* exit thread */
	NULL,						   /* exit process */
	NULL,						   /* exit master */
	NGX_MODULE_V1_PADDING};

static ngx_int_t ngx_http_auth_jwt_handler(ngx_http_request_t *r)
{
	char *jwtCookieValChrPtr;
	char *return_url;
	ngx_http_auth_jwt_loc_conf_t *jwtcf;
	u_char *keyBinary;
	// For clearing it later on
	char *pub_key = NULL;
	jwt_t *jwt = NULL;
	int jwtParseReturnCode;
	jwt_alg_t alg;
	const char *sub;
	const char *roles;
	ngx_str_t sub_t;
	time_t exp;
	time_t now;
	int keylen;
	ngx_str_t x_user_id_header = ngx_string("x-userid");

	jwtcf = ngx_http_get_module_loc_conf(r, ngx_http_auth_jwt_module);

	if (!jwtcf->enabled)
	{
		return NGX_DECLINED;
	}

	// pass through options requests without token authentication
	if (r->method == NGX_HTTP_OPTIONS)
	{
		return NGX_DECLINED;
	}

	jwtCookieValChrPtr = get_jwt(r, jwtcf->validation_type);
	if (jwtCookieValChrPtr == NULL)
	{
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "failed to find a jwt");
		goto redirect;
	}

	// convert key from hex to binary, if a symmetric key

	if (jwtcf->algorithm.len == 0 || (jwtcf->algorithm.len == sizeof("HS256") - 1 && ngx_strncmp(jwtcf->algorithm.data, "HS256", sizeof("HS256") - 1) == 0))
	{
		keylen = jwtcf->key.len / 2;
		keyBinary = ngx_palloc(r->pool, keylen);

		if (hex_to_binary((char *)jwtcf->key.data, keyBinary, jwtcf->key.len) != 0)
		{
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "failed to turn hex key into binary");
			goto redirect;
		}
	}
	else if (jwtcf->algorithm.len == sizeof("RS256") - 1 && ngx_strncmp(jwtcf->algorithm.data, "RS256", sizeof("RS256") - 1) == 0)
	{
		// in this case, 'Binary' is a misnomer, as it is the public key string itself
		if (jwtcf->use_keyfile == 1)
		{
			FILE *file = fopen((const char *)jwtcf->keyfile_path.data, "rb");

			// Check if file exists or is correctly opened
			if (file == NULL)
			{
				ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "failed to open pub key file '%s'", (const char *)jwtcf->keyfile_path.data);
				goto redirect;
			}

			// Read file length
			fseek(file, 0, SEEK_END);
			long key_size = ftell(file);
			fseek(file, 0, SEEK_SET);

			if (key_size == 0)
			{
				fclose(file);

				ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "invalid key file size, check the key file");
				goto redirect;
			}

			// Read pub key
			pub_key = malloc(key_size + 1);

			long readBytes = fread(pub_key, 1, key_size, file);
			if (readBytes < key_size)
			{
				fclose(file);

				ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "an error occurred reading the key file");
				goto redirect;
			}

			fclose(file);

			keyBinary = (u_char *)pub_key;
			keylen = (int)key_size;
		}
		else
		{
			keyBinary = jwtcf->key.data;
			keylen = jwtcf->key.len;
		}
	}
	else
	{
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "unsupported algorithm");
		goto redirect;
	}

	// validate the jwt
	jwtParseReturnCode = jwt_decode(&jwt, jwtCookieValChrPtr, keyBinary, keylen);
	if (jwtParseReturnCode != 0)
	{
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "failed to parse jwt");
		goto redirect;
	}

	// validate the algorithm
	alg = jwt_get_alg(jwt);
	if (alg != JWT_ALG_HS256 && alg != JWT_ALG_RS256)
	{
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "invalid algorithm in jwt %d", alg);
		goto redirect;
	}

	// validate the exp date of the JWT
	exp = (time_t)jwt_get_grant_int(jwt, "exp");
	now = time(NULL);
	if (exp < now)
	{
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "the jwt has expired");
		goto redirect;
	}

	// extract the userid
	sub = jwt_get_grant(jwt, "sub");
	if (sub == NULL)
	{
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "the jwt does not contain a subject");
	}
	else
	{
		sub_t = ngx_char_ptr_to_str_t(r->pool, (char *)sub);
		set_custom_header_in_headers_out(r, &x_user_id_header, &sub_t);
	}

	if (jwtcf->validate_roles == 1 && jwtcf->required_roles->nelts > 0)
	{
		roles = jwt_get_grants_json(jwt, (const char *)jwtcf->roles_grant.data);
		if (roles == NULL || validate_jwt_token_roles(r, roles, jwtcf->required_roles) == 0)
		{
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "jwt roles validation failed");
			goto redirect;
		}
	}

	jwt_free(jwt);

	if (pub_key == NULL)
	{
		free(pub_key);
	}

	return NGX_OK;

redirect:
	if (jwt)
	{
		jwt_free(jwt);
	}

	r->headers_out.location = ngx_list_push(&r->headers_out.headers);

	if (r->headers_out.location == NULL)
	{
		ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
	}

	r->headers_out.location->hash = 1;
	r->headers_out.location->key.len = sizeof("Location") - 1;
	r->headers_out.location->key.data = (u_char *)"Location";

	if (r->method == NGX_HTTP_GET)
	{
		int loginlen;
		char *scheme;
		ngx_str_t server;
		ngx_str_t uri_variable_name = ngx_string("request_uri");
		ngx_int_t uri_variable_hash;
		ngx_http_variable_value_t *request_uri_var;
		ngx_str_t uri;
		ngx_str_t uri_escaped;
		uintptr_t escaped_len;

		loginlen = jwtcf->loginurl.len;

		scheme = (r->connection->ssl) ? "https" : "http";
		server = r->headers_in.server;

		// get the URI
		uri_variable_hash = ngx_hash_key(uri_variable_name.data, uri_variable_name.len);
		request_uri_var = ngx_http_get_variable(r, &uri_variable_name, uri_variable_hash);

		// get the URI
		if (request_uri_var && !request_uri_var->not_found && request_uri_var->valid)
		{
			// ideally we would like the uri with the querystring parameters
			uri.data = ngx_palloc(r->pool, request_uri_var->len);
			uri.len = request_uri_var->len;
			ngx_memcpy(uri.data, request_uri_var->data, request_uri_var->len);

			// ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "found uri with querystring %s", ngx_str_t_to_char_ptr(r->pool, uri));
		}
		else
		{
			// fallback to the querystring without params
			uri = r->uri;

			// ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "fallback to querystring without params");
		}

		// escape the URI
		escaped_len = 2 * ngx_escape_uri(NULL, uri.data, uri.len, NGX_ESCAPE_ARGS) + uri.len;
		uri_escaped.data = ngx_palloc(r->pool, escaped_len);
		uri_escaped.len = escaped_len;
		ngx_escape_uri(uri_escaped.data, uri.data, uri.len, NGX_ESCAPE_ARGS);

		r->headers_out.location->value.len = loginlen + sizeof("?return_url=") - 1 + strlen(scheme) + sizeof("://") - 1 + server.len + uri_escaped.len;
		return_url = ngx_palloc(r->pool, r->headers_out.location->value.len);
		ngx_memcpy(return_url, jwtcf->loginurl.data, jwtcf->loginurl.len);
		int return_url_idx = jwtcf->loginurl.len;
		ngx_memcpy(return_url + return_url_idx, "?return_url=", sizeof("?return_url=") - 1);
		return_url_idx += sizeof("?return_url=") - 1;
		ngx_memcpy(return_url + return_url_idx, scheme, strlen(scheme));
		return_url_idx += strlen(scheme);
		ngx_memcpy(return_url + return_url_idx, "://", sizeof("://") - 1);
		return_url_idx += sizeof("://") - 1;
		ngx_memcpy(return_url + return_url_idx, server.data, server.len);
		return_url_idx += server.len;
		ngx_memcpy(return_url + return_url_idx, uri_escaped.data, uri_escaped.len);
		return_url_idx += uri_escaped.len;
		r->headers_out.location->value.data = (u_char *)return_url;

		// ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "return_url: %s", ngx_str_t_to_char_ptr(r->pool, r->headers_out.location->value));
	}
	else
	{
		// for non-get requests, redirect to the login page without a return URL
		r->headers_out.location->value.len = jwtcf->loginurl.len;
		r->headers_out.location->value.data = jwtcf->loginurl.data;
	}

	if (jwtcf->redirect)
	{
		return NGX_HTTP_MOVED_TEMPORARILY;
	}
	else
	{
		return NGX_HTTP_UNAUTHORIZED;
	}
}

static ngx_int_t ngx_http_auth_jwt_init(ngx_conf_t *cf)
{
	ngx_http_handler_pt *h;
	ngx_http_core_main_conf_t *cmcf;

	cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

	h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
	if (h == NULL)
	{
		return NGX_ERROR;
	}

	*h = ngx_http_auth_jwt_handler;
	return NGX_OK;
}

static void *ngx_http_auth_jwt_create_loc_conf(ngx_conf_t *cf)
{
	ngx_http_auth_jwt_loc_conf_t *conf;

	conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_auth_jwt_loc_conf_t));
	if (conf == NULL)
	{
		return NULL;
	}

	// set the flag to unset
	conf->enabled = (ngx_flag_t)-1;
	conf->redirect = (ngx_flag_t)-1;
	conf->use_keyfile = (ngx_flag_t)-1;
	conf->validate_roles = (ngx_flag_t)-1;
	conf->required_roles_source = NGX_CONF_UNSET_PTR;

	ngx_conf_log_error(NGX_LOG_DEBUG, cf, 0, "Created Location Configuration");

	return conf;
}

static char *ngx_http_auth_jwt_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
	ngx_int_t rc;
	ngx_http_auth_jwt_loc_conf_t *prev = parent;
	ngx_http_auth_jwt_loc_conf_t *conf = child;

	ngx_conf_merge_str_value(conf->loginurl, prev->loginurl, "");
	ngx_conf_merge_str_value(conf->key, prev->key, "");
	ngx_conf_merge_str_value(conf->validation_type, prev->validation_type, "");
	ngx_conf_merge_str_value(conf->algorithm, prev->algorithm, "HS256");
	ngx_conf_merge_str_value(conf->keyfile_path, prev->keyfile_path, KEY_FILE_PATH);
	ngx_conf_merge_str_value(conf->roles_grant, prev->roles_grant, "");
	ngx_conf_merge_ptr_value(conf->required_roles_source, prev->required_roles_source, NULL);

	if (conf->enabled == ((ngx_flag_t)-1))
	{
		conf->enabled = (prev->enabled == ((ngx_flag_t)-1)) ? 0 : prev->enabled;
	}

	if (conf->redirect == ((ngx_flag_t)-1))
	{
		conf->redirect = (prev->redirect == ((ngx_flag_t)-1)) ? 0 : prev->redirect;
	}

	if (conf->use_keyfile == ((ngx_flag_t)-1))
	{
		conf->use_keyfile = (prev->use_keyfile == ((ngx_flag_t)-1)) ? 0 : prev->use_keyfile;
	}

	if (conf->validate_roles == ((ngx_flag_t)-1))
	{
		conf->validate_roles = (prev->validate_roles == ((ngx_flag_t)-1)) ? 0 : prev->validate_roles;
	}

	if (conf->required_roles_source == prev->required_roles_source)
	{
		conf->required_roles = prev->required_roles;
	}
	else
	{
		rc = ngx_http_auth_jwt_init_roles(cf, conf);
		if (rc != NGX_OK)
		{
			return NGX_CONF_ERROR;
		}
	}

	return NGX_CONF_OK;
}

static ngx_int_t ngx_http_auth_jwt_init_roles(ngx_conf_t *cf, ngx_http_auth_jwt_loc_conf_t *conf)
{
	ngx_uint_t i;
	ngx_http_auth_jwt_roles_t *roles;
	ngx_str_t *role;
	char *token;
	char *context;

	conf->required_roles = ngx_array_create(cf->pool, 1, sizeof(ngx_http_auth_jwt_roles_t));
	if (conf->required_roles == NULL)
	{
		return NGX_ERROR;
	}

	if (conf->required_roles_source)
	{
		for (i = 0; i < conf->required_roles_source->nelts; i++)
		{
			role = &((ngx_str_t *)conf->required_roles_source->elts)[i];
			if (role && role->len > 0)
			{
				context = NULL;
				token = strtok_r((char *)role->data, " ", &context);

				if (token == NULL)
				{
					continue;
				}

				roles = (ngx_http_auth_jwt_roles_t *)ngx_array_push(conf->required_roles);
				if (roles == NULL)
				{
					return NGX_ERROR;
				}

				if (ngx_array_init(&roles->roles, cf->pool, 1, sizeof(ngx_str_t)) != NGX_OK)
				{
					return NGX_ERROR;
				}

				do
				{
					role = (ngx_str_t *)ngx_array_push(&roles->roles);
					if (role == NULL)
					{
						return NGX_ERROR;
					}

					role->len = ngx_strlen(token);
					role->data = ngx_palloc(cf->pool, role->len + 1);
					ngx_memcpy(role->data, token, role->len + 1);

					ngx_log_error(NGX_LOG_ERR, cf->log, 0, "Found role %s for policy %d", token, i);

					token = strtok_r(NULL, " ", &context);
				} while (token != NULL);
			}
		}
	}

	return NGX_OK;
}

static char *get_jwt(ngx_http_request_t *r, ngx_str_t validation_type)
{
	static const ngx_str_t authorizationHeaderName = ngx_string("Authorization");
	ngx_table_elt_t *authorizationHeader;
	char *jwtCookieValChrPtr = NULL;
	ngx_str_t jwtCookieVal;
	ngx_int_t n;
	ngx_str_t authorizationHeaderStr;
	u_char *p, *equal, *amp, *last;

	ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "validation_type.len %d", validation_type.len);

	if (validation_type.len == 0 || (validation_type.len == sizeof("AUTHORIZATION") - 1 && ngx_strncmp(validation_type.data, "AUTHORIZATION", sizeof("AUTHORIZATION") - 1) == 0))
	{
		// using authorization header
		authorizationHeader = search_headers_in(r, authorizationHeaderName.data, authorizationHeaderName.len);
		if (authorizationHeader != NULL && authorizationHeader->value.len > (sizeof("Bearer ") - 1))
		{
			ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "Found authorization header len %d", authorizationHeader->value.len);

			authorizationHeaderStr.data = authorizationHeader->value.data + sizeof("Bearer ") - 1;
			authorizationHeaderStr.len = authorizationHeader->value.len - (sizeof("Bearer ") - 1);

			jwtCookieValChrPtr = ngx_str_t_to_char_ptr(r->pool, authorizationHeaderStr);
		}
	}
	else if (validation_type.len > sizeof("COOKIE=") && ngx_strncmp(validation_type.data, "COOKIE=", sizeof("COOKIE=") - 1) == 0)
	{
		validation_type.data += sizeof("COOKIE=") - 1;
		validation_type.len -= sizeof("COOKIE=") - 1;

		// get the cookie
		// TODO: the cookie name could be passed in dynamicallly
		n = ngx_http_parse_multi_header_lines(&r->headers_in.cookies, &validation_type, &jwtCookieVal);
		if (n != NGX_DECLINED)
		{
			jwtCookieValChrPtr = ngx_str_t_to_char_ptr(r->pool, jwtCookieVal);
		}
	}
	else if (validation_type.len > sizeof("URL=") && ngx_strncmp(validation_type.data, "URL=", sizeof("URL=") - 1) == 0)
	{
		if (r->args.len > (validation_type.len - (sizeof("URL=") - 1)) + 1)
		{
			validation_type.data += sizeof("URL=") - 1;
			validation_type.len -= sizeof("URL=") - 1;

			p = (u_char *)ngx_strstr(r->args.data, validation_type.data);
			if (p != NULL)
			{
				last = r->args.data + r->args.len;
				equal = ngx_strlchr(p + validation_type.len, last, '=');
				if (equal != NULL)
				{
					amp = ngx_strlchr(++equal, last, '&');
					if (amp == NULL)
					{
						amp = last;
					}

					if (amp - equal > 0)
					{
						jwtCookieValChrPtr = ngx_uchar_to_char_ptr(r->pool, equal, amp - equal);
					}
				}
			}
		}
	}

	return jwtCookieValChrPtr;
}

static ngx_flag_t validate_jwt_token_roles(ngx_http_request_t *r, const char *token_roles, ngx_array_t *required_roles)
{
	const char *role;
	json_t *json_roles;
	json_error_t error;
	size_t i, j, json_roles_count;
	ngx_http_auth_jwt_roles_t *jwt_roles;
	hashset_t hashset;

	json_roles = json_loads(token_roles, JSON_DECODE_ANY | JSON_DISABLE_EOF_CHECK, &error);
	if (json_roles != NULL)
	{
		if (json_is_array(json_roles))
		{
			json_roles_count = json_array_size(json_roles);
			if (json_roles_count == 1)
			{
				role = json_string_value(json_array_get(json_roles, 0));
				if (role != NULL)
				{
					for (i = 0; i < required_roles->nelts; i++)
					{
						jwt_roles = &((ngx_http_auth_jwt_roles_t *)required_roles->elts)[i];
						if (jwt_roles->roles.nelts == 1 && ngx_strcasecmp(((ngx_str_t *)jwt_roles->roles.elts)[0].data, (u_char *)role) == 0)
						{
							goto success;
						}
					}
				}
			}
			else if (json_roles_count > 0)
			{
				if (hashset_init(&hashset, json_roles_count) == NGX_OK)
				{
					for (i = 0; i < json_roles_count; i++)
					{
						role = json_string_value(json_array_get(json_roles, i));
						if (role == NULL)
						{
							continue;
						}

						hashset_add(&hashset, role);
					}

					for (i = 0; i < required_roles->nelts;)
					{
						jwt_roles = &((ngx_http_auth_jwt_roles_t *)required_roles->elts)[i];
						if (jwt_roles->roles.nelts != json_roles_count)
						{
							goto next_policy;
						}

						for (j = 0; j < jwt_roles->roles.nelts;)
						{
							if (hashset_contains(&hashset, (const char *)((ngx_str_t *)jwt_roles->roles.elts)[j].data))
							{
								goto next_role;
							}

							goto next_policy;

						next_role:
							j++;
						}

					next_policy:
						i++;
					}

					hashset_destroy(&hashset);
				}
			}
		}
		else if (json_is_string(json_roles))
		{
			role = json_string_value(json_roles);
			if (role != NULL)
			{
				for (i = 0; i < required_roles->nelts; i++)
				{
					jwt_roles = &((ngx_http_auth_jwt_roles_t *)required_roles->elts)[i];
					if (jwt_roles->roles.nelts == 1 && ngx_strcasecmp(((ngx_str_t *)jwt_roles->roles.elts)[0].data, (u_char *)role) == 0)
					{
						goto success;
					}
				}
			}
		}

		json_decref(json_roles);
	}
	else
	{
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, error.text);
	}

	return 0;

success:
	json_decref(json_roles);
	return 1;
}
