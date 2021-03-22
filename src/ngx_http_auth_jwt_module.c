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
	ngx_str_t key_source;
	ngx_flag_t enabled;
	ngx_str_t validation_type;
	ngx_str_t algorithm;
	ngx_flag_t use_keyfile;
	ngx_str_t keyfile_path;
	ngx_flag_t validate_roles;
	ngx_str_t roles_grant;
	ngx_array_t *required_roles_source;
	ngx_array_t *required_roles;
	ngx_str_t key;

} ngx_http_auth_jwt_loc_conf_t;

static ngx_int_t ngx_http_auth_jwt_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_auth_jwt_handler(ngx_http_request_t *r);
static void *ngx_http_auth_jwt_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_auth_jwt_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t ngx_http_auth_jwt_init_roles(ngx_conf_t *cf, ngx_http_auth_jwt_loc_conf_t *conf);
static char *get_jwt(ngx_http_request_t *r, ngx_str_t validation_type);
static ngx_flag_t matches_jwt_roles(json_t *json_roles, size_t json_roles_count, ngx_array_t *required_roles);
static ngx_flag_t validate_jwt_token_roles(ngx_http_request_t *r, const char *token_roles, ngx_array_t *required_roles_source);

static ngx_command_t ngx_http_auth_jwt_commands[] = {
	{ngx_string("auth_jwt_key"),
	 NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
	 ngx_conf_set_str_slot,
	 NGX_HTTP_LOC_CONF_OFFSET,
	 offsetof(ngx_http_auth_jwt_loc_conf_t, key_source),
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
	char *jwt_value;
	//char *return_url;
	ngx_http_auth_jwt_loc_conf_t *jwt_cf;
	jwt_t *jwt = NULL;
	int jwt_parse_result;
	jwt_alg_t alg;
	const char *sub;
	const char *roles;
	ngx_str_t sub_t;
	time_t exp;
	time_t now;
	ngx_str_t x_user_id_header = ngx_string("x-userid");

	jwt_cf = ngx_http_get_module_loc_conf(r, ngx_http_auth_jwt_module);

	if (!jwt_cf->enabled)
	{
		return NGX_DECLINED;
	}

	// pass through options requests without token authentication
	if (r->method == NGX_HTTP_OPTIONS)
	{
		return NGX_DECLINED;
	}

	jwt_value = get_jwt(r, jwt_cf->validation_type);
	if (jwt_value == NULL)
	{
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "failed to find a jwt");
		goto redirect;
	}

	// validate the jwt
	jwt_parse_result = jwt_decode(&jwt, jwt_value, jwt_cf->key.data, jwt_cf->key.len);
	if (jwt_parse_result != 0)
	{
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "failed to parse jwt (%d)", jwt_parse_result);
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

	if (jwt_cf->validate_roles == 1 && jwt_cf->required_roles->nelts > 0)
	{
		roles = jwt_get_grants_json(jwt, (const char *)jwt_cf->roles_grant.data);
		if (roles == NULL || validate_jwt_token_roles(r, roles, jwt_cf->required_roles) == 0)
		{
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "jwt roles validation failed");
			goto redirect;
		}
	}

	jwt_free(jwt);

	return NGX_OK;

redirect:
	if (jwt)
	{
		jwt_free(jwt);
	}

	return NGX_HTTP_UNAUTHORIZED;
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

	ngx_conf_merge_str_value(conf->key_source, prev->key_source, "");
	ngx_conf_merge_str_value(conf->validation_type, prev->validation_type, "");
	ngx_conf_merge_str_value(conf->algorithm, prev->algorithm, "HS256");
	ngx_conf_merge_str_value(conf->keyfile_path, prev->keyfile_path, KEY_FILE_PATH);
	ngx_conf_merge_str_value(conf->roles_grant, prev->roles_grant, "");
	ngx_conf_merge_ptr_value(conf->required_roles_source, prev->required_roles_source, NULL);

	if (conf->enabled == ((ngx_flag_t)-1))
	{
		conf->enabled = (prev->enabled == ((ngx_flag_t)-1)) ? 0 : prev->enabled;
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

	// convert key from hex to binary, if a symmetric key
	if (conf->algorithm.len == 0 || (conf->algorithm.len == sizeof("HS256") - 1 && ngx_strncmp(conf->algorithm.data, "HS256", sizeof("HS256") - 1) == 0))
	{
		conf->key.len = conf->key_source.len / 2;
		conf->key.data = ngx_palloc(cf->pool, conf->key.len);

		if (hex_to_binary((char *)conf->key_source.data, conf->key.data, conf->key_source.len) != 0)
		{
			ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "failed to turn hex key into binary");
			return NGX_CONF_ERROR;
		}
	}
	else if (conf->algorithm.len == sizeof("RS256") - 1 && ngx_strncmp(conf->algorithm.data, "RS256", sizeof("RS256") - 1) == 0)
	{
		// in this case, 'Binary' is a misnomer, as it is the public key string itself
		if (conf->use_keyfile == 1)
		{
			FILE *file = fopen((const char *)conf->keyfile_path.data, "rb");

			// Check if file exists or is correctly opened
			if (file == NULL)
			{
				ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "failed to open pub key file '%s'", (const char *)conf->keyfile_path.data);
				return NGX_CONF_ERROR;
			}

			// Read file length
			fseek(file, 0, SEEK_END);
			long key_size = ftell(file);
			fseek(file, 0, SEEK_SET);

			if (key_size == 0)
			{
				fclose(file);

				ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "invalid key file size, check the key file");
				return NGX_CONF_ERROR;
			}

			// Read pub key
			conf->key.len = (size_t)key_size;
			conf->key.data = ngx_palloc(cf->pool, key_size);

			long readBytes = fread(conf->key.data, 1, key_size, file);
			if (readBytes < key_size)
			{
				fclose(file);

				ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "an error occurred reading the key file");
				return NGX_CONF_ERROR;
			}

			fclose(file);
		}
		else
		{
			conf->key.data = conf->key_source.data;
			conf->key.len = conf->key_source.len;
		}
	}
	else
	{
		ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "unsupported algorithm");
		return NGX_CONF_ERROR;
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
	static const ngx_str_t authorization_header_name = ngx_string("Authorization");
	ngx_table_elt_t *authorization_header;
	char *jwt_value = NULL;
	ngx_str_t jwt_http_value;
	ngx_int_t n;
	u_char *p, *equal, *amp, *last;

	ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "validation_type.len %d", validation_type.len);

	if (validation_type.len == 0 || (validation_type.len == (sizeof("AUTHORIZATION") - 1) && ngx_strncmp(validation_type.data, "AUTHORIZATION", (sizeof("AUTHORIZATION") - 1)) == 0))
	{
		// using authorization header
		authorization_header = search_headers_in(r, authorization_header_name.data, authorization_header_name.len);
		if (authorization_header != NULL && authorization_header->value.len > (sizeof("Bearer ") - 1))
		{
			ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "Found authorization header len %d", authorization_header->value.len);

			jwt_http_value.data = authorization_header->value.data + (sizeof("Bearer ") - 1);
			jwt_http_value.len = authorization_header->value.len - (sizeof("Bearer ") - 1);

			jwt_value = ngx_str_t_to_char_ptr(r->pool, jwt_http_value);
		}
	}
	else if (validation_type.len > sizeof("COOKIE=") && ngx_strncmp(validation_type.data, "COOKIE=", (sizeof("COOKIE=") - 1)) == 0)
	{
		validation_type.data += (sizeof("COOKIE=") - 1);
		validation_type.len -= (sizeof("COOKIE=") - 1);

		// get the cookie
		n = ngx_http_parse_multi_header_lines(&r->headers_in.cookies, &validation_type, &jwt_http_value);
		if (n != NGX_DECLINED)
		{
			jwt_value = ngx_str_t_to_char_ptr(r->pool, jwt_http_value);
		}
	}
	else if (validation_type.len > sizeof("URL=") && ngx_strncmp(validation_type.data, "URL=", (sizeof("URL=") - 1)) == 0)
	{
		if (r->args.len > (validation_type.len - (sizeof("URL=") - 1)) + 1)
		{
			validation_type.data += (sizeof("URL=") - 1);
			validation_type.len -= (sizeof("URL=") - 1);

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
						jwt_value = ngx_uchar_to_char_ptr(r->pool, equal, amp - equal);
					}
				}
			}
		}
	}

	return jwt_value;
}

static ngx_flag_t matches_jwt_roles(json_t *json_roles, size_t json_roles_count, ngx_array_t *required_roles)
{
	ngx_flag_t result;
	size_t i, j;
	const char *role;
	ngx_http_auth_jwt_roles_t *jwt_roles;

	hashset_t hashset;
	hashset.nentries = 0;
	hashset.capacity = json_roles_count;

	if (json_roles_count > 1024)
	{
		hashset.buckets = (size_t *)malloc(json_roles_count * sizeof(size_t));
		hashset.entries = (hashset_entry_t *)malloc(json_roles_count * sizeof(hashset_entry_t));
	}
	else
	{
		hashset.buckets = (size_t *)alloca(json_roles_count * sizeof(size_t));
		hashset.entries = (hashset_entry_t *)alloca(json_roles_count * sizeof(hashset_entry_t));
	}

	memset(hashset.buckets, 0, json_roles_count * sizeof(size_t));
	memset(hashset.entries, 0, json_roles_count * sizeof(hashset_entry_t));

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

		result = 1;
		goto end;

	next_policy:
		i++;
	}

	result = 0;

end:
	if (json_roles_count > 1024)
	{
		free(hashset.buckets);
		free(hashset.entries);
	}

	return result;
}

static ngx_flag_t validate_jwt_token_roles(ngx_http_request_t *r, const char *token_roles, ngx_array_t *required_roles)
{
	const char *role;
	json_t *json_roles;
	json_error_t error;
	size_t i, json_roles_count;
	ngx_http_auth_jwt_roles_t *jwt_roles;

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
				if (matches_jwt_roles(json_roles, json_roles_count, required_roles))
				{
					goto success;
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
