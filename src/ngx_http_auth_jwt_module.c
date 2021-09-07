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

typedef char *(*ngx_http_auth_jwt_access_pt)(ngx_http_request_t *r, ngx_str_t *context);

typedef enum
{
	ACCESS_TYPE_ALLOW = 0,
	ACCESS_TYPE_DENY = 1
} ngx_http_auth_jwt_policy_access_type_t;

typedef struct
{
	ngx_http_auth_jwt_policy_access_type_t access_type;
	ngx_array_t *users;
	ngx_array_t *roles;
} ngx_http_auth_jwt_policy_t;

typedef struct
{
	ngx_str_t grant;
	ngx_str_t header;
	ngx_flag_t replace;
} ngx_http_auth_jwt_grant_mapping_t;

typedef struct
{
	ngx_http_auth_jwt_access_pt handler;
	ngx_str_t context;
} ngx_http_auth_jwt_accessor_t;

typedef struct
{
	ngx_str_t key_source;
	ngx_flag_t enabled;
	ngx_str_t validation_type;
	ngx_str_t algorithm;
	ngx_str_t keyfile_path;
	ngx_str_t name_grant;
	ngx_str_t role_grant;
	ngx_array_t *policies;
	ngx_array_t *grant_header_mappings;
	ngx_str_t key;
	ngx_http_auth_jwt_accessor_t jwt_accessor;

} ngx_http_auth_jwt_loc_conf_t;

static ngx_int_t ngx_http_auth_jwt_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_auth_jwt_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_auth_set_headers(ngx_http_request_t *r, jwt_t *jwt, ngx_http_auth_jwt_loc_conf_t *jwt_cf);
static void *ngx_http_auth_jwt_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_auth_jwt_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
static char *get_jwt_from_header(ngx_http_request_t *r, ngx_str_t *context);
static char *get_jwt_from_cookie(ngx_http_request_t *r, ngx_str_t *context);
static char *get_jwt_from_url(ngx_http_request_t *r, ngx_str_t *context);
static ngx_flag_t matches_jwt_policy_n(ngx_http_request_t *r, const char *user, json_t *json_roles, size_t json_roles_count, ngx_array_t *policies);
static ngx_flag_t matches_jwt_policy(ngx_http_request_t *r, const char *user, const char *role, ngx_array_t *policies);
static ngx_flag_t validate_jwt_token_policies(ngx_http_request_t *r, jwt_t *jwt, ngx_http_auth_jwt_loc_conf_t *jwt_cf);
static char *ngx_http_auth_jwt_add_policy(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_auth_jwt_add_grant_header_mapping(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

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

	{ngx_string("auth_jwt_name_grant"),
	 NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
	 ngx_conf_set_str_slot,
	 NGX_HTTP_LOC_CONF_OFFSET,
	 offsetof(ngx_http_auth_jwt_loc_conf_t, name_grant),
	 NULL},

	{ngx_string("auth_jwt_role_grant"),
	 NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
	 ngx_conf_set_str_slot,
	 NGX_HTTP_LOC_CONF_OFFSET,
	 offsetof(ngx_http_auth_jwt_loc_conf_t, role_grant),
	 NULL},

	{ngx_string("auth_jwt_policy"),
	 NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE23,
	 ngx_http_auth_jwt_add_policy,
	 NGX_HTTP_LOC_CONF_OFFSET,
	 offsetof(ngx_http_auth_jwt_loc_conf_t, policies),
	 NULL},

	{ngx_string("auth_jwt_grant_header_mapping"),
	 NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE23,
	 ngx_http_auth_jwt_add_grant_header_mapping,
	 NGX_HTTP_LOC_CONF_OFFSET,
	 offsetof(ngx_http_auth_jwt_loc_conf_t, grant_header_mappings),
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

inline static void ngx_log_policy(ngx_uint_t level, ngx_log_t *log, ngx_err_t err, ngx_http_auth_jwt_policy_t *policy)
{
	char *type;
	char users[NGX_MAX_ERROR_STR];
	char roles[NGX_MAX_ERROR_STR];

	if (policy->access_type == ACCESS_TYPE_ALLOW)
	{
		type = "allow";
	}
	else
	{
		type = "deny";
	}

	ngx_memzero(users, sizeof(users));
	ngx_memzero(roles, sizeof(roles));

	ngx_str_t str;
	str.len = NGX_MAX_ERROR_STR;

	str.data = (u_char *)users;
	ngx_str_join(policy->users, &str, ",");

	str.data = (u_char *)roles;
	ngx_str_join(policy->roles, &str, ",");

	ngx_log_error(level, log, err, "validating policy with type=%s, users=[%s], roles=[%s]", type, users, roles);
}

static ngx_int_t ngx_http_auth_jwt_handler(ngx_http_request_t *r)
{
	jwt_t *jwt = NULL;
	char *jwt_value;
	ngx_http_auth_jwt_loc_conf_t *jwt_cf;
	int jwt_parse_result;
	jwt_alg_t alg;
	time_t exp;
	time_t now;

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

	jwt_value = jwt_cf->jwt_accessor.handler(r, &jwt_cf->jwt_accessor.context);
	if (jwt_value == NULL)
	{
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "failed to find a jwt");
		goto unauthorized;
	}

	// validate the jwt
	jwt_parse_result = jwt_decode(&jwt, jwt_value, jwt_cf->key.data, jwt_cf->key.len);
	if (jwt_parse_result != 0)
	{
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "failed to parse jwt (%d)", jwt_parse_result);
		goto unauthorized;
	}

	// validate the algorithm
	alg = jwt_get_alg(jwt);
	if (alg != JWT_ALG_HS256 && alg != JWT_ALG_RS256)
	{
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "invalid algorithm in jwt %d", alg);
		goto unauthorized;
	}

	// validate the exp date of the JWT
	exp = (time_t)jwt_get_grant_int(jwt, "exp");
	now = time(NULL);
	if (exp < now)
	{
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "the jwt has expired");
		goto unauthorized;
	}

#if NGX_DEBUG
	ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "found valid jwt token: %s", jwt_value);
#endif

	if (validate_jwt_token_policies(r, jwt, jwt_cf) == 0)
	{
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "jwt policy validation failed");
		goto unauthorized;
	}

	if (ngx_http_auth_set_headers(r, jwt, jwt_cf) == 0)
	{
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "an error occurred mapping grants");
		goto unauthorized;
	}

	jwt_free(jwt);

	return NGX_OK;

unauthorized:
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
	conf->policies = NGX_CONF_UNSET_PTR;
	conf->grant_header_mappings = NGX_CONF_UNSET_PTR;

	ngx_conf_log_error(NGX_LOG_DEBUG, cf, 0, "Created Location Configuration");

	return conf;
}

static char *ngx_http_auth_jwt_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
	ngx_http_auth_jwt_loc_conf_t *prev = parent;
	ngx_http_auth_jwt_loc_conf_t *conf = child;

	ngx_conf_merge_str_value(conf->key_source, prev->key_source, "");
	ngx_conf_merge_str_value(conf->validation_type, prev->validation_type, "");
	ngx_conf_merge_str_value(conf->algorithm, prev->algorithm, "HS256");
	ngx_conf_merge_str_value(conf->keyfile_path, prev->keyfile_path, "");
	ngx_conf_merge_str_value(conf->name_grant, prev->name_grant, "sub");
	ngx_conf_merge_str_value(conf->role_grant, prev->role_grant, "role");
	ngx_conf_merge_ptr_value(conf->policies, prev->policies, NULL);
	ngx_conf_merge_ptr_value(conf->grant_header_mappings, prev->grant_header_mappings, NULL);

	if (conf->enabled == ((ngx_flag_t)-1))
	{
		conf->enabled = (prev->enabled == ((ngx_flag_t)-1)) ? 0 : prev->enabled;
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
		if (conf->keyfile_path.len > 0)
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

	if (conf->validation_type.len == 0)
	{
		conf->jwt_accessor.handler = get_jwt_from_header;
		conf->jwt_accessor.context.data = (u_char *)"Authorization";
		conf->jwt_accessor.context.len = sizeof("Authorization") - 1;

		ngx_conf_log_error(NGX_LOG_DEBUG, cf, 0, "Serching for jwt in header 'Authorization'");
	}
	else if (conf->validation_type.len >= (sizeof("HEADER=") - 1) && ngx_strncmp(conf->validation_type.data, "HEADER=", (sizeof("HEADER=") - 1)) == 0)
	{
		conf->jwt_accessor.handler = get_jwt_from_header;
		conf->jwt_accessor.context.len = conf->validation_type.len - (sizeof("HEADER=") - 1);

		if (conf->jwt_accessor.context.len == 0)
		{
			conf->jwt_accessor.context.data = (u_char *)"Authorization";
			conf->jwt_accessor.context.len = sizeof("Authorization") - 1;
		}
		else
		{
			conf->jwt_accessor.context.data = conf->validation_type.data + (sizeof("HEADER=") - 1);
		}

		ngx_conf_log_error(NGX_LOG_DEBUG, cf, 0, "Serching for jwt in header '%s'", conf->jwt_accessor.context.data);
	}
	else if (conf->validation_type.len >= (sizeof("COOKIE=") - 1) && ngx_strncmp(conf->validation_type.data, "COOKIE=", (sizeof("COOKIE=") - 1)) == 0)
	{
		conf->jwt_accessor.handler = get_jwt_from_cookie;
		conf->jwt_accessor.context.len = conf->validation_type.len - (sizeof("COOKIE=") - 1);

		if (conf->jwt_accessor.context.len == 0)
		{
			conf->jwt_accessor.context.data = (u_char *)"access_token";
			conf->jwt_accessor.context.len = sizeof("access_token") - 1;
		}
		else
		{
			conf->jwt_accessor.context.data = conf->validation_type.data + (sizeof("COOKIE=") - 1);
		}

		ngx_conf_log_error(NGX_LOG_DEBUG, cf, 0, "Serching for jwt in cookie '%s'", conf->jwt_accessor.context.data);
	}
	else if (conf->validation_type.len >= (sizeof("URL=") - 1) && ngx_strncmp(conf->validation_type.data, "URL=", (sizeof("URL=") - 1)) == 0)
	{
		conf->jwt_accessor.handler = get_jwt_from_url;
		conf->jwt_accessor.context.len = conf->validation_type.len - (sizeof("URL=") - 1);

		if (conf->jwt_accessor.context.len == 0)
		{
			conf->jwt_accessor.context.data = (u_char *)"access_token";
			conf->jwt_accessor.context.len = sizeof("access_token") - 1;
		}
		else
		{
			conf->jwt_accessor.context.data = conf->validation_type.data + (sizeof("URL=") - 1);
		}

		ngx_conf_log_error(NGX_LOG_DEBUG, cf, 0, "Serching for jwt in url param '%s'", conf->jwt_accessor.context.data);
	}
	else
	{
		ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "unsupported validation type");
		return NGX_CONF_ERROR;
	}

	return NGX_CONF_OK;
}

static char *ngx_http_auth_jwt_add_policy(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ngx_str_t *sAccessType;
	ngx_array_t **policies;
	ngx_array_t *users = NULL;
	ngx_array_t *roles = NULL;
	ngx_http_auth_jwt_policy_t *policy;
	ngx_http_auth_jwt_policy_access_type_t accessType;

	policies = (ngx_array_t **)((char *)conf + cmd->offset);

	if (*policies == NGX_CONF_UNSET_PTR)
	{
		*policies = ngx_array_create(cf->pool, 1, sizeof(ngx_http_auth_jwt_policy_t));
		if (*policies == NULL)
		{
			return NGX_CONF_ERROR;
		}
	}

	sAccessType = &((ngx_str_t *)cf->args->elts)[1];
	if (sAccessType->len == 0 || ngx_strcasecmp(sAccessType->data, (u_char *)"allow") == 0)
	{
		accessType = ACCESS_TYPE_ALLOW;
	}
	else if (ngx_strcasecmp(sAccessType->data, (u_char *)"deny") == 0)
	{
		accessType = ACCESS_TYPE_DENY;
	}
	else
	{
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
						   "invalid value \"%s\" in \"%s\" directive, "
						   "it must be \"allow\" or \"deny\"",
						   sAccessType->data, cmd->name.data);
		return NGX_CONF_ERROR;
	}

	users = ngx_array_create(cf->pool, 1, sizeof(ngx_str_t));
	if (users == NULL)
	{
		goto error;
	}

	if (ngx_str_split(&((ngx_str_t *)cf->args->elts)[2], users, ",") != NGX_OK)
	{
		goto error;
	}

	roles = ngx_array_create(cf->pool, 1, sizeof(ngx_str_t));
	if (roles == NULL)
	{
		goto error;
	}

	if (cf->args->nelts == 4)
	{
		if (ngx_str_split(&((ngx_str_t *)cf->args->elts)[3], roles, ",") != NGX_OK)
		{
			goto error;
		}
	}

	//Check for empty policy
	if (users->nelts == 0 && roles->nelts == 0)
	{
#if NGX_DEBUG
		ngx_conf_log_error(NGX_LOG_INFO, cf, 0, "found empty policy (%d)");
#endif

		ngx_array_destroy(users);
		ngx_array_destroy(roles);
		return NGX_CONF_OK;
	}

	policy = (ngx_http_auth_jwt_policy_t *)ngx_array_push(*policies);
	if (policy == NULL)
	{
		goto error;
	}

#if NGX_DEBUG
	size_t i;

	ngx_conf_log_error(NGX_LOG_INFO, cf, 0, "found valid policy (%d) for users (%d) and roles (%d)", accessType, users->nelts, roles->nelts);

	if (accessType == ACCESS_TYPE_ALLOW)
	{
		for (i = 0; i < users->nelts; i++)
		{
			ngx_conf_log_error(NGX_LOG_INFO, cf, 0, "users (%s) is allowed", ((ngx_str_t *)users->elts)[i].data);
		}

		for (i = 0; i < roles->nelts; i++)
		{
			ngx_conf_log_error(NGX_LOG_INFO, cf, 0, "role (%s) is allowed", ((ngx_str_t *)roles->elts)[i].data);
		}
	}
	else
	{
		for (i = 0; i < users->nelts; i++)
		{
			ngx_conf_log_error(NGX_LOG_INFO, cf, 0, "users (%s) is denied", ((ngx_str_t *)users->elts)[i].data);
		}

		for (i = 0; i < roles->nelts; i++)
		{
			ngx_conf_log_error(NGX_LOG_INFO, cf, 0, "role (%s) is denied", ((ngx_str_t *)roles->elts)[i].data);
		}
	}
#endif

	policy->access_type = accessType;
	policy->users = users;
	policy->roles = roles;
	return NGX_CONF_OK;

error:
	ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "an error occurred creating the policy");

	if (users != NULL)
	{
		ngx_array_destroy(users);
	}

	if (roles != NULL)
	{
		ngx_array_destroy(roles);
	}

	return NGX_CONF_ERROR;
}

static char *ngx_http_auth_jwt_add_grant_header_mapping(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ngx_str_t *grant;
	ngx_str_t *header;
	ngx_str_t *replace;
	ngx_array_t **mappings;
	ngx_http_auth_jwt_grant_mapping_t *mapping;

	mappings = (ngx_array_t **)((char *)conf + cmd->offset);

	if (*mappings == NGX_CONF_UNSET_PTR)
	{
		*mappings = ngx_array_create(cf->pool, 1, sizeof(ngx_http_auth_jwt_policy_t));
		if (*mappings == NULL)
		{
			return NGX_CONF_ERROR;
		}
	}

	grant = &((ngx_str_t *)cf->args->elts)[1];
	header = &((ngx_str_t *)cf->args->elts)[2];
	if (grant->len > 0 && header->len > 0)
	{
		mapping = (ngx_http_auth_jwt_grant_mapping_t *)ngx_array_push(*mappings);
		if (mapping == NULL)
		{
			return NGX_CONF_ERROR;
		}

		mapping->grant = *grant;
		mapping->header = *header;

		if (cf->args->nelts == 4)
		{
			replace = &((ngx_str_t *)cf->args->elts)[3];
			if (replace->len == 0)
			{
				mapping->replace = 1;
			}
			else if (ngx_strcasecmp(replace->data, (u_char *)"on") == 0)
			{
				mapping->replace = 1;
			}
			else if (ngx_strcasecmp(replace->data, (u_char *)"off") == 0)
			{
				mapping->replace = 0;
			}
			else
			{
				ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
								   "invalid value \"%s\" in \"%s\" directive, "
								   "it must be \"on\" or \"off\"",
								   replace->data, cmd->name.data);
				return NGX_CONF_ERROR;
			}
		}
		else
		{
			mapping->replace = 1;
		}

		ngx_conf_log_error(NGX_LOG_INFO, cf, 0, "found valid mapping for grant (%s) and header (%s)", grant->data, header->data);
	}

	return NGX_CONF_OK;
}

static char *get_jwt_from_header(ngx_http_request_t *r, ngx_str_t *context)
{
	ngx_table_elt_t *authorization_header;
	ngx_str_t jwt_http_value;

	// using authorization header
	authorization_header = search_headers_in(r, context);
	if (authorization_header != NULL && authorization_header->value.len > (sizeof("Bearer ") - 1))
	{
		jwt_http_value.data = authorization_header->value.data + (sizeof("Bearer ") - 1);
		jwt_http_value.len = authorization_header->value.len - (sizeof("Bearer ") - 1);

		return ngx_str_t_to_char_ptr(r->pool, jwt_http_value);
	}

	return NULL;
}

static char *get_jwt_from_cookie(ngx_http_request_t *r, ngx_str_t *context)
{
	ngx_str_t jwt_http_value;
	ngx_int_t n;

	// get the cookie
	n = ngx_http_parse_multi_header_lines(&r->headers_in.cookies, context, &jwt_http_value);
	if (n != NGX_DECLINED)
	{
		return ngx_str_t_to_char_ptr(r->pool, jwt_http_value);
	}

	return NULL;
}

static char *get_jwt_from_url(ngx_http_request_t *r, ngx_str_t *context)
{
	u_char *p, *equal, *amp, *last;

	if (r->args.len > context->len + 1)
	{
		p = (u_char *)ngx_strstr(r->args.data, context->data);
		if (p != NULL)
		{
			last = r->args.data + r->args.len;
			equal = ngx_strlchr(p + context->len, last, '=');
			if (equal != NULL)
			{
				amp = ngx_strlchr(++equal, last, '&');
				if (amp == NULL)
				{
					amp = last;
				}

				if (amp - equal > 0)
				{
					return ngx_uchar_to_char_ptr(r->pool, equal, amp - equal);
				}
			}
		}
	}

	return NULL;
}

static ngx_flag_t matches_jwt_policy(ngx_http_request_t *r, const char *user, const char *role, ngx_array_t *policies)
{
	size_t i;
	ngx_http_auth_jwt_policy_t *policy;

	if (role == NULL)
	{
#if NGX_DEBUG
		ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "validating policies against and role=%s", role);
#endif

		for (i = 0; i < policies->nelts; i++)
		{
			policy = &((ngx_http_auth_jwt_policy_t *)policies->elts)[i];

#if NGX_DEBUG
			ngx_log_policy(NGX_LOG_INFO, r->connection->log, 0, policy);
#endif

			if (policy->users->nelts > 0)
			{
				if (user == NULL || ngx_array_includes_insensitive(policy->users, user) == 0)
				{
					return 0;
				}
			}

			if (policy->roles->nelts == 0)
			{
				return 1;
			}
		}
	}
	else
	{
#if NGX_DEBUG
		ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "validating policies against user=%s and role=%s", user, role);
#endif

		for (i = 0; i < policies->nelts; i++)
		{
			policy = &((ngx_http_auth_jwt_policy_t *)policies->elts)[i];

#if NGX_DEBUG
			ngx_log_policy(NGX_LOG_INFO, r->connection->log, 0, policy);
#endif

			if (policy->users->nelts > 0)
			{
				if (user == NULL || ngx_array_includes_insensitive(policy->users, user) == 0)
				{
					return 0;
				}
			}

			if (policy->roles->nelts == 1 && ngx_strcasecmp(((ngx_str_t *)policy->roles->elts)[0].data, (u_char *)role) == 0)
			{
				return 1;
			}
		}
	}

	return 0;
}

static ngx_flag_t matches_jwt_policy_n(ngx_http_request_t *r, const char *user, json_t *json_roles, size_t json_roles_count, ngx_array_t *policies)
{
	ngx_flag_t result;
	size_t i, j;
	const char *role;
	ngx_http_auth_jwt_policy_t *policy;

	hashset_t hashset;
	hashset.nentries = 0;
	hashset.capacity = json_roles_count;

	if (json_roles_count > 1024)
	{
		hashset.buckets = (size_t *)ngx_palloc(r->pool, json_roles_count * sizeof(size_t));
		hashset.entries = (hashset_entry_t *)ngx_palloc(r->pool, json_roles_count * sizeof(hashset_entry_t));
	}
	else
	{
		hashset.buckets = (size_t *)alloca(json_roles_count * sizeof(size_t));
		hashset.entries = (hashset_entry_t *)alloca(json_roles_count * sizeof(hashset_entry_t));
	}

	ngx_memzero(hashset.buckets, json_roles_count * sizeof(size_t));
	ngx_memzero(hashset.entries, json_roles_count * sizeof(hashset_entry_t));

	for (i = 0; i < json_roles_count; i++)
	{
		role = json_string_value(json_array_get(json_roles, i));
		if (role == NULL)
		{
			continue;
		}

#if NGX_DEBUG
		if (user == NULL)
		{
			ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "validating policies against and role=%s", role);
		}
		else
		{
			ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "validating policies against user=%s and role=%s", user, role);
		}
#endif

		hashset_add(&hashset, role);
	}

	for (i = 0; i < policies->nelts;)
	{
		policy = &((ngx_http_auth_jwt_policy_t *)policies->elts)[i];

#if NGX_DEBUG
		ngx_log_policy(NGX_LOG_INFO, r->connection->log, 0, policy);
#endif

		if (policy->users->nelts > 0)
		{
			if (user == NULL || ngx_array_includes_insensitive(policy->users, user) == 0)
			{
				goto next_policy;
			}
		}

		if (policy->roles->nelts > json_roles_count)
		{
			goto next_policy;
		}

		for (j = 0; j < policy->roles->nelts;)
		{
			if (hashset_contains(&hashset, (const char *)((ngx_str_t *)policy->roles->elts)[j].data))
			{
				goto next_role;
			}

			goto next_policy;

		next_role:
			j++;
		}

		result = 1;
		goto exit;

	next_policy:
		i++;
	}

	result = 0;

exit:
	if (json_roles_count > 1024)
	{
		ngx_pfree(r->pool, hashset.buckets);
		ngx_pfree(r->pool, hashset.entries);
	}

	return result;
}

static ngx_flag_t validate_jwt_token_policies(ngx_http_request_t *r, jwt_t *jwt, ngx_http_auth_jwt_loc_conf_t *jwt_cf)
{
	const char *user;
	const char *token_roles;
	json_t *json_roles;
	json_error_t error;
	size_t json_roles_count;

	if (jwt_cf->policies == NULL || jwt_cf->policies->nelts == 0)
	{
		return 1;
	}

	user = jwt_get_grant(jwt, (const char *)jwt_cf->name_grant.data);
	token_roles = jwt_get_grants_json(jwt, (const char *)jwt_cf->role_grant.data);

	json_roles = json_loads(token_roles, JSON_DECODE_ANY | JSON_DISABLE_EOF_CHECK, &error);
	if (json_roles != NULL)
	{
		if (json_is_array(json_roles))
		{
			json_roles_count = json_array_size(json_roles);
			if (json_roles_count == 1)
			{
				if (matches_jwt_policy(r, user, json_string_value(json_array_get(json_roles, 0)), jwt_cf->policies))
				{
					goto success;
				}
			}
			else if (json_roles_count > 0)
			{
				if (matches_jwt_policy_n(r, user, json_roles, json_roles_count, jwt_cf->policies))
				{
					goto success;
				}
			}
		}
		else if (json_is_string(json_roles))
		{
			if (matches_jwt_policy(r, user, json_string_value(json_roles), jwt_cf->policies))
			{
				goto success;
			}
		}

		json_decref(json_roles);
	}
	else
	{
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "an error occurred validating authorization policies: %s", error.text);
	}

	return 0;

success:
	json_decref(json_roles);
	return 1;
}

static ngx_int_t ngx_http_auth_set_headers(ngx_http_request_t *r, jwt_t *jwt, ngx_http_auth_jwt_loc_conf_t *jwt_cf)
{
	const char *grant;
	ngx_str_t grant_t;
	size_t i;
	ngx_http_auth_jwt_grant_mapping_t *mapping;

	if (jwt_cf->grant_header_mappings == NULL || jwt_cf->grant_header_mappings->nelts == 0)
	{
		return 1;
	}

	for (i = 0; i < jwt_cf->grant_header_mappings->nelts; i++)
	{
		mapping = &((ngx_http_auth_jwt_grant_mapping_t *)jwt_cf->grant_header_mappings->elts)[i];

		grant = jwt_get_grant(jwt, (const char *)mapping->grant.data);
		if (grant == NULL)
		{
			continue;
		}

		grant_t = ngx_char_ptr_to_str_t(r->pool, (char *)grant);
		if (grant_t.data == NULL)
		{
			return 0;
		}

		if (set_custom_header_in_headers_out(r, &mapping->header, &grant_t) != NGX_OK)
		{
			return 0;
		}
	}

	return 1;
}