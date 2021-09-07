/*
 * Copyright (C) 2018 Tesla Government
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 *
 * https://github.com/TeslaGov/ngx-http-auth-jwt-module
 */
#include <ngx_core.h>

#include "ngx_http_auth_jwt_string.h"

/** copies an nginx string structure to a newly allocated character pointer */
char *ngx_str_t_to_char_ptr(ngx_pool_t *pool, ngx_str_t str)
{
	char *char_ptr = ngx_palloc(pool, str.len + 1);
	ngx_memcpy(char_ptr, str.data, str.len);
	*(char_ptr + str.len) = '\0';
	return char_ptr;
}

char *ngx_uchar_to_char_ptr(ngx_pool_t *pool, u_char *str, size_t len)
{
	char *char_ptr = ngx_palloc(pool, len + 1);
	ngx_memcpy(char_ptr, str, len);
	*(char_ptr + len) = '\0';
	return char_ptr;
}

/** copies a character pointer string to an nginx string structure */
ngx_str_t ngx_char_ptr_to_str_t(ngx_pool_t *pool, char *char_ptr)
{
	size_t len = ngx_strlen(char_ptr);

	ngx_str_t str_t;
	str_t.data = ngx_palloc(pool, len);
	ngx_memcpy(str_t.data, char_ptr, len);
	str_t.len = len;
	return str_t;
}

ngx_flag_t ngx_array_includes(ngx_array_t *array, const char *value)
{
	size_t i;
	ngx_str_t *entry;

	for (i = 0; i < array->nelts; i++)
	{
		entry = &((ngx_str_t *)array->elts)[i];

		if (ngx_strcmp((u_char *)entry->data, (u_char *)value) == 0)
		{
			return 1;
		}
	}

	return 0;
}

ngx_flag_t ngx_array_includes_insensitive(ngx_array_t *array, const char *value)
{
	size_t i;
	ngx_str_t *entry;

	for (i = 0; i < array->nelts; i++)
	{
		entry = &((ngx_str_t *)array->elts)[i];

		if (ngx_strcasecmp((u_char *)entry->data, (u_char *)value) == 0)
		{
			return 1;
		}
	}

	return 0;
}

size_t trim(char **value, char *next)
{
	size_t len;
	char *start;
	char *end;

	start = *value;
	if (next == NULL)
	{
		len = strlen(start);
	}
	else
	{
		len = next - start;
	}

	if (len == 0)
	{
		return 0;
	}

	while (isspace(*start))
	{
		start++;
		len--;
	}

	end = start + len;
	while (end > start && isspace(*end))
	{
		end--;
		len--;
	}

	end[1] = '\0';
	*value = start;
	return len;
}

ngx_int_t ngx_str_split(ngx_str_t *value, ngx_array_t *result, const char *separator)
{
	size_t len;
	ngx_str_t *entry;
	char *nextToken;
	char *token = (char *)value->data;
	size_t separatorLen = strlen(separator);

	if (value->len > 0)
	{
		if (separatorLen == 0)
		{
			entry = (ngx_str_t *)ngx_array_push(result);
			if (entry == NULL)
			{
				return NGX_ERROR;
			}

			*entry = *value;
		}

		do
		{
			nextToken = ngx_strstr(token, separator);
			len = trim(&token, nextToken);

			if (len > 0)
			{
				entry = (ngx_str_t *)ngx_array_push(result);
				if (entry == NULL)
				{
					return NGX_ERROR;
				}

				entry->len = len;
				entry->data = (u_char *)token;
			}

			token = nextToken + separatorLen;
		} while (nextToken != NULL);
	}

	return NGX_OK;
}

ngx_int_t ngx_str_join(ngx_array_t *value, ngx_str_t *result, const char *separator)
{
	size_t i;
	ngx_str_t *element;
	size_t offset = 0;
	size_t separatorLen = ngx_strlen(separator);

	if (result->len > 0)
	{
		for (i = 0; i < value->nelts; i++)
		{
			element = &((ngx_str_t *)value->elts)[i];

			if (offset + element->len + separatorLen >= result->len)
			{
				break;
			}

			offset += element->len;
			ngx_memcpy(result->data + offset, separator, separatorLen);
			offset += separatorLen;
		}

		if (offset > separatorLen)
		{
			result->data[offset - separatorLen] = '\0';
		}
		else
		{
			result->data[0] = '\0';
		}
	}

	return NGX_OK;
}