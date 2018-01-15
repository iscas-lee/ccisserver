#include "configure.h"
GKeyFile*	keyFile	= NULL;

gchar *get_string_accord_group_key(GKeyFile *keyfile, const char *conf_file, const char *group, const char *key)
{
	GError *error = NULL;
	GKeyFileFlags flags;
	flags = G_KEY_FILE_KEEP_COMMENTS | G_KEY_FILE_KEEP_TRANSLATIONS;
	gchar *value = NULL;

	if (!g_key_file_load_from_file(keyfile, conf_file, flags, &error)) {
		g_error("%s", error->message);
		g_error_free(error);
		error = NULL;
		return NULL;
	}
	if (g_key_file_has_group(keyfile, group)) {
		value = g_strdup(g_key_file_get_string(keyfile, group, key, NULL));  
	}

	if (error) {
		g_error_free(error);
		error = NULL;
	}

	return value;
}

int get_int_accord_group_key(GKeyFile *keyfile, const char *conf_file, const char *group, const char *key)
{
	GError *error = NULL;
	GKeyFileFlags flags;
	flags = G_KEY_FILE_KEEP_COMMENTS | G_KEY_FILE_KEEP_TRANSLATIONS;
	int value = -1;

	if (!g_key_file_load_from_file(keyfile, conf_file, flags, &error)) {
		g_error("%s", error->message);
		g_error_free(error);
		error = NULL;
		return value;
	}

	if (g_key_file_has_group(keyfile, group)) {
		value = g_key_file_get_integer(keyfile, group, key, NULL);  
	}

	if (error) {
		g_error_free(error);
		error = NULL;
	}
	return value;
}
