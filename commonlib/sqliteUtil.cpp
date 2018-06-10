// ---------------------------- Database Helpers ------------------------------------
#include "sqliteUtil.h"

std::mutex sql_mutex;
sqlite3 *database;

bool sqlite_get_user_salt(sqlite3 *db, char *username, char **salt_string)
{
	char prepared_sql[] = "SELECT salt FROM users WHERE username = ?;";

	sqlite3_stmt *stmt = NULL;

	sql_mutex.lock();
	int rc = sqlite3_prepare_v2(db, prepared_sql, -1, &stmt, NULL);
	if (rc != SQLITE_OK) {
		LOG_ERROR("sqlite_get_user_salt: prepare error!\n");
		sql_mutex.unlock();
		return false;
	}

	if(sqlite3_bind_text(stmt, 1, username, strlen(username), SQLITE_STATIC))
	{
		LOG_ERROR("sqlite_get_user_salt: prepare error!\n");
		sql_mutex.unlock();
		return false;
	}

	rc = sqlite3_step(stmt);
	if(rc != SQLITE_ROW)
	{
		if(rc == SQLITE_DONE)
			LOG_ERROR("sqlite_get_user_salt: empty result!\n");
		else
			LOG_ERROR("sqlite_get_user_salt: step error!\n");

		sql_mutex.unlock();
		return false;
	}
	char *result_string = (char *)sqlite3_column_text(stmt, 0);
	*salt_string = new char[strlen(result_string)+1];
	strcpy(*salt_string, result_string);

	rc = sqlite3_finalize(stmt);
	sql_mutex.unlock();

	return true;
}

bool sqlite_check_password(sqlite3 *db, char *username, char *hashed_password)
{
	char prepared_sql[] = "SELECT COUNT(*) FROM users WHERE username = ? AND password = ?;";

	sqlite3_stmt *stmt = NULL;
	
	sql_mutex.lock();
	int rc = sqlite3_prepare_v2(db, prepared_sql, -1, &stmt, NULL);
	if (rc != SQLITE_OK) {
		LOG_ERROR("sqlite_check_password: prepare error!\n");
		sql_mutex.unlock();
		return false;
	}

	if( sqlite3_bind_text(stmt, 1, username, strlen(username), SQLITE_STATIC) ||
		sqlite3_bind_text(stmt, 2, hashed_password, strlen(hashed_password), SQLITE_STATIC))
	{
		LOG_ERROR("sqlite_check_password: prepare error!\n");
		sql_mutex.unlock();
		return false;
	}

	rc = sqlite3_step(stmt);
	// int colCount = sqlite3_column_count(stmt);
	// int type = sqlite3_column_type(stmt, 0);
	int valInt = sqlite3_column_int(stmt, 0);

	rc = sqlite3_finalize(stmt);
	sql_mutex.unlock();

	return valInt;
}

bool open_database(sqlite3 **db, const char *database_path) {
	int rc = sqlite3_open(database_path, db);
	if(rc) {
		LOG_ERROR("Can't open database: %s\n", sqlite3_errmsg(*db));
		sqlite3_close(*db);
		return false;
	}

	return true;
}
// ----------------------------------------------------------------------------------
