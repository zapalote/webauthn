<?php
mb_internal_encoding("UTF-8");
date_default_timezone_set("Europe/Amsterdam");
setlocale(LC_TIME, 'en_NL');

// App wide constants, these will get overwritten
define('WEBAUTHN_DB_DEV_INI', "../../private/webauthn.ini");
define('WEBAUTHN_DB_PROD_INI', "../../../webauthn.ini");

// Don't change beyond here
define('WAUTHN_LOCK', true);
define('NOK', '{"status": "nok"}');
define('OK', '{"status": "ok"}');

// Connect to the database
require_once 'db/db.php';
$db = db_connect();
$usr_table = 'webauthn_users';
$creds_table = 'webauthn_credentials';
