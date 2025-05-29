<?php
mb_internal_encoding("UTF-8");
date_default_timezone_set("Europe/Amsterdam");
setlocale(LC_TIME, 'en_NL');

// App wide constants, these will get overwritten
define('CAL_DB_DEV_INI', "../../private/webauthn.ini");
define('CAL_DB_PROD_INI', "../../../webauthn.ini");

// Don't change beyond here
define('WAUTHN_LOCK', true);
define('NOK', '{"status": "nok"}');
define('OK', '{"status": "ok"}');

// Backup config
define('BCK_DIR', '../../backup');
define('PASS_KEY', '977824rhgd9');

// Connect to the database
require_once 'db/db.php';
$db = db_connect();
$usr_table = 'webauthn_users';
$creds_table = 'webauthn_credentials';

function deriveDay($d) {
  // return human friendly date string
  $now = time();
  if (gettype($d) == "string") $d = strtotime($d);

  $dayString = date("Y-m-d H:i:s", $d);
  if ($now - $d < 86400) {
    $dayString = "today " . date("l", $d);
  }
  if ($now - $d < 86400 * 2) {
    $dayString = "yesterday " . date("l", $d);
  }
  if ($now - $d < 86400 * 7) {
    $dayString = date("l, j F", $d);
  }
  return $dayString;
}