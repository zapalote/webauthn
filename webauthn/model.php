<?php
header('Content-Type: text/plain');

// Connect to the database
require_once 'db/config.php';
global $db, $usr_table, $creds_table;

// webauthn users
$sql = "
CREATE TABLE IF NOT EXISTS `{$usr_table}` (
 id INT NOT NULL AUTO_INCREMENT,
 email NVARCHAR(100) NOT NULL UNIQUE,
 displayName NVARCHAR(200),
 token NVARCHAR(200),
 registrationDate DATETIME DEFAULT CURRENT_TIMESTAMP,
 lastUpdatedDate DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
 PRIMARY KEY (id)
) ENGINE=MyISAM DEFAULT CHARSET=utf8mb3;";

if ($db->query($sql)) {
  echo "{$usr_table} table created.....\n";
} else {
  echo "Error defining {$usr_table} table: {$db->error}\n";
}

// Webauthn credentials
// -- AAGUID is the unique identifier for the authenticator

$sql = "
CREATE TABLE IF NOT EXISTS `{$creds_table}` (
  id INT NOT NULL AUTO_INCREMENT,
  user_id INT NOT NULL,
  credentialId NVARCHAR(1023),
  publicKey TEXT,
  AAGUID NVARCHAR(200),
  creationDate DATETIME DEFAULT CURRENT_TIMESTAMP,
  lastUpdatedDate DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  FOREIGN KEY (user_id)
  REFERENCES {$usr_table}(id)
  ON DELETE CASCADE
) ENGINE=MyISAM DEFAULT CHARSET=utf8mb3;";

if ($db->query($sql)) {
  echo "{$creds_table} table created.....\n";
} else {
  echo "Error defining {$creds_table} table: {$db->error}\n";
}
// Close the database connection
$db->close();
