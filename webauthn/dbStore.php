<?php

use lbuchs\WebAuthn\Binary\ByteBuffer;

require_once 'api/Binary/ByteBuffer.php';
require_once 'db/config.php';
global $db, $usr_table, $creds_table;

function saveRegistration($token, $email, $displayName = null) {
  global $db, $usr_table;

  // Check if the user already exists
  $stmt = $db->prepare("SELECT * FROM {$usr_table} WHERE email = ?");
  $stmt->bind_param("s", $email);
  if (!$stmt->execute()) {
    // can't access the db
    throw new \Exception("Error checking registration: " . $stmt->error);

  } elseif ($stmt->get_result()->num_rows > 0) {
    // if user exists, update the token and displayName
    return updateRegistration($email, $token, $displayName);

  }

  // insert new user
  $stmt = $db->prepare("INSERT INTO {$usr_table} (token, email, displayName) VALUES (?, ?, ?)");
  $stmt->bind_param("sss", $token, $email, $displayName);
  if (!$stmt->execute()) {
    throw new \Exception("Error saving registration: " . $stmt->error);
  }

  return true;
}

function updateRegistration($email, $token, $displayName = null){
  global $db, $usr_table;

  // Check if the user exists
  $res = $db->query("SELECT id FROM $usr_table WHERE email = '$email'");
  if (!$res) {
    throw new \Exception("Error checking registration: " . $db->error);
  } elseif ($res->num_rows == 0) {
    throw new \Exception("No registration found for User: " . $email);
  }

  $sql = $displayName === null ?
    "UPDATE $usr_table SET token = '$token' WHERE email = '$email'" :
    "UPDATE $usr_table SET token = '$token', displayName = '$displayName' WHERE email = '$email'";

  // update the displayName
  $res = $db->query($sql);
  if (!$res) {
    throw new \Exception("Error updating registration: " . $db->error);
  }

  return true;
}


function getRegistrationFromDB($email) {
  global $db, $usr_table;

  $sql = "SELECT * FROM $usr_table WHERE email = '$email'";
  if ($res = $db->query($sql)) {
    if ($usr = $res->fetch_assoc()) {
      return $usr;

    } else {
      throw new \Exception("No registration found for User: " . $email);
    }
  }
}

function deleteRegistration($email) {
  global $db, $usr_table;

  $stmt = $db->prepare("DELETE FROM {$usr_table} WHERE email = ?");
  $stmt->bind_param("s", $email);
  if (!$stmt->execute()) {
    throw new \Exception("Error deleting registration: " . $stmt->error);
  }

  return $stmt->affected_rows > 0;
}

function saveCredential($email, $credential) {
  global $db, $creds_table, $usr_table;

  // Check if the user ID is valid
  $stmt = $db->prepare("SELECT id FROM {$usr_table} WHERE email = ?");
  $stmt->bind_param("s", $email);
  if (!$stmt->execute()) {

    throw new \Exception("Error fetching user: " . $stmt->error);
  } else {
    $row = $stmt->get_result()->fetch_assoc();
    $userId = $row['id'];

    if ($userId == null) {
      throw new \Exception("Unknown user, ID not found: " . $email);
    }
  }
  $stmt->close();

  $credId = base64_encode($credential->credentialId);
  $credAAGUID = base64_encode($credential->AAGUID);
  $credPublicKey = base64_encode($credential->credentialPublicKey) ?? null;

  // Insert new credential
  $stmt = $db->prepare(
    "INSERT INTO {$creds_table}
    (user_id, credentialId, publicKey, AAGUID) VALUES (?, ?, ?, ?)"
  );
  $stmt->bind_param("isss",
    $userId, $credId, $credPublicKey, $credAAGUID
  );
  if (!$stmt->execute()) {
    throw new \Exception("Error saving credential: " . $stmt->error);
  }

  return true;
}

function getCredentialsForUser($email) {
  global $db, $creds_table, $usr_table;

  $sql = "select c.*
          from {$creds_table} as c, {$usr_table} as u
          where c.user_id=u.id and u.email = ?";
  $stmt = $db->prepare($sql);
  $stmt->bind_param("s", $email);
  if (!$stmt->execute()) {
    throw new \Exception("Error fetching credential: " . $stmt->error);
  }

  $result = $stmt->get_result();
  if ($result->num_rows == 0) {
    throw new \Exception("No credential found for token: " . $email);
  }

  $creds = [];
  while ($row = $result->fetch_assoc()) {
    $cred['credentialId'] = base64_decode($row['credentialId']);
    $cred['AAGUID'] = base64_decode($row['AAGUID']);
    $cred['creationDate'] = strtotime($row['creationDate']);
    $cred['lastUpdatedDate'] = strtotime($row['lastUpdatedDate']);
    $cred['publicKey'] = base64_decode($row['publicKey']);
    $creds[] = $cred;
  }
  return $creds;
}

function deleteCredentialsForUser($email) {
  global $db, $creds_table, $usr_table;

  $sql = "delete c.* from $creds_table as c, $usr_table as u
          where c.user_id=u.id and u.email='$email'";
  if (!$res = $db->query($sql)) {
    throw new \Exception("Error deleting credentials for User {$email}: " . $db->error);
  }
  return true;
}

function getAllCredentials() {
  global $db, $creds_table, $usr_table;

  $sql = "SELECT u.*, c.* FROM $creds_table as c, $usr_table as u
          WHERE c.user_id = u.id
          ORDER BY u.email, c.creationDate DESC";
  if ($res = $db->query($sql)) {
    $rows = [];
    while ($row = $res->fetch_assoc()) {
      $row['credentialId'] = base64_decode($row['credentialId']);
      $row['AAGUID'] = base64_decode($row['AAGUID']);
      $row['publicKey'] = base64_decode($row['publicKey']);
      $rows[] = $row;
    }
    return $rows;
  } else {
    throw new \Exception("Error fetching all credentials: " . $db->error);
  }
}
