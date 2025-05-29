<?php

header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Headers: *");
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
header('Access-Control-Allow-Credentials: true');
mb_internal_encoding("UTF-8");
date_default_timezone_set('CET');

/*
 * Copyright (C) 2022 Lukas Buchs
 * license https://github.com/lbuchs/WebAuthn/blob/master/LICENSE MIT
 *
 * Server test script for WebAuthn library. Saves new registrations in a database.
 *
 *            JAVASCRIPT            |          SERVER
 * ------------------------------------------------------------
 *
 *               REGISTRATION
 *
 *      window.fetch  ----------------->     getCreateArgs
 *                                                |
 *   navigator.credentials.create   <-------- challenge
 *           |
 *       encr chlg -------------------->     processCreate
 *                                                |
 *         alert ok or fail      <----------------'
 *
 * ------------------------------------------------------------
 *
 *              VALIDATION
 *
 *      window.fetch ------------------>      getGetArgs
 *                                                |
 *   navigator.credentials.get   <----------- challenge
 *           |
 *           encr chlg ---------------->      processGet
 *                                                |
 *         alert ok or fail      <----------------'
 *
 * ------------------------------------------------------------
 */

require_once 'api/WebAuthn.php';
require_once 'api/Binary/ByteBuffer.php';
require_once 'db/config.php';
require_once 'dbStore.php';

define ('CHALLENGE_STORE', 'challengeStore');

try {
    global $db;

    if(!is_dir(CHALLENGE_STORE)) {
        mkdir(CHALLENGE_STORE, 0777, true);
    }

    // read get argument and post body
    $fn = filter_input(INPUT_GET, 'fn');
    $requireResidentKey = !!filter_input(INPUT_GET, 'requireResidentKey');
    $userVerification = filter_input(INPUT_GET, 'userVerification', FILTER_SANITIZE_SPECIAL_CHARS);

    $userId = filter_input(INPUT_GET, 'userId', FILTER_SANITIZE_SPECIAL_CHARS);
    $userId = $userId ? preg_replace('/[^0-9a-f]/i', '', $userId): "";
    $userHandle = $userId;
    if ($userId === false) {
        throw new \Exception('The request must include user token (userId) as a hex string.');
    }

    $userName = filter_input(INPUT_GET, 'userName', FILTER_SANITIZE_SPECIAL_CHARS);
    $userDisplayName = filter_input(INPUT_GET, 'userDisplayName', FILTER_SANITIZE_SPECIAL_CHARS);

    $userName = $userName ? preg_replace('/[^0-9a-z\.\@]/i', '', $userName): "";
    $userDisplayName = $userDisplayName ? preg_replace('/[^0-9a-z öüäéèàÖÜÄÉÈÀÂÊÎÔÛâêîôû]/i', '', $userDisplayName): "";

    $post = trim(file_get_contents('php://input'));
    if ($post) {
        $post = json_decode($post, null, 512, JSON_THROW_ON_ERROR);
    }

    if ($fn !== 'getStoredDataHtml' && $fn !== 'getStoredDataJson' && $fn !== 'queryFidoMetaDataService') {

        // Formats
        $formats = [];
        if (filter_input(INPUT_GET, 'fmt_android-key')) {
            $formats[] = 'android-key';
        }
        if (filter_input(INPUT_GET, 'fmt_android-safetynet')) {
            $formats[] = 'android-safetynet';
        }
        if (filter_input(INPUT_GET, 'fmt_apple')) {
            $formats[] = 'apple';
        }
        if (filter_input(INPUT_GET, 'fmt_fido-u2f')) {
            $formats[] = 'fido-u2f';
        }
        if (filter_input(INPUT_GET, 'fmt_none')) {
            $formats[] = 'none';
        }
        if (filter_input(INPUT_GET, 'fmt_packed')) {
            $formats[] = 'packed';
        }
        if (filter_input(INPUT_GET, 'fmt_tpm')) {
            $formats[] = 'tpm';
        }

        $rpId = 'localhost';
        if (filter_input(INPUT_GET, 'rpId')) {
            $rpId = filter_input(INPUT_GET, 'rpId', FILTER_VALIDATE_DOMAIN);
            if ($rpId === false) {
                throw new \Exception('invalid relying party ID, must a valid domain name');
            }
        }

        // types selected on front end
        $typeUsb = !!filter_input(INPUT_GET, 'type_usb');
        $typeNfc = !!filter_input(INPUT_GET, 'type_nfc');
        $typeBle = !!filter_input(INPUT_GET, 'type_ble');
        $typeInt = !!filter_input(INPUT_GET, 'type_int');
        $typeHyb = !!filter_input(INPUT_GET, 'type_hybrid');

        // cross-platform: true, if type internal is not allowed
        //                 false, if only internal is allowed
        //                 null, if internal and cross-platform is allowed
        $crossPlatformAttachment = null;
        if (($typeUsb || $typeNfc || $typeBle || $typeHyb) && !$typeInt) {
            $crossPlatformAttachment = true;

        } else if (!$typeUsb && !$typeNfc && !$typeBle && !$typeHyb && $typeInt) {
            $crossPlatformAttachment = false;
        }


        // new Instance of the server library.
        // make sure that $rpId is the domain name.
        $WebAuthn = new lbuchs\WebAuthn\WebAuthn('WebAuthn Library', $rpId, $formats);

        // add root certificates to validate new registrations
        if (filter_input(INPUT_GET, 'solo')) {
            $WebAuthn->addRootCertificates('rootCertificates/solo.pem');
            $WebAuthn->addRootCertificates('rootCertificates/solokey_f1.pem');
            $WebAuthn->addRootCertificates('rootCertificates/solokey_r1.pem');
        }
        if (filter_input(INPUT_GET, 'apple')) {
            $WebAuthn->addRootCertificates('rootCertificates/apple.pem');
        }
        if (filter_input(INPUT_GET, 'yubico')) {
            $WebAuthn->addRootCertificates('rootCertificates/yubico.pem');
        }
        if (filter_input(INPUT_GET, 'hypersecu')) {
            $WebAuthn->addRootCertificates('rootCertificates/hypersecu.pem');
        }
        if (filter_input(INPUT_GET, 'google')) {
            $WebAuthn->addRootCertificates('rootCertificates/globalSign.pem');
            $WebAuthn->addRootCertificates('rootCertificates/googleHardware.pem');
        }
        if (filter_input(INPUT_GET, 'microsoft')) {
            $WebAuthn->addRootCertificates('rootCertificates/microsoftTpmCollection.pem');
        }
        if (filter_input(INPUT_GET, 'mds')) {
            $WebAuthn->addRootCertificates('rootCertificates/mds');
        }

    }

    // ------------------------------------
    // request for create arguments: first step in registration
    // ------------------------------------

    if ($fn === 'getCreateArgs') {
        $createArgs = $WebAuthn->getCreateArgs(
            \hex2bin($userHandle),
            $userName,
            $userDisplayName,
            60*4,
            $requireResidentKey,
            $userVerification,
            $crossPlatformAttachment);

        header('Content-Type: application/json');
        print(json_encode($createArgs));

        // the challenge is temporal, save it in a file
        // we have to deliver it to processGet later.
        $challenge = $WebAuthn->getChallenge();
        storeChallenge($userId, $challenge);

        // save the user details in the db for later valifation
        saveRegistration($userHandle, $userName, $userDisplayName);


        // ------------------------------------
        // process create: second step in registration
        // ------------------------------------

    } else if ($fn === 'processCreate') {

        $clientDataJSON = !empty($post->clientDataJSON) ? base64_decode($post->clientDataJSON) : null;
        $attestationObject = !empty($post->attestationObject) ? base64_decode($post->attestationObject) : null;

        // get the challenge generated in getCreateArgs
        // from the store associated to the userId;
        $challenge = retrieveChallenge($userId);

        // processCreate returns data to be stored for future logins.
        // we store the data in a database connected
        // with the username.
        $data = $WebAuthn->processCreate($clientDataJSON, $attestationObject, $challenge, $userVerification === 'required', true, false);

        // structure of $data object:
        // $data = new \stdClass();
        // $data->rpId = $this->_rpId;
        // $data->attestationFormat = $attestationObject->getAttestationFormatName();
        // $data->credentialId = $attestationObject->getAuthenticatorData()->getCredentialId();
        // $data->credentialPublicKey = $attestationObject->getAuthenticatorData()->getPublicKeyPem();
        // $data->certificateChain = $attestationObject->getCertificateChain();
        // $data->certificate = $attestationObject->getCertificatePem();
        // $data->certificateIssuer = $attestationObject->getCertificateIssuer();
        // $data->certificateSubject = $attestationObject->getCertificateSubject();
        // $data->signatureCounter = $this->_signatureCounter;
        // $data->AAGUID = $attestationObject->getAuthenticatorData()->getAAGUID();
        // $data->rootValid = $rootValid;
        // $data->userPresent = $userPresent;
        // $data->userVerified = $userVerified;
        // $data->isBackupEligible = $attestationObject->getAuthenticatorData()->getIsBackupEligible();
        // $data->isBackedUp = $attestationObject->getAuthenticatorData()->getIsBackup();

        // add user infos
        $data->userId = $userId;
        $data->userName = $userName;
        $data->userDisplayName = $userDisplayName;

        // save credential data in database
        saveCredential($userName, $data);

        $msg = 'registration success.';

        $return = new stdClass();
        $return->success = true;
        $return->msg = $msg;

        header('Content-Type: application/json');
        print(json_encode($return));


        // ------------------------------------
        // request for get arguments: first step in validation (login)
        // ------------------------------------

    } else if ($fn === 'getGetArgs') {
        $ids = [];

        // load the credential Id's for a username
        // from the database created by processCreate
        $credIds = [];
        $creds = getCredentialsForUser($userName) ?? [];
        foreach ($creds as $cred) {
            $credIds[] = $cred['credentialId'];
        }
        if (count($credIds) === 0) {
            throw new Exception("No credentials found for User $userName, please register first!");
        }

        $getArgs = $WebAuthn->getGetArgs($credIds, 60*4, $typeUsb, $typeNfc, $typeBle, $typeHyb, $typeInt, $userVerification);

        header('Content-Type: application/json');
        print(json_encode($getArgs));

        // the challenge is temporal, save it in a file
        // we have to deliver it to processGet later.
        $challenge = $WebAuthn->getChallenge();
        storeChallenge($userId, $challenge);


    // ------------------------------------
    // proccess get: second step in validation (login)
    // ------------------------------------

    } else if ($fn === 'processGet') {
        $clientDataJSON = !empty($post->clientDataJSON) ? base64_decode($post->clientDataJSON) : null;
        $authenticatorData = !empty($post->authenticatorData) ? base64_decode($post->authenticatorData) : null;
        $signature = !empty($post->signature) ? base64_decode($post->signature) : null;
        $userHandle = !empty($post->userHandle) ? base64_decode($post->userHandle) : null;
        $id = !empty($post->id) ? base64_decode($post->id) : null;
        $credentialPublicKey = null;

        // get the challenge generated in getCreateArgs
        // from the store associated to the userId;
        $challenge = retrieveChallenge($userId);

        // look up correspondending public key of the credential id
        // for the given user.
        $creds = getCredentialsForUser($userName) ?? [];
        foreach($creds as $cred) {
            if ($cred['credentialId'] === $id) {
                $credentialPublicKey = $cred['publicKey'];
                break;
            }
        }

        if ($credentialPublicKey === null) {
            throw new Exception('Credential info missing (Public Key). Please register again.');
        }

        // if we have resident key, we have to verify that the userHandle is the provided userId at registration
        if ($requireResidentKey && $userHandle !== hex2bin($reg->userId)) {
            throw new \Exception('userId doesnt match (is ' . bin2hex($userHandle) . ' but expect ' . $reg->userId . ')');
        }

        // process the get request. throws WebAuthnException if it fails
        $WebAuthn->processGet($clientDataJSON, $authenticatorData, $signature, $credentialPublicKey, $challenge, null, $userVerification === 'required');

        $return = new stdClass();
        $return->success = true;

        header('Content-Type: application/json');
        print(json_encode($return));

    // ------------------------------------
    // proccess clear registrations
    // ------------------------------------

    } else if ($fn === 'clearRegistrations') {
        $_SESSION['registrations'] = null;
        $_SESSION['challenge'] = null;

        deleteCredentialsForUser($userName);

        $return = new stdClass();
        $return->success = true;
        $return->msg = 'all registrations deleted';

        header('Content-Type: application/json');
        print(json_encode($return));


        // ------------------------------------
        // display stored data as JSON
        // ------------------------------------

    } else if ($fn === 'getStoredDataJson') {
        $regs = getAllCredentials();

        if (count($regs) > 0) {
            foreach ($regs as $idx => $reg) {
                foreach ($reg as $key => $value) {

                    if (is_bool($value)) {
                        $value = $value ? 'yes' : 'no';
                    } elseif (is_null($value)) {
                        $value = 'null';
                    } elseif (is_object($value)) {
                        $value = chunk_split(strval($value), 64);
                    } elseif (is_string($value) && strlen($value) > 0 && htmlspecialchars($value, ENT_QUOTES) === '') {
                        $value = bin2hex($value);
                    } elseif ($key === 'credentialId' || $key === 'AAGUID') {
                        // convert binary to base64
                        $value = base64_encode($value);
                    }

                    $reg[$key] = $value;
                    $regs[$idx] = $reg;
                }
            }
        } else {
            $regs = [];
        }

        header('Content-Type: application/json');
        print json_encode($regs);

    // ------------------------------------
    // display stored data as HTML
    // ------------------------------------

    } else if ($fn === 'getStoredDataHtml') {
        $html = '<!DOCTYPE html>' . "\n";
        $html .= '<html><head><style>tr:nth-child(even){background-color: #f2f2f2;}</style></head>';
        $html .= '<body style="font-family:sans-serif">';
        if (isset($_SESSION['registrations']) && is_array($_SESSION['registrations'])) {
            $regs = getAllCredentials();
            $html .= '<p>There are ' . count($regs) . ' registrations in the db:</p>';
            foreach ($regs as $reg) {
                $html .= '<table style="border:1px solid black;margin:10px 0;">';
                foreach ($reg as $key => $value) {

                    if (is_bool($value)) {
                        $value = $value ? 'yes' : 'no';

                    } else if (is_null($value)) {
                        $value = 'null';

                    } else if (is_object($value)) {
                        $value = chunk_split(strval($value), 64);

                    } else if (is_string($value) && strlen($value) > 0 && htmlspecialchars($value, ENT_QUOTES) === '') {
                        $value = chunk_split(bin2hex($value), 64);
                    }
                    $html .= '<tr><td>' . htmlspecialchars($key) . '</td><td style="font-family:monospace;">' . nl2br(htmlspecialchars($value)) . '</td>';
                }
                $html .= '</table>';
            }
        } else {
            $html .= '<p>There are no registrations in the database.</p>';
        }
        $html .= '</body></html>';

        header('Content-Type: text/html');
        print $html;

    // ------------------------------------
    // get root certs from FIDO Alliance Metadata Service
    // ------------------------------------

    } else if ($fn === 'queryFidoMetaDataService') {

        $mdsFolder = 'rootCertificates/mds';
        $success = false;
        $msg = null;

        // fetch only 1x / 24h
        $lastFetch = \is_file($mdsFolder .  '/lastMdsFetch.txt') ? \strtotime(\file_get_contents($mdsFolder .  '/lastMdsFetch.txt')) : 0;
        if ($lastFetch + (3600*48) < \time()) {
            $cnt = $WebAuthn->queryFidoMetaDataService($mdsFolder);
            $success = true;
            \file_put_contents($mdsFolder .  '/lastMdsFetch.txt', date('r'));
            $msg = 'successfully queried FIDO Alliance Metadata Service - ' . $cnt . ' certificates downloaded.';

        } else {
            $msg = 'Fail: last fetch was at ' . date('r', $lastFetch) . ' - fetch only 1x every 48h';
        }

        $return = new stdClass();
        $return->success = $success;
        $return->msg = $msg;

        header('Content-Type: application/json');
        print(json_encode($return));
    }

} catch (Throwable $ex) {
    $return = new stdClass();
    $return->success = false;
    $return->msg = $ex->getMessage();

    header('Content-Type: application/json');
    print(json_encode($return));
}

function storeChallenge($userId, $challenge) {
    $file = CHALLENGE_STORE . '/' . $userId . '.challenge';
    if (is_file($file)) {
        unlink($file);
    }
    file_put_contents($file, $challenge->getHex());
}

function retrieveChallenge($userId) {
    $file = CHALLENGE_STORE . '/' . $userId . '.challenge';
    if (is_file($file)) {
        $data = file_get_contents($file);
        return \lbuchs\WebAuthn\Binary\ByteBuffer::fromHex($data);
    }
    return null;
}