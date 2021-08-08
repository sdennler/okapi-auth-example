<?php

declare(strict_types=1);
error_reporting(E_ALL); // & ~E_NOTICE
ini_set('display_errors', 'On');

require_once __DIR__.'/vendor/autoload.php';

use OkapiAuth\Okapi;

// Start session
session_start();
#header('Content-Type: text/plain');

// Prepare config
$configs = require __DIR__.'/config.php';
$config = false;
$server = false;

if (isset($_GET['oc_server']) && isset($configs[$_GET['oc_server']])) {
    $_SESSION['oc_server'] = $_GET['oc_server'];
    $config = $configs[$_GET['oc_server']];
}
elseif (isset($_SESSION['oc_server'])) {
    $config = $configs[$_SESSION['oc_server']];
}

if ($config) {
    $config['callback_uri'] = 'https://' . $_SERVER['SERVER_NAME'] . $_SERVER['SCRIPT_NAME'];
    // Create server
    $server = new Okapi($config);
}

// Step 4
if (isset($_GET['user']) && $server) {

    // Check somebody hasn't manually entered this URL in,
    // by checking that we have the token credentials in
    // the session.
    if ( ! isset($_SESSION['token_credentials'])) {
        echo 'No token credentials.';
        exit(1);
    }

    // Retrieve our token credentials. From here, it's play time!
    $tokenCredentials = unserialize($_SESSION['token_credentials']);

    // // Below is an example of retrieving the identifier & secret
    // // (formally known as access token key & secret in earlier
    // // OAuth 1.0 specs).
    // $identifier = $tokenCredentials->getIdentifier();
    // $secret = $tokenCredentials->getSecret();

    // Authenticated! Welcome the user
    echo '<p>Welcome '.$server->getUserScreenName($tokenCredentials).' @ '.$_SESSION['oc_server'].'</p>';

    // This does a second call to the OKAPI! Do only this or the above line.
    $user = $server->getUserDetails($tokenCredentials);
    echo "\n<p>Details:</p><pre>";
    var_dump($user);
    echo "</pre>\n";

// Step 3
} elseif (isset($_GET['oauth_token']) && isset($_GET['oauth_verifier']) && $server) {

    // Retrieve the temporary credentials from step 2
    $temporaryCredentials = unserialize($_SESSION['temporary_credentials']);

    // Third and final part to OAuth 1.0 authentication is to retrieve token
    // credentials (formally known as access tokens in earlier OAuth 1.0
    // specs).
    $tokenCredentials = $server->getTokenCredentials($temporaryCredentials, $_GET['oauth_token'], $_GET['oauth_verifier']);

    // Now, we'll store the token credentials and discard the temporary
    // ones - they're irrelevant at this stage.
    unset($_SESSION['temporary_credentials']);
    $_SESSION['token_credentials'] = serialize($tokenCredentials);
    session_write_close();

    // Redirect to the user page
    header("Location: ${config['callback_uri']}/?user=user");
    exit;

// Step 2
} elseif (isset($_GET['go']) && $server) {

    // First part of OAuth 1.0 authentication is retrieving temporary credentials.
    // These identify you as a client to the server.
    $temporaryCredentials = $server->getTemporaryCredentials();

    // Store the credentials in the session.
    $_SESSION['temporary_credentials'] = serialize($temporaryCredentials);
    session_write_close();

    // Second part of OAuth 1.0 authentication is to redirect the
    // resource owner to the login screen on the server.
    $server->authorize($temporaryCredentials);

// Step 1
} else {

    // Display links to start process
    foreach ($configs as $server => $config) {
        echo "<p><a href=\"?go=go&oc_server=$server\">Login with $server</a></p>";
    }
}
