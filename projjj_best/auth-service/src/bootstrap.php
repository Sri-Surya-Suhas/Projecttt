<?php
/**
 * Secure application bootstrap
 * - Reverse proxy HTTPS awareness
 * - Secure session handling
 * - Session timeout enforcement
 */

/* Trust HTTPS from NGINX */
if (
    isset($_SERVER['HTTP_X_FORWARDED_PROTO']) &&
    $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https'
) {
    $_SERVER['HTTPS'] = 'on';
}

/* Secure session configuration */
ini_set('session.cookie_secure', '1');
ini_set('session.cookie_httponly', '1');
ini_set('session.cookie_samesite', 'Strict');
ini_set('session.use_strict_mode', '1');

/* Session limits */
define('SESSION_IDLE_TIMEOUT', 900);      // 15 minutes
define('SESSION_ABSOLUTE_TIMEOUT', 3600); // 1 hour

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

/* Enforce idle timeout */
if (isset($_SESSION['last_activity']) &&
    time() - $_SESSION['last_activity'] > SESSION_IDLE_TIMEOUT) {

    session_unset();
    session_destroy();
    header("Location: index.php?expired=1");
    exit;
}

/* Enforce absolute timeout */
if (isset($_SESSION['created_at']) &&
    time() - $_SESSION['created_at'] > SESSION_ABSOLUTE_TIMEOUT) {

    session_unset();
    session_destroy();
    header("Location: index.php?expired=1");
    exit;
}

/* Update activity timestamp */
$_SESSION['last_activity'] = time();
