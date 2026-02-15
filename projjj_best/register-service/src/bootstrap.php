<?php
/**
 * Registration service bootstrap
 * - Reverse proxy HTTPS awareness
 * - Secure session handling
 * - NO session timeout enforcement (public page)
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

/* Start session once */
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}
