<?php
require_once 'roles.php';

/**
 * Enforce access to a page based on role
 */
function requireRole(array $roles): void
{
    if (session_status() === PHP_SESSION_NONE) {
        session_start();
    }

    if (
        !isset($_SESSION['role']) ||
        !in_array($_SESSION['role'], $roles, true)
    ) {
        http_response_code(403);
        exit('Forbidden');
    }
}
