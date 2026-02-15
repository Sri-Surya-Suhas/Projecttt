<?php
/**
 * Central Security Event Logger
 * Writes to audit_logs table
 * MUST NEVER break application flow
 */

function log_event(
    string $eventType,
    string $message = '',
    string $severity = 'info',
    string $category = 'auth'
): void {
    global $pdo;

    try {
        $ip = $_SERVER['REMOTE_ADDR'] ?? null;
        $userId = $_SESSION['user_id'] ?? null;

        $stmt = $pdo->prepare(
            "INSERT INTO audit_logs
                (event_type, message, severity, category, ip_address, user_id)
             VALUES (?, ?, ?, ?, ?, ?)"
        );

        $stmt->execute([
            $eventType,
            $message,
            $severity,
            $category,
            $ip,
            $userId
        ]);

    } catch (Throwable $e) {
        // Logging must never break the app
        error_log('LOG_EVENT_FAILED: ' . $e->getMessage());
    }
}
