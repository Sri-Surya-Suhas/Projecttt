<?php
/**
 * Control 17 — Behavioral Risk Scoring
 * MUST be deterministic and FAIL-SAFE
 */

function calculate_risk(
    array $user,
    string $ip,
    array $deviceContext = []
): array {
    global $pdo;

    $risk = 0;
    $reasons = [];

    // 1️⃣ Failed login attempts
    if (!empty($user['failed_attempts']) && $user['failed_attempts'] >= 3) {
        $risk += 30;
        $reasons[] = 'multiple_failed_logins';
    }

    // 2️⃣ Account lock signal
    if (!empty($user['lock_until'])) {
        $risk += 40;
        $reasons[] = 'recent_account_lock';
    }

    // 3️⃣ New device
    if (($deviceContext['known'] ?? true) === false) {
        $risk += 20;
        $reasons[] = 'new_device';
    }

    // 4️⃣ Rapid failures from IP (fail-safe)
    try {
        $stmt = $pdo->prepare(
            "SELECT COUNT(*)
             FROM audit_logs
             WHERE ip_address = ?
               AND event_type = 'LOGIN_FAILED'
               AND created_at > NOW() - INTERVAL '10 minutes'"
        );
        $stmt->execute([$ip]);

        if ((int)$stmt->fetchColumn() >= 5) {
            $risk += 30;
            $reasons[] = 'rapid_failures_from_ip';
        }
    } catch (Throwable $e) {
        // MUST FAIL OPEN
    }

    return [
        min(100, $risk),
        $reasons   // <-- KEEP AS ARRAY
    ];
}
