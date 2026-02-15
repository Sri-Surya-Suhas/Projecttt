<?php
/**
 * Control 16 — IP Reputation & Blocking
 * FAIL-SAFE, STANDALONE
 */

function ip_is_blocked(string $ip): bool
{
    global $pdo;

    if ($ip === '') {
        return false;
    }

    try {
        $stmt = $pdo->prepare(
            "SELECT 1
             FROM ip_reputation
             WHERE ip_address = ?
               AND blocked_until > NOW()"
        );
        $stmt->execute([$ip]);

        return (bool)$stmt->fetchColumn();
    } catch (Throwable $e) {
        // MUST fail open
        error_log('IP_CHECK_ERROR: ' . $e->getMessage());
        return false;
    }
}

function ip_record_event(string $ip, int $delta): void
{
    global $pdo;

    if ($ip === '') {
        return;
    }

    try {
        $stmt = $pdo->prepare(
            "INSERT INTO ip_reputation (ip_address, score, last_event)
             VALUES (?, ?, NOW())
             ON CONFLICT (ip_address)
             DO UPDATE SET
                score = GREATEST(0, ip_reputation.score + EXCLUDED.score),
                last_event = NOW()"
        );
        $stmt->execute([$ip, $delta]);

        $stmt = $pdo->prepare(
            "SELECT score, blocked_until
             FROM ip_reputation
             WHERE ip_address = ?"
        );
        $stmt->execute([$ip]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$row) {
            return;
        }

        // Apply block only if not already blocked
        if ($row['blocked_until'] === null) {
            if ($row['score'] >= 100) {
                set_ip_block($ip, 3600);
            } elseif ($row['score'] >= 50) {
                set_ip_block($ip, 900);
            }
        }

    } catch (Throwable $e) {
        // MUST NOT depend on audit logging
        error_log('IP_REP_ERROR: ' . $e->getMessage());
    }
}

function set_ip_block(string $ip, int $seconds): void
{
    global $pdo;

    try {
        $stmt = $pdo->prepare(
            "UPDATE ip_reputation
             SET blocked_until = NOW() + make_interval(secs => ?)
             WHERE ip_address = ?"
        );
        $stmt->execute([$seconds, $ip]);
    } catch (Throwable $e) {
        error_log('IP_BLOCK_ERROR: ' . $e->getMessage());
    }
}
