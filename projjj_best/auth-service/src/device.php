<?php
/**
 * Control 15 — Device Fingerprinting (MONITOR ONLY)
 * MUST NEVER break login
 */

function handle_device(
    int $userId,
    string $fingerprint,
    string $ip,
    string $ua
): array {
    global $pdo;

    $default = [
        'known' => true,
        'times_seen' => 0
    ];

    if ($fingerprint === '') {
        return $default;
    }

    try {
        $stmt = $pdo->prepare(
            "SELECT id, times_seen
             FROM device_fingerprints
             WHERE user_id = ?
               AND fingerprint_hash = ?"
        );
        $stmt->execute([$userId, $fingerprint]);
        $device = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($device) {
            $pdo->prepare(
                "UPDATE device_fingerprints
                 SET times_seen = times_seen + 1,
                     ip_last = ?,
                     last_seen = NOW()
                 WHERE id = ?"
            )->execute([$ip, $device['id']]);

            return [
                'known' => true,
                'times_seen' => (int)$device['times_seen'] + 1
            ];
        }

        $pdo->prepare(
            "INSERT INTO device_fingerprints
                (user_id, fingerprint_hash, user_agent, ip_first, ip_last)
             VALUES (?, ?, ?, ?, ?)"
        )->execute([$userId, $fingerprint, $ua, $ip, $ip]);

        return [
            'known' => false,
            'times_seen' => 1
        ];

    } catch (Throwable $e) {
        log_event('DEVICE_FP_ERROR', $e->getMessage(), 'warning');
        return $default;
    }
}
