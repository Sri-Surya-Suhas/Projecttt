<?php
/**
 * reCAPTCHA v3 verification
 * FAIL-OPEN when Google is unavailable (Option B)
 * NEVER breaks login flow
 *
 * Return values:
 *  - true  → reCAPTCHA passed
 *  - false → reCAPTCHA failed (bot / low score / mismatch)
 *  - null  → reCAPTCHA unavailable (network / Google down)
 */

function verify_recaptcha(string $token, string $action): ?bool
{
    $secret = getenv('RECAPTCHA_SECRET_KEY');

    // Missing secret or token = hard fail
    if (!$secret || $token === '') {
        return false;
    }

    $data = [
        'secret'   => $secret,
        'response' => $token,
        'remoteip' => $_SERVER['REMOTE_ADDR'] ?? ''
    ];

    $options = [
        'http' => [
            'method'  => 'POST',
            'header'  => "Content-Type: application/x-www-form-urlencoded\r\n",
            'content' => http_build_query($data),
            'timeout' => 5
        ]
    ];

    $context = stream_context_create($options);
    $result  = @file_get_contents(
        'https://www.google.com/recaptcha/api/siteverify',
        false,
        $context
    );

    // Google unreachable → FAIL OPEN
    if ($result === false) {
        log_event('RECAPTCHA_UNAVAILABLE', 'google_unreachable', 'warning', 'security');
        return null;
    }

    $json = json_decode($result, true);

    if (!is_array($json)) {
        log_event('RECAPTCHA_INVALID_RESPONSE', 'json_decode_failed', 'warning', 'security');
        return null;
    }

    // Hard failure conditions
    if (
        empty($json['success']) ||
        ($json['action'] ?? '') !== $action ||
        ($json['score'] ?? 0) < 0.5
    ) {
        log_event(
            'RECAPTCHA_FAILED',
            json_encode([
                'action' => $json['action'] ?? null,
                'score'  => $json['score'] ?? null
            ]),
            'warning',
            'security'
        );
        return false;
    }

    return true;
}
