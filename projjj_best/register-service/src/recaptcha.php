<?php

function verify_recaptcha(string $token, string $action): bool
{
    $secret = $_ENV['RECAPTCHA_SECRET_KEY'] ?? '';

    if ($secret === '' || $token === '') {
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
    $result  = file_get_contents(
        'https://www.google.com/recaptcha/api/siteverify',
        false,
        $context
    );

    if ($result === false) {
        return false;
    }

    $json = json_decode($result, true);

    return (
        isset($json['success'], $json['score'], $json['action']) &&
        $json['success'] === true &&
        $json['action'] === $action &&
        $json['score'] >= 0.5
    );
}
