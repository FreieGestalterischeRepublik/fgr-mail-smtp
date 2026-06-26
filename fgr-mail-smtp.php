<?php
/**
 * Plugin Name:  FGR Mail SMTP
 * Description:  Ein Plugin der Freien Gestalterischen Republik. Ersetzt den Standard-WordPress-Mailer und sendet alle ausgehenden E-Mails zuverlässig über einen eigenen SMTP-Mailserver. Unterstützt TLS- und SSL-Verschlüsselung, SMTP-Authentifizierung sowie benutzerdefinierte Absenderangaben – alles bequem über das WordPress-Backend konfigurierbar.
 * Version:      1.4.0
 * Author:       Freie Gestalterische Republik
 * Author URI:   https://fgr.design
 * License:      GPL-2.0-or-later
 * Requires PHP: 8.0
 * Requires at least: 6.0
 * Text Domain:  fgr-mail-smtp
 */

defined( 'ABSPATH' ) || exit;

// Update-Checker: prüft GitHub auf neue Versionen
require_once plugin_dir_path( __FILE__ ) . 'lib/plugin-update-checker/plugin-update-checker.php';
$fgr_smtp_updater = YahnisElsts\PluginUpdateChecker\v5\PucFactory::buildUpdateChecker(
    'https://github.com/FreieGestalterischeRepublik/fgr-mail-smtp/',
    __FILE__,
    'fgr-mail-smtp'
);
$fgr_smtp_updater->setBranch( 'main' );

// Wert verschlüsseln — Schlüssel kommt aus der wp-config.php (AUTH_KEY)
function fgr_smtp_encrypt( string $value ): string {
    if ( '' === $value ) return '';
    $key    = substr( hash( 'sha256', AUTH_KEY . SECURE_AUTH_KEY ), 0, 32 );
    $iv     = random_bytes( 16 );
    $cipher = openssl_encrypt( $value, 'AES-256-CBC', $key, 0, $iv );
    return 'enc:' . base64_encode( $iv . $cipher );
}

// Wert entschlüsseln — "enc:"-Prefix erkennt verschlüsselte Werte
function fgr_smtp_decrypt( string $value ): string {
    if ( '' === $value ) return '';
    if ( ! str_starts_with( $value, 'enc:' ) ) return $value;
    $key    = substr( hash( 'sha256', AUTH_KEY . SECURE_AUTH_KEY ), 0, 32 );
    $raw    = base64_decode( substr( $value, 4 ) );
    $iv     = substr( $raw, 0, 16 );
    $cipher = substr( $raw, 16 );
    return openssl_decrypt( $cipher, 'AES-256-CBC', $key, 0, $iv ) ?: '';
}

$fgr_smtp_mode = get_option( 'fgr_smtp', [] )['mailer_mode'] ?? 'smtp';

// ── SMTP-Modus ────────────────────────────────────────────────────────────────

if ( 'smtp' === $fgr_smtp_mode ) {

    add_filter( 'wp_mail_from', function ( $default ) {
        $opt = get_option( 'fgr_smtp', [] );
        if ( ! empty( $opt['from_email'] ) ) return $opt['from_email'];
        return ( 'wordpress@localhost' === $default ) ? get_option( 'admin_email' ) : $default;
    } );

    add_filter( 'wp_mail_from_name', function ( $default ) {
        $opt = get_option( 'fgr_smtp', [] );
        return ! empty( $opt['from_name'] ) ? $opt['from_name'] : $default;
    } );

    add_action( 'phpmailer_init', 'fgr_smtp_configure_mailer' );
}

function fgr_smtp_configure_mailer( PHPMailer\PHPMailer\PHPMailer $mailer ): void {
    $opt = get_option( 'fgr_smtp', [] );
    if ( empty( $opt['host'] ) ) return;

    $mailer->isSMTP();
    $mailer->Host = $opt['host'];
    $mailer->Port = ! empty( $opt['port'] ) ? absint( $opt['port'] ) : 587;

    $enc = $opt['encryption'] ?? 'tls';
    if ( 'ssl' === $enc ) {
        $mailer->SMTPSecure = PHPMailer\PHPMailer\PHPMailer::ENCRYPTION_SMTPS;
    } elseif ( 'tls' === $enc ) {
        $mailer->SMTPSecure = PHPMailer\PHPMailer\PHPMailer::ENCRYPTION_STARTTLS;
    } else {
        $mailer->SMTPSecure = '';
        $mailer->SMTPAutoTLS = false;
    }

    if ( ! empty( $opt['username'] ) ) {
        $mailer->SMTPAuth = true;
        $mailer->Username = $opt['username'];
        $mailer->Password = fgr_smtp_decrypt( $opt['password'] ?? '' );
    } else {
        $mailer->SMTPAuth = false;
    }

    if ( ! empty( $opt['from_email'] ) ) {
        $mailer->From     = $opt['from_email'];
        $mailer->FromName = ! empty( $opt['from_name'] ) ? $opt['from_name'] : get_bloginfo( 'name' );
    }
}

// ── Microsoft 365 Graph API-Modus ────────────────────────────────────────────

if ( 'ms365' === $fgr_smtp_mode ) {
    // pre_wp_mail: fängt wp_mail() komplett ab, bevor PHPMailer läuft
    add_filter( 'pre_wp_mail', 'fgr_ms365_send', 10, 2 );
}

function fgr_ms365_get_access_token(): string|WP_Error {
    $cached = get_transient( 'fgr_ms365_token' );
    if ( $cached ) return $cached;

    $opt    = get_option( 'fgr_smtp', [] );
    $tenant = $opt['ms365_tenant'] ?? '';
    $app_id = $opt['ms365_app_id'] ?? '';
    $secret = fgr_smtp_decrypt( $opt['ms365_secret'] ?? '' );

    if ( ! $tenant || ! $app_id || ! $secret ) {
        return new WP_Error( 'ms365_config', 'Microsoft 365: Tenant-ID, Application-ID oder Client Secret fehlt.' );
    }

    $response = wp_remote_post(
        "https://login.microsoftonline.com/{$tenant}/oauth2/v2.0/token",
        [
            'body' => [
                'client_id'     => $app_id,
                'client_secret' => $secret,
                'scope'         => 'https://graph.microsoft.com/.default',
                'grant_type'    => 'client_credentials',
            ],
            'timeout' => 15,
        ]
    );

    if ( is_wp_error( $response ) ) return $response;

    $body = json_decode( wp_remote_retrieve_body( $response ), true );

    if ( empty( $body['access_token'] ) ) {
        $err = $body['error_description'] ?? ( $body['error'] ?? 'Unbekannter Fehler beim Token-Abruf.' );
        return new WP_Error( 'ms365_token', $err );
    }

    // Token 60 Sekunden vor Ablauf erneuern
    $expires = max( 60, (int) ( $body['expires_in'] ?? 3600 ) - 60 );
    set_transient( 'fgr_ms365_token', $body['access_token'], $expires );

    return $body['access_token'];
}

function fgr_ms365_send( $null, array $atts ): bool {
    $opt        = get_option( 'fgr_smtp', [] );
    $from_email = ! empty( $opt['from_email'] ) ? $opt['from_email'] : get_option( 'admin_email' );
    $from_name  = ! empty( $opt['from_name'] )  ? $opt['from_name']  : get_bloginfo( 'name' );

    $token = fgr_ms365_get_access_token();
    if ( is_wp_error( $token ) ) {
        do_action( 'wp_mail_failed', $token );
        return false;
    }

    // Header normalisieren (können String oder Array sein)
    $raw_headers = $atts['headers'] ?? [];
    if ( ! is_array( $raw_headers ) ) {
        $raw_headers = explode( "\n", str_replace( "\r\n", "\n", $raw_headers ) );
    }

    $cc_list  = [];
    $bcc_list = [];
    $is_html  = false;

    foreach ( $raw_headers as $header ) {
        $header = trim( $header );
        if ( ! $header ) continue;
        [ $name, $value ] = array_pad( explode( ':', $header, 2 ), 2, '' );
        $name  = strtolower( trim( $name ) );
        $value = trim( $value );

        if ( 'cc' === $name ) {
            foreach ( explode( ',', $value ) as $addr ) {
                $addr = trim( $addr );
                if ( $addr ) $cc_list[] = [ 'emailAddress' => [ 'address' => $addr ] ];
            }
        } elseif ( 'bcc' === $name ) {
            foreach ( explode( ',', $value ) as $addr ) {
                $addr = trim( $addr );
                if ( $addr ) $bcc_list[] = [ 'emailAddress' => [ 'address' => $addr ] ];
            }
        } elseif ( 'content-type' === $name && false !== stripos( $value, 'text/html' ) ) {
            $is_html = true;
        }
    }

    // Empfänger aufbereiten
    $to_addresses = is_array( $atts['to'] ) ? $atts['to'] : explode( ',', $atts['to'] );
    $to_list      = [];
    foreach ( $to_addresses as $addr ) {
        $addr = trim( $addr );
        if ( $addr ) $to_list[] = [ 'emailAddress' => [ 'address' => $addr ] ];
    }

    $body = [
        'message' => [
            'subject'      => $atts['subject'],
            'body'         => [
                'contentType' => $is_html ? 'Html' : 'Text',
                'content'     => $atts['message'],
            ],
            'from'         => [ 'emailAddress' => [ 'address' => $from_email, 'name' => $from_name ] ],
            'toRecipients' => $to_list,
        ],
        'saveToSentItems' => false,
    ];

    if ( $cc_list )  $body['message']['ccRecipients']  = $cc_list;
    if ( $bcc_list ) $body['message']['bccRecipients'] = $bcc_list;

    // Anhänge (base64-kodiert, max. ~3 MB pro Datei)
    if ( ! empty( $atts['attachments'] ) ) {
        $graph_attachments = [];
        foreach ( (array) $atts['attachments'] as $path ) {
            if ( ! is_readable( $path ) ) continue;
            $graph_attachments[] = [
                '@odata.type'  => '#microsoft.graph.fileAttachment',
                'name'         => basename( $path ),
                'contentType'  => mime_content_type( $path ) ?: 'application/octet-stream',
                'contentBytes' => base64_encode( file_get_contents( $path ) ),
            ];
        }
        if ( $graph_attachments ) $body['message']['attachments'] = $graph_attachments;
    }

    $response = wp_remote_post(
        'https://graph.microsoft.com/v1.0/users/' . rawurlencode( $from_email ) . '/sendMail',
        [
            'headers' => [
                'Authorization' => 'Bearer ' . $token,
                'Content-Type'  => 'application/json',
            ],
            'body'    => wp_json_encode( $body ),
            'timeout' => 20,
        ]
    );

    if ( is_wp_error( $response ) ) {
        do_action( 'wp_mail_failed', $response );
        return false;
    }

    $code = (int) wp_remote_retrieve_response_code( $response );
    if ( $code >= 200 && $code <= 299 ) return true;

    $resp_body = json_decode( wp_remote_retrieve_body( $response ), true );
    $err_msg   = $resp_body['error']['message'] ?? "Microsoft Graph: HTTP {$code}";
    do_action( 'wp_mail_failed', new WP_Error( 'ms365_send', $err_msg ) );
    return false;
}

// ── Admin-Einstellungsseite ───────────────────────────────────────────────────

add_action( 'plugins_loaded', function () {
    if ( is_admin() ) {
        require_once plugin_dir_path( __FILE__ ) . 'includes/class-fgr-smtp-settings.php';
        new FGR_SMTP_Settings();
    }
} );
