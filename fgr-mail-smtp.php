<?php
/**
 * Plugin Name:  FGR Mail SMTP
 * Description:  Ein Plugin der Freien Gestalterischen Republik. Ersetzt den Standard-WordPress-Mailer und sendet alle ausgehenden E-Mails zuverlässig über einen eigenen SMTP-Mailserver. Unterstützt TLS- und SSL-Verschlüsselung, SMTP-Authentifizierung sowie benutzerdefinierte Absenderangaben – alles bequem über das WordPress-Backend konfigurierbar.
 * Version:      1.3.0
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

// Passwort verschlüsseln — Schlüssel kommt aus der wp-config.php (AUTH_KEY)
function fgr_smtp_encrypt( string $value ): string {
    if ( '' === $value ) return '';
    $key    = substr( hash( 'sha256', AUTH_KEY . SECURE_AUTH_KEY ), 0, 32 );
    $iv     = random_bytes( 16 );
    $cipher = openssl_encrypt( $value, 'AES-256-CBC', $key, 0, $iv );
    return 'enc:' . base64_encode( $iv . $cipher );
}

// Passwort entschlüsseln — "enc:"-Prefix erkennt verschlüsselte Werte
function fgr_smtp_decrypt( string $value ): string {
    if ( '' === $value ) return '';
    if ( ! str_starts_with( $value, 'enc:' ) ) return $value; // Altdaten ohne Prefix
    $key    = substr( hash( 'sha256', AUTH_KEY . SECURE_AUTH_KEY ), 0, 32 );
    $raw    = base64_decode( substr( $value, 4 ) );
    $iv     = substr( $raw, 0, 16 );
    $cipher = substr( $raw, 16 );
    return openssl_decrypt( $cipher, 'AES-256-CBC', $key, 0, $iv ) ?: '';
}

// Hooks nur aktiv schalten wenn SMTP-Modus gewählt ist
$fgr_smtp_mode = get_option( 'fgr_smtp', [] )['mailer_mode'] ?? 'smtp';

if ( 'smtp' === $fgr_smtp_mode ) {

    // Absenderadresse früh setzen, bevor WordPress "wordpress@localhost" verwendet
    add_filter( 'wp_mail_from', function ( $default ) {
        $opt = get_option( 'fgr_smtp', [] );
        if ( ! empty( $opt['from_email'] ) ) {
            return $opt['from_email'];
        }
        // "wordpress@localhost" ist ungültig — Fallback auf Admin-E-Mail
        return ( 'wordpress@localhost' === $default ) ? get_option( 'admin_email' ) : $default;
    } );

    add_filter( 'wp_mail_from_name', function ( $default ) {
        $opt = get_option( 'fgr_smtp', [] );
        return ! empty( $opt['from_name'] ) ? $opt['from_name'] : $default;
    } );

    // SMTP konfigurieren, wenn WordPress PHPMailer initialisiert
    add_action( 'phpmailer_init', 'fgr_smtp_configure_mailer' );

}

function fgr_smtp_configure_mailer( PHPMailer\PHPMailer\PHPMailer $mailer ) {
    $opt = get_option( 'fgr_smtp', [] );

    if ( empty( $opt['host'] ) ) {
        return;
    }

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

// Admin-Einstellungsseite laden
add_action( 'plugins_loaded', function () {
    if ( is_admin() ) {
        require_once plugin_dir_path( __FILE__ ) . 'includes/class-fgr-smtp-settings.php';
        new FGR_SMTP_Settings();
    }
} );
