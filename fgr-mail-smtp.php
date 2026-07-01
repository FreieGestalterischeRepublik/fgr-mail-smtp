<?php
/**
 * Plugin Name:  FGR Mail SMTP
 * Description:  Ein Plugin der Freien Gestalterischen Republik. Ersetzt den Standard-WordPress-Mailer und sendet alle ausgehenden E-Mails zuverlässig über einen eigenen SMTP-Mailserver. Unterstützt TLS- und SSL-Verschlüsselung, SMTP-Authentifizierung sowie benutzerdefinierte Absenderangaben – alles bequem über das WordPress-Backend konfigurierbar.
 * Version:      1.9.2
 * Author:       Freie Gestalterische Republik
 * Author URI:   https://fgr.design
 * License:      GPL-2.0-or-later
 * Requires PHP: 7.4
 * Requires at least: 5.0
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
$fgr_smtp_updater->getVcsApi()->enableReleaseAssets();

// "Details anzeigen" und "Nach Update suchen" erscheinen in der Pluginliste auch wenn ein Update verfügbar ist.
// PUC überspringt "Details anzeigen" wenn WordPress einen slug in plugin_data setzt (passiert bei erkanntem Update).
add_filter( 'plugin_row_meta', function ( array $links, string $plugin_file ): array {
    if ( plugin_basename( __FILE__ ) !== $plugin_file || ! current_user_can( 'update_plugins' ) ) {
        return $links;
    }
    $has_details = false;
    $has_check   = false;
    foreach ( $links as $link ) {
        if ( strpos( $link, 'open-plugin-details-modal' ) !== false ) $has_details = true;
        if ( strpos( $link, 'puc_check_for_updates' )     !== false ) $has_check   = true;
    }
    if ( ! $has_details ) {
        $url     = network_admin_url( 'plugin-install.php?tab=plugin-information&plugin=fgr-mail-smtp&TB_iframe=true&width=600&height=550' );
        $links[] = '<a href="' . esc_url( $url ) . '" class="thickbox open-plugin-details-modal">Details anzeigen</a>';
    }
    if ( ! $has_check ) {
        $url     = wp_nonce_url(
            add_query_arg( [ 'puc_check_for_updates' => 1, 'puc_slug' => 'fgr-mail-smtp' ], self_admin_url( 'plugins.php' ) ),
            'puc_check_for_updates'
        );
        $links[] = '<a href="' . esc_url( $url ) . '">Nach Update suchen</a>';
    }
    return $links;
}, 20, 2 );

// Warnung wenn Plugin im falschen Ordner installiert ist (z. B. "fgr-mail-smtp-main")
if ( is_admin() && substr( untrailingslashit( plugin_dir_path( __FILE__ ) ), -5 ) === '-main' ) {
    add_action( 'admin_notices', function () {
        $zip_url = 'https://github.com/FreieGestalterischeRepublik/fgr-mail-smtp/releases/latest';
        echo '<div class="notice notice-error"><p>'
            . '<strong>FGR Mail SMTP:</strong> Das Plugin ist im falschen Ordner installiert '
            . '(<code>' . esc_html( basename( plugin_dir_path( __FILE__ ) ) ) . '</code>). '
            . 'Bitte das Plugin <strong>deaktivieren → löschen → neu installieren</strong>. '
            . 'Deine Einstellungen bleiben dabei erhalten. '
            . '<a href="' . esc_url( $zip_url ) . '" target="_blank">ZIP herunterladen →</a>'
            . '</p></div>';
    } );
}

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
    if ( strpos( $value, 'enc:' ) !== 0 ) return $value;
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

// Rückgabetyp-Union (string|WP_Error) entfernt für PHP 7.4-Kompatibilität
function fgr_ms365_get_access_token() {
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

// ── MU-Plugin-Sync ────────────────────────────────────────────────────────────
// Installiert/aktualisiert das MU-Plugin von GitHub (function_exists-Guard: MU-Plugin definiert dieselbe Funktion)

if ( ! function_exists( 'fgr_mu_sync' ) ) {
    function fgr_mu_sync(): void {
        $url      = 'https://raw.githubusercontent.com/FreieGestalterischeRepublik/fgr-plugin-overview/main/fgr-plugin-overview.php';
        $dest_dir = WPMU_PLUGIN_DIR;
        $dest     = $dest_dir . '/fgr-plugin-overview.php';

        $response = wp_remote_get( $url, [
            'timeout'    => 15,
            'user-agent' => 'WordPress/' . get_bloginfo( 'version' ) . '; ' . home_url(),
        ] );

        if ( is_wp_error( $response ) ) return;
        if ( 200 !== wp_remote_retrieve_response_code( $response ) ) return;

        $remote_content = wp_remote_retrieve_body( $response );
        if ( empty( $remote_content ) ) return;

        preg_match( '/\*\s+Version:\s+([\d.]+)/i', $remote_content, $matches );
        $remote_version = $matches[1] ?? '0';

        // Installierte Version lesen
        $installed_version = '0';
        if ( file_exists( $dest ) ) {
            $contents = file_get_contents( $dest );
            preg_match( '/\*\s+Version:\s+([\d.]+)/i', $contents, $m );
            $installed_version = $m[1] ?? '0';
        }

        if ( ! file_exists( $dest ) || version_compare( $remote_version, $installed_version, '>' ) ) {
            if ( ! is_dir( $dest_dir ) ) {
                wp_mkdir_p( $dest_dir );
            }
            file_put_contents( $dest, $remote_content );
            delete_transient( 'fgr_mu_update_info' );
        }
    }
}

// MU-Plugin bei Plugin-Aktivierung installieren/aktualisieren
register_activation_hook( __FILE__, 'fgr_mu_sync' );

// MU-Plugin nach Update eines FGR-Plugins aktualisieren
add_action( 'upgrader_process_complete', function ( $upgrader, array $hook_extra ): void {
    if ( ( $hook_extra['type'] ?? '' ) !== 'plugin' ) return;
    if ( ( $hook_extra['action'] ?? '' ) !== 'update' ) return;

    $fgr_plugins = [
        'fgr-mail-smtp/fgr-mail-smtp.php',
        'fgr-hide-login/fgr-hide-login.php',
        'fgr-maintenance/fgr-maintenance.php',
        'fgr-email-encoder/fgr-email-encoder.php',
    ];

    $updated = array_merge(
        isset( $hook_extra['plugin'] )  ? (array) $hook_extra['plugin']  : [],
        isset( $hook_extra['plugins'] ) ? (array) $hook_extra['plugins'] : []
    );

    foreach ( $updated as $plugin_file ) {
        if ( in_array( $plugin_file, $fgr_plugins, true ) ) {
            fgr_mu_sync();
            return;
        }
    }
}, 10, 2 );

// ── Gemeinsamer FGR-Admin-Menüpunkt ──────────────────────────────────────────
// function_exists-Guard verhindert Doppelung wenn mehrere FGR-Plugins aktiv sind

if ( ! function_exists( 'fgr_register_admin_menu' ) ) {

    function fgr_register_admin_menu(): void {
        add_menu_page(
            'FGR Plugins',
            'FGR Plugins',
            'manage_options',
            'fgr-plugins',
            'fgr_render_plugins_overview',
            'dashicons-shield',
            65
        );
        // Den automatisch erzeugten doppelten "FGR Plugins"-Untermenüeintrag
        // durch einen sauberen "Übersicht"-Eintrag ersetzen
        add_submenu_page(
            'fgr-plugins',
            'FGR Plugins',
            'Übersicht',
            'manage_options',
            'fgr-plugins',
            'fgr_render_plugins_overview'
        );
    }
    add_action( 'admin_menu', 'fgr_register_admin_menu', 5 );

    function fgr_render_plugins_overview(): void {
        $plugins = [
            [
                'slug' => 'fgr-mail-smtp',
                'file' => 'fgr-mail-smtp/fgr-mail-smtp.php',
                'name' => 'FGR Mail SMTP',
                'desc' => 'E-Mails über SMTP oder Microsoft 365 versenden',
                'page' => 'fgr-mail-smtp',
            ],
            [
                'slug' => 'fgr-hide-login',
                'file' => 'fgr-hide-login/fgr-hide-login.php',
                'name' => 'FGR Hide Login',
                'desc' => 'Login-URL individuell anpassen und schützen',
                'page' => 'fgr-hide-login',
            ],
            [
                'slug' => 'fgr-maintenance',
                'file' => 'fgr-maintenance/fgr-maintenance.php',
                'name' => 'FGR Maintenance',
                'desc' => 'Under-Construction- oder Wartungsseite anzeigen',
                'page' => 'fgr-maintenance',
            ],
            [
                'slug' => 'fgr-email-encoder',
                'file' => 'fgr-email-encoder/fgr-email-encoder.php',
                'name' => 'FGR Email Encoder',
                'desc' => 'E-Mail-Adressen vor Spam-Bots schützen',
                'page' => 'fgr-email-encoder',
            ],
        ];
        ?>
        <div class="wrap">
            <h1>FGR Plugins</h1>
            <p style="color:#888;margin-top:-8px">von der <em>Freien Gestalterischen Republik</em></p>
            <div style="display:flex;gap:16px;flex-wrap:wrap;margin-top:20px">
            <?php foreach ( $plugins as $p ) :
                $active    = is_plugin_active( $p['file'] );
                $installed = file_exists( WP_PLUGIN_DIR . '/' . $p['file'] );
                if ( $active ) {
                    $badge = '<span style="color:#46b450;font-size:12px">&#9679; Aktiv</span>';
                } elseif ( $installed ) {
                    $badge = '<span style="color:#888;font-size:12px">&#9679; Inaktiv</span>';
                } else {
                    $badge = '<span style="color:#dc3545;font-size:12px">&#9679; Nicht installiert</span>';
                }
            ?>
                <div style="background:#fff;border:1px solid #ccd0d4;border-radius:4px;padding:20px 24px;min-width:240px;max-width:320px">
                    <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:4px">
                        <h2 style="margin:0"><?php echo esc_html( $p['name'] ); ?></h2>
                        <?php echo $badge; ?>
                    </div>
                    <p style="color:#555;margin-bottom:16px"><?php echo esc_html( $p['desc'] ); ?></p>
                    <?php if ( $active ) : ?>
                        <a href="<?php echo esc_url( admin_url( 'admin.php?page=' . $p['page'] ) ); ?>"
                           class="button button-primary">Einstellungen</a>
                    <?php elseif ( $installed ) : ?>
                        <a href="<?php echo esc_url( wp_nonce_url(
                            admin_url( 'plugins.php?action=activate&plugin=' . urlencode( $p['file'] ) ),
                            'activate-plugin_' . $p['file']
                        ) ); ?>" class="button button-primary">Aktivieren</a>
                    <?php else : ?>
                        <button type="button" class="button button-primary fgr-install-btn"
                                data-slug="<?php echo esc_attr( $p['slug'] ); ?>">
                            Installieren
                        </button>
                    <?php endif; ?>
                </div>
            <?php endforeach; ?>
            </div>
        </div>
        <script>
        document.querySelectorAll( '.fgr-install-btn' ).forEach( function ( btn ) {
            btn.addEventListener( 'click', function () {
                var self = this;
                self.disabled    = true;
                self.textContent = 'Installiere…';
                fetch( ajaxurl, {
                    method: 'POST',
                    body:   new URLSearchParams( {
                        action:      'fgr_install_plugin',
                        slug:        self.dataset.slug,
                        _ajax_nonce: '<?php echo wp_create_nonce( 'fgr_install_plugin' ); ?>'
                    } )
                } )
                .then( function ( r ) { return r.json(); } )
                .then( function ( data ) {
                    if ( data.success ) {
                        location.reload();
                    } else {
                        alert( 'Fehler: ' + ( data.data || 'Unbekannter Fehler' ) );
                        self.disabled    = false;
                        self.textContent = 'Installieren';
                    }
                } )
                .catch( function () {
                    alert( 'Verbindungsfehler.' );
                    self.disabled    = false;
                    self.textContent = 'Installieren';
                } );
            } );
        } );
        </script>
        <?php
    }

    add_action( 'wp_ajax_fgr_install_plugin', 'fgr_install_plugin_handler' );

    function fgr_install_plugin_handler(): void {
        check_ajax_referer( 'fgr_install_plugin' );

        if ( ! current_user_can( 'install_plugins' ) ) {
            wp_send_json_error( 'Keine Berechtigung.' );
        }

        $slug    = sanitize_key( $_POST['slug'] ?? '' );
        $allowed = [ 'fgr-mail-smtp', 'fgr-hide-login', 'fgr-maintenance', 'fgr-email-encoder' ];

        if ( ! in_array( $slug, $allowed, true ) ) {
            wp_send_json_error( 'Unbekanntes Plugin.' );
        }

        require_once ABSPATH . 'wp-admin/includes/class-wp-upgrader.php';
        require_once ABSPATH . 'wp-admin/includes/plugin.php';

        // GitHub-Source-ZIP des main-Branches laden
        $zip_url  = "https://github.com/FreieGestalterischeRepublik/{$slug}/archive/refs/heads/main.zip";
        $skin     = new WP_Ajax_Upgrader_Skin();
        $upgrader = new Plugin_Upgrader( $skin );
        $result   = $upgrader->install( $zip_url );

        if ( is_wp_error( $result ) ) {
            wp_send_json_error( $result->get_error_message() );
        }
        if ( false === $result ) {
            wp_send_json_error( 'Installation fehlgeschlagen. Bitte Dateisystem-Berechtigungen prüfen.' );
        }

        // GitHub-ZIP entpackt in "{slug}-main/" → zum korrekten Ordnernamen umbenennen
        $wrong_dir   = WP_PLUGIN_DIR . '/' . $slug . '-main';
        $correct_dir = WP_PLUGIN_DIR . '/' . $slug;
        if ( is_dir( $wrong_dir ) && ! is_dir( $correct_dir ) ) {
            rename( $wrong_dir, $correct_dir );
        }

        wp_send_json_success( [ 'message' => 'Plugin erfolgreich installiert.' ] );
    }
}

// ── Admin-Einstellungsseite ───────────────────────────────────────────────────

add_action( 'plugins_loaded', function () {
    if ( is_admin() ) {
        require_once plugin_dir_path( __FILE__ ) . 'includes/class-fgr-smtp-settings.php';
        new FGR_SMTP_Settings();
    }
} );
