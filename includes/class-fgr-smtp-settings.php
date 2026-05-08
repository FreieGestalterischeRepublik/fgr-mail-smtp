<?php
defined( 'ABSPATH' ) || exit;

class FGR_SMTP_Settings {

    public function __construct() {
        add_action( 'admin_menu',   [ $this, 'add_menu' ] );
        add_action( 'admin_init',   [ $this, 'handle_save' ] );
        add_action( 'admin_init',   [ $this, 'handle_test_mail' ] );
        add_action( 'admin_notices', [ $this, 'show_notices' ] );
    }

    public function add_menu() {
        add_options_page(
            'FGR Mail SMTP',
            'FGR Mail SMTP',
            'manage_options',
            'fgr-mail-smtp',
            [ $this, 'render_page' ]
        );
    }

    // Einstellungen speichern
    public function handle_save() {
        if ( ! isset( $_POST['fgr_smtp_save'] ) ) {
            return;
        }
        check_admin_referer( 'fgr_smtp_save', 'fgr_smtp_nonce' );

        $enc = sanitize_key( $_POST['encryption'] ?? 'tls' );
        if ( ! in_array( $enc, [ 'none', 'ssl', 'tls' ], true ) ) {
            $enc = 'tls';
        }

        $existing = get_option( 'fgr_smtp', [] );

        // Passwort nur überschreiben wenn ein neues eingegeben wurde
        $new_pass        = $_POST['password'] ?? '';
        $saved_pass      = ( '' !== $new_pass ) ? fgr_smtp_encrypt( $new_pass ) : ( $existing['password'] ?? '' );

        update_option( 'fgr_smtp', [
            'host'       => sanitize_text_field( $_POST['host'] ?? '' ),
            'port'       => absint( $_POST['port'] ?? 587 ),
            'encryption' => $enc,
            'username'   => sanitize_text_field( $_POST['username'] ?? '' ),
            'password'   => $saved_pass,
            'from_email' => sanitize_email( $_POST['from_email'] ?? '' ),
            'from_name'  => sanitize_text_field( $_POST['from_name'] ?? '' ),
        ] );

        set_transient( 'fgr_smtp_notice', 'saved', 30 );
        wp_safe_redirect( admin_url( 'options-general.php?page=fgr-mail-smtp' ) );
        exit;
    }

    // Testmail verschicken
    public function handle_test_mail() {
        if ( ! isset( $_POST['fgr_smtp_test'] ) ) {
            return;
        }
        check_admin_referer( 'fgr_smtp_test', 'fgr_smtp_test_nonce' );

        $to = sanitize_email( $_POST['test_email'] ?? '' );

        if ( ! is_email( $to ) ) {
            set_transient( 'fgr_smtp_notice', 'test_invalid', 30 );
            wp_safe_redirect( admin_url( 'options-general.php?page=fgr-mail-smtp' ) );
            exit;
        }

        $last_error = null;
        add_action( 'wp_mail_failed', function ( WP_Error $error ) use ( &$last_error ) {
            $last_error = $error->get_error_message();
        } );

        $sent = wp_mail(
            $to,
            'Testmail – ' . get_bloginfo( 'name' ),
            "Diese E-Mail wurde erfolgreich über FGR Mail SMTP verschickt.\n\nDie SMTP-Verbindung funktioniert korrekt."
        );

        if ( $sent ) {
            set_transient( 'fgr_smtp_notice', 'test_ok:' . $to, 30 );
        } else {
            $msg = $last_error ?? 'Unbekannter Fehler – bitte SMTP-Einstellungen prüfen.';
            set_transient( 'fgr_smtp_notice', 'test_err:' . $msg, 30 );
        }

        wp_safe_redirect( admin_url( 'options-general.php?page=fgr-mail-smtp' ) );
        exit;
    }

    // Admin-Meldungen anzeigen
    public function show_notices() {
        if ( ( $_GET['page'] ?? '' ) !== 'fgr-mail-smtp' ) {
            return;
        }

        $n = get_transient( 'fgr_smtp_notice' );
        if ( ! $n ) {
            return;
        }
        delete_transient( 'fgr_smtp_notice' );

        if ( 'saved' === $n ) {
            echo '<div class="notice notice-success is-dismissible"><p><strong>Einstellungen gespeichert.</strong></p></div>';
        } elseif ( str_starts_with( $n, 'test_ok:' ) ) {
            $to = esc_html( substr( $n, 8 ) );
            echo "<div class=\"notice notice-success is-dismissible\"><p><strong>Testmail erfolgreich an {$to} verschickt.</strong></p></div>";
        } elseif ( str_starts_with( $n, 'test_err:' ) ) {
            $msg = esc_html( substr( $n, 9 ) );
            echo "<div class=\"notice notice-error is-dismissible\"><p><strong>Testmail fehlgeschlagen:</strong> {$msg}</p></div>";
        } elseif ( 'test_invalid' === $n ) {
            echo '<div class="notice notice-error is-dismissible"><p><strong>Ungültige E-Mail-Adresse.</strong></p></div>';
        }
    }

    // Einstellungsseite rendern
    public function render_page() {
        if ( ! current_user_can( 'manage_options' ) ) {
            return;
        }

        $opt  = get_option( 'fgr_smtp', [] );
        $enc  = $opt['encryption'] ?? 'tls';
        ?>
        <div class="wrap">
            <h1>FGR Mail SMTP</h1>
            <p style="color:#888;margin-top:-8px">aus der <em>Freien Gestalterischen Republik</em></p>

            <form method="post">
                <?php wp_nonce_field( 'fgr_smtp_save', 'fgr_smtp_nonce' ); ?>
                <table class="form-table" role="presentation">

                    <tr>
                        <th scope="row"><label for="host">SMTP-Host</label></th>
                        <td>
                            <input type="text" id="host" name="host" class="regular-text"
                                   value="<?php echo esc_attr( $opt['host'] ?? '' ); ?>"
                                   placeholder="mail.example.com">
                        </td>
                    </tr>

                    <tr>
                        <th scope="row"><label for="port">SMTP-Port</label></th>
                        <td>
                            <input type="number" id="port" name="port" class="small-text"
                                   value="<?php echo esc_attr( $opt['port'] ?? 587 ); ?>"
                                   min="1" max="65535">
                            <p class="description">587 = TLS &nbsp;|&nbsp; 465 = SSL &nbsp;|&nbsp; 25 = Ohne</p>
                        </td>
                    </tr>

                    <tr>
                        <th scope="row">Verschlüsselung</th>
                        <td>
                            <fieldset>
                                <label>
                                    <input type="radio" name="encryption" value="tls" <?php checked( $enc, 'tls' ); ?>>
                                    TLS <span style="color:#888">(empfohlen)</span>
                                </label><br>
                                <label>
                                    <input type="radio" name="encryption" value="ssl" <?php checked( $enc, 'ssl' ); ?>>
                                    SSL
                                </label><br>
                                <label>
                                    <input type="radio" name="encryption" value="none" <?php checked( $enc, 'none' ); ?>>
                                    Keine
                                </label>
                            </fieldset>
                        </td>
                    </tr>

                    <tr>
                        <th scope="row"><label for="username">Benutzername</label></th>
                        <td>
                            <input type="text" id="username" name="username" class="regular-text"
                                   value="<?php echo esc_attr( $opt['username'] ?? '' ); ?>"
                                   placeholder="info@example.com" autocomplete="off">
                            <p class="description">Leer lassen für SMTP ohne Authentifizierung.</p>
                        </td>
                    </tr>

                    <tr>
                        <th scope="row"><label for="password">Passwort</label></th>
                        <td>
                            <input type="password" id="password" name="password" class="regular-text"
                                   value="" autocomplete="new-password"
                                   placeholder="<?php echo ! empty( $opt['password'] ) ? '(gespeichert – leer lassen, um es zu behalten)' : ''; ?>">
                        </td>
                    </tr>

                    <tr>
                        <th scope="row"><label for="from_email">Absender-E-Mail</label></th>
                        <td>
                            <input type="email" id="from_email" name="from_email" class="regular-text"
                                   value="<?php echo esc_attr( $opt['from_email'] ?? '' ); ?>"
                                   placeholder="info@example.com">
                        </td>
                    </tr>

                    <tr>
                        <th scope="row"><label for="from_name">Absender-Name</label></th>
                        <td>
                            <input type="text" id="from_name" name="from_name" class="regular-text"
                                   value="<?php echo esc_attr( $opt['from_name'] ?? get_bloginfo( 'name' ) ); ?>">
                        </td>
                    </tr>

                </table>

                <p class="submit">
                    <button type="submit" name="fgr_smtp_save" class="button button-primary">
                        Einstellungen speichern
                    </button>
                </p>
            </form>

            <hr>

            <h2>Testmail senden</h2>
            <p>Testet die SMTP-Verbindung mit den aktuell <strong>gespeicherten</strong> Einstellungen.</p>

            <form method="post">
                <?php wp_nonce_field( 'fgr_smtp_test', 'fgr_smtp_test_nonce' ); ?>
                <table class="form-table" role="presentation">
                    <tr>
                        <th scope="row"><label for="test_email">Empfänger</label></th>
                        <td>
                            <input type="email" id="test_email" name="test_email" class="regular-text"
                                   value="<?php echo esc_attr( get_option( 'admin_email' ) ); ?>" required>
                        </td>
                    </tr>
                </table>
                <p class="submit">
                    <button type="submit" name="fgr_smtp_test" class="button button-secondary">
                        Testmail senden
                    </button>
                </p>
            </form>
        </div>
        <script>
        ( function () {
            const port  = document.getElementById( 'port' );
            const radios = document.querySelectorAll( 'input[name="encryption"]' );
            const defaults = { tls: 587, ssl: 465, none: 25 };

            radios.forEach( function ( radio ) {
                radio.addEventListener( 'change', function () {
                    port.value = defaults[ this.value ];
                } );
            } );
        } )();
        </script>
        <?php
    }
}
