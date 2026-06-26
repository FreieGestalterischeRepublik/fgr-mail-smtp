<?php
defined( 'ABSPATH' ) || exit;

class FGR_SMTP_Settings {

    public function __construct() {
        add_action( 'admin_menu',    [ $this, 'add_menu' ] );
        add_action( 'admin_init',    [ $this, 'handle_save' ] );
        add_action( 'admin_init',    [ $this, 'handle_test_mail' ] );
        add_action( 'admin_notices', [ $this, 'show_notices' ] );
    }

    public function add_menu(): void {
        add_options_page(
            'FGR Mail SMTP',
            'FGR Mail SMTP',
            'manage_options',
            'fgr-mail-smtp',
            [ $this, 'render_page' ]
        );
    }

    // Einstellungen speichern
    public function handle_save(): void {
        if ( ! isset( $_POST['fgr_smtp_save'] ) ) return;
        check_admin_referer( 'fgr_smtp_save', 'fgr_smtp_nonce' );

        $mode = sanitize_key( $_POST['mailer_mode'] ?? 'smtp' );
        if ( ! in_array( $mode, [ 'phpmailer', 'smtp', 'ms365' ], true ) ) {
            $mode = 'smtp';
        }

        $enc = sanitize_key( $_POST['encryption'] ?? 'tls' );
        if ( ! in_array( $enc, [ 'none', 'ssl', 'tls' ], true ) ) {
            $enc = 'tls';
        }

        $existing = get_option( 'fgr_smtp', [] );

        // SMTP-Passwort nur überschreiben wenn ein neues eingegeben wurde
        $new_pass   = $_POST['password'] ?? '';
        $saved_pass = ( '' !== $new_pass )
            ? fgr_smtp_encrypt( $new_pass )
            : ( $existing['password'] ?? '' );

        // MS365 Client Secret nur überschreiben wenn ein neues eingegeben wurde
        $new_secret        = $_POST['ms365_secret'] ?? '';
        $saved_ms365_secret = ( '' !== $new_secret )
            ? fgr_smtp_encrypt( $new_secret )
            : ( $existing['ms365_secret'] ?? '' );

        $new_tenant = sanitize_text_field( $_POST['ms365_tenant'] ?? '' );
        $new_app_id = sanitize_text_field( $_POST['ms365_app_id'] ?? '' );

        // Gecachten Access-Token löschen wenn sich MS365-Zugangsdaten geändert haben
        if (
            ( $existing['ms365_tenant'] ?? '' ) !== $new_tenant ||
            ( $existing['ms365_app_id'] ?? '' ) !== $new_app_id ||
            '' !== $new_secret
        ) {
            delete_transient( 'fgr_ms365_token' );
        }

        update_option( 'fgr_smtp', [
            'mailer_mode'  => $mode,
            'host'         => sanitize_text_field( $_POST['host'] ?? '' ),
            'port'         => absint( $_POST['port'] ?? 587 ),
            'encryption'   => $enc,
            'username'     => sanitize_text_field( $_POST['username'] ?? '' ),
            'password'     => $saved_pass,
            'from_email'   => sanitize_email( $_POST['from_email'] ?? '' ),
            'from_name'    => sanitize_text_field( $_POST['from_name'] ?? '' ),
            'ms365_tenant' => $new_tenant,
            'ms365_app_id' => $new_app_id,
            'ms365_secret' => $saved_ms365_secret,
        ] );

        set_transient( 'fgr_smtp_notice', 'saved', 30 );
        wp_safe_redirect( admin_url( 'options-general.php?page=fgr-mail-smtp' ) );
        exit;
    }

    // Testmail verschicken
    public function handle_test_mail(): void {
        if ( ! isset( $_POST['fgr_smtp_test'] ) ) return;
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
            "Diese E-Mail wurde erfolgreich über FGR Mail SMTP verschickt.\n\nDie Verbindung funktioniert korrekt."
        );

        if ( $sent ) {
            set_transient( 'fgr_smtp_notice', 'test_ok:' . $to, 30 );
        } else {
            $msg = $last_error ?? 'Unbekannter Fehler – bitte Einstellungen prüfen.';
            set_transient( 'fgr_smtp_notice', 'test_err:' . $msg, 30 );
        }

        wp_safe_redirect( admin_url( 'options-general.php?page=fgr-mail-smtp' ) );
        exit;
    }

    // Admin-Meldungen anzeigen
    public function show_notices(): void {
        if ( ( $_GET['page'] ?? '' ) !== 'fgr-mail-smtp' ) return;

        $n = get_transient( 'fgr_smtp_notice' );
        if ( ! $n ) return;
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
    public function render_page(): void {
        if ( ! current_user_can( 'manage_options' ) ) return;

        $opt      = get_option( 'fgr_smtp', [] );
        $enc      = $opt['encryption'] ?? 'tls';
        $mode     = $opt['mailer_mode'] ?? 'smtp';
        $is_smtp  = ( 'smtp'  === $mode );
        $is_ms365 = ( 'ms365' === $mode );
        ?>
        <div class="wrap">
            <h1>FGR Mail SMTP</h1>
            <p style="color:#888;margin-top:-8px">aus der <em>Freien Gestalterischen Republik</em></p>

            <form method="post">
                <?php wp_nonce_field( 'fgr_smtp_save', 'fgr_smtp_nonce' ); ?>

                <!-- Versandmethode -->
                <table class="form-table" role="presentation">
                    <tr>
                        <th scope="row">Versandmethode</th>
                        <td>
                            <fieldset>
                                <label>
                                    <input type="radio" name="mailer_mode" value="phpmailer" <?php checked( $mode, 'phpmailer' ); ?>>
                                    Standard-Versand via PHP-Mailer
                                </label><br>
                                <label>
                                    <input type="radio" name="mailer_mode" value="smtp" <?php checked( $mode, 'smtp' ); ?>>
                                    SMTP-Server
                                </label><br>
                                <label>
                                    <input type="radio" name="mailer_mode" value="ms365" <?php checked( $mode, 'ms365' ); ?>>
                                    Microsoft 365 <span style="color:#888">(Graph API)</span>
                                </label>
                            </fieldset>
                        </td>
                    </tr>
                </table>

                <!-- SMTP-spezifische Felder -->
                <div id="fgr-smtp-fields"<?php echo $is_smtp ? '' : ' style="display:none"'; ?>>
                <table class="form-table" role="presentation">

                    <tr>
                        <th scope="row"><label for="smtp_preset">Anbieter-Vorlage</label></th>
                        <td>
                            <select id="smtp_preset">
                                <option value="">– Vorlage auswählen –</option>
                                <option value="fgr">FGR Mailserver</option>
                                <option value="strato">Strato</option>
                                <option value="ionos">IONOS</option>
                                <option value="1und1">1&amp;1</option>
                                <option value="hosteurope">HostEurope</option>
                                <option value="gmail">Gmail (App-Passwort)</option>
                                <option value="ms365smtp">Microsoft 365 (SMTP AUTH)</option>
                            </select>
                            <p class="description">Füllt Host, Port und Verschlüsselung automatisch aus.</p>
                        </td>
                    </tr>

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

                </table>
                </div><!-- #fgr-smtp-fields -->

                <!-- Microsoft 365 Graph API Felder -->
                <div id="fgr-ms365-fields"<?php echo $is_ms365 ? '' : ' style="display:none"'; ?>>
                <table class="form-table" role="presentation">

                    <tr>
                        <th scope="row"><label for="ms365_tenant">Tenant-ID</label></th>
                        <td>
                            <input type="text" id="ms365_tenant" name="ms365_tenant" class="regular-text"
                                   value="<?php echo esc_attr( $opt['ms365_tenant'] ?? '' ); ?>"
                                   placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx">
                            <p class="description">Verzeichnis-ID aus dem Azure-Portal → Azure Active Directory → Übersicht.</p>
                        </td>
                    </tr>

                    <tr>
                        <th scope="row"><label for="ms365_app_id">Application-ID</label></th>
                        <td>
                            <input type="text" id="ms365_app_id" name="ms365_app_id" class="regular-text"
                                   value="<?php echo esc_attr( $opt['ms365_app_id'] ?? '' ); ?>"
                                   placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx">
                            <p class="description">Client-ID der App-Registrierung im Azure-Portal.</p>
                        </td>
                    </tr>

                    <tr>
                        <th scope="row"><label for="ms365_secret">Client Secret</label></th>
                        <td>
                            <input type="password" id="ms365_secret" name="ms365_secret" class="regular-text"
                                   value="" autocomplete="new-password"
                                   placeholder="<?php echo ! empty( $opt['ms365_secret'] ) ? '(gespeichert – leer lassen, um es zu behalten)' : ''; ?>">
                            <p class="description">Client Secret der App-Registrierung (wird verschlüsselt gespeichert).</p>
                        </td>
                    </tr>

                </table>
                <div class="notice notice-info inline" style="margin:0 0 16px 206px;padding:8px 12px;max-width:600px">
                    <p><strong>Einrichtung im Azure-Portal:</strong><br>
                    App-Registrierungen → Neu → API-Berechtigungen → <code>Mail.Send</code> (Anwendungsberechtigung) hinzufügen → Administratorzustimmung erteilen → Zertifikate &amp; Geheimnisse → Neues Client Secret erstellen.</p>
                </div>
                </div><!-- #fgr-ms365-fields -->

                <!-- Absender (für SMTP und MS365) -->
                <div id="fgr-sender-fields"<?php echo ( 'phpmailer' === $mode ) ? ' style="display:none"' : ''; ?>>
                <table class="form-table" role="presentation">

                    <tr>
                        <th scope="row"><label for="from_email">Absender-E-Mail</label></th>
                        <td>
                            <input type="email" id="from_email" name="from_email" class="regular-text"
                                   value="<?php echo esc_attr( $opt['from_email'] ?? '' ); ?>"
                                   placeholder="info@example.com">
                            <?php if ( $is_ms365 ) : ?>
                            <p class="description">Muss dem Microsoft 365-Postfach entsprechen, für das die App <code>Mail.Send</code>-Berechtigung hat.</p>
                            <?php endif; ?>
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
                </div><!-- #fgr-sender-fields -->

                <p class="submit">
                    <button type="submit" name="fgr_smtp_save" class="button button-primary">
                        Einstellungen speichern
                    </button>
                </p>
            </form>

            <hr>

            <h2>Testmail senden</h2>
            <p>Testet die Verbindung mit den aktuell <strong>gespeicherten</strong> Einstellungen.</p>

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
            const port         = document.getElementById( 'port' );
            const host         = document.getElementById( 'host' );
            const preset       = document.getElementById( 'smtp_preset' );
            const encRadios    = document.querySelectorAll( 'input[name="encryption"]' );
            const modeRadios   = document.querySelectorAll( 'input[name="mailer_mode"]' );
            const smtpFields   = document.getElementById( 'fgr-smtp-fields' );
            const ms365Fields  = document.getElementById( 'fgr-ms365-fields' );
            const senderFields = document.getElementById( 'fgr-sender-fields' );
            const encDefaults  = { tls: 587, ssl: 465, none: 25 };

            const presets = {
                fgr:        { host: 'vps017.server001.datenfalke.biz', port: 587, enc: 'tls' },
                strato:     { host: 'smtp.strato.de',                  port: 465, enc: 'ssl' },
                ionos:      { host: 'smtp.ionos.de',                   port: 587, enc: 'tls' },
                '1und1':    { host: 'smtp.1und1.de',                   port: 587, enc: 'tls' },
                hosteurope: { host: 'smtp.hosteurope.de',              port: 465, enc: 'ssl' },
                gmail:      { host: 'smtp.gmail.com',                  port: 587, enc: 'tls' },
                ms365smtp:  { host: 'smtp.office365.com',             port: 587, enc: 'tls' },
            };

            function applyMode( value ) {
                smtpFields.style.display   = value === 'smtp'      ? '' : 'none';
                ms365Fields.style.display  = value === 'ms365'     ? '' : 'none';
                senderFields.style.display = value === 'phpmailer' ? 'none' : '';
            }

            encRadios.forEach( function ( radio ) {
                radio.addEventListener( 'change', function () {
                    port.value = encDefaults[ this.value ];
                } );
            } );

            modeRadios.forEach( function ( radio ) {
                radio.addEventListener( 'change', function () {
                    applyMode( this.value );
                } );
            } );

            preset.addEventListener( 'change', function () {
                const p = presets[ this.value ];
                if ( ! p ) return;
                host.value = p.host;
                port.value = p.port;
                encRadios.forEach( function ( radio ) {
                    radio.checked = ( radio.value === p.enc );
                } );
                preset.value = '';
            } );
        } )();
        </script>
        <?php
    }
}
