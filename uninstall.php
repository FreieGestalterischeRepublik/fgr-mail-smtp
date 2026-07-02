<?php
// Wird von WordPress aufgerufen, wenn das Plugin gelöscht wird
if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
    exit;
}

if ( is_multisite() ) {
    delete_site_option( 'fgr_smtp' );
} else {
    delete_option( 'fgr_smtp' );
}
