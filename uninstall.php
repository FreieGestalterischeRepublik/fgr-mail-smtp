<?php
// Wird von WordPress aufgerufen, wenn das Plugin gelöscht wird
if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
    exit;
}

delete_option( 'fgr_smtp' );
