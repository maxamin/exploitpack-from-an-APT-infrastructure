if (@unlink('%s') === FALSE) {
   $err = error_get_last();
   echo 'error: ' . $err['message'];
}