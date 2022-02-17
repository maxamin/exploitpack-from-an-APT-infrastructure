if (@mkdir('%s', %d) === FALSE) {
   $err = error_get_last();
   echo 'error: ' . $err['message'];
}