if (@posix_mknod('%s', %d, %d) === FALSE) {
   $err = error_get_last();
   echo 'error: ' . $err['message'];
}
