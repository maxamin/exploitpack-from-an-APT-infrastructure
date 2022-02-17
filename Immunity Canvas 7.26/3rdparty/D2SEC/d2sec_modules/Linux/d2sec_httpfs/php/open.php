if (@fopen('%s', '%s') === FALSE) {
   $err = error_get_last();
   echo 'error: ' . $err['message'];
}
else {
	 @fclose($fp);
}