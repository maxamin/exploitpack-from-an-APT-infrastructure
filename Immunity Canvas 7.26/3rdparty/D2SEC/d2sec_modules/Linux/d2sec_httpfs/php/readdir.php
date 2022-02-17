if (($handle = @opendir('%s')) != false) {
    while (false !== ($entry = readdir($handle))) {
		  echo "$entry\n";
    }
    closedir($handle);
}
else {
   $err = error_get_last();
   echo 'error: ' . $err['message'];
}