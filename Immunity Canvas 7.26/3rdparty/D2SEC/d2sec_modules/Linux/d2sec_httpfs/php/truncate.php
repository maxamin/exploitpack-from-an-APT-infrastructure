$path = '%s';
$size = %d;

if (($fp = fopen($path, 'a+b')) === FALSE ||
    ftruncate($fp, $size) === FALSE) {
   $err = error_get_last();
   echo 'error: ' . $err['message'];
}
if ($fp !== FALSE) {
   fclose($fp);
}