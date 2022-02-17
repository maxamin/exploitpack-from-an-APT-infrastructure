$path = '%s';
$buf = base64_decode('%s');
$offset = %d;

if (($fp = fopen($path, 'a+b')) == FALSE) {
   $err = error_get_last();
   echo 'error: ' . $err['message'];
}
else {
	 fseek($fp, $offset, SEEK_SET);
	 for ($i = 0; $i < strlen($buf); $i += $written) {
	 	$written = fwrite($fp, substr($buf, $i));
		if ($written === FALSE || $written == 0)
			   break;
	}
	echo $i;
}
fclose($fp);