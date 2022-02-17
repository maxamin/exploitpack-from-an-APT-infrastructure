$path = '%s';
$length = %d;
$offset = %d;

if (($fp = @fopen($path, 'rb')) !== false) {
	@fseek($fp, $offset, SEEK_SET);
	for ($i = 0; $i < $length;) {
		$data = fread($fp, $length - $i);
		if ($data === FALSE)
			break;
		$len = strlen($data);
		if ($len === 0)
			break;
		echo $data;
		$i += $len;
	}
	@fclose($fp);
}
else {
   $err = error_get_last();
   echo 'error: ' . $err['message'];
}
