$path = '%s';
$entries = array();

if (($handle = @opendir($path)) != false) {
    while (false !== ($entry = readdir($handle))) {
		array_push($entries, $entry);
		echo "$entry\n";
    }
    closedir($handle);

	echo "\n";

	foreach ($entries as $entry) {
		$stat = @stat($path . DIRECTORY_SEPARATOR . $entry);
		if ($stat !== FALSE) {
			echo $stat['mode'] . ' ';
			echo $stat['ino'] . ' ';
			echo $stat['dev'] . ' ';
			echo $stat['nlink'] . ' ';
			echo $stat['uid'] . ' ';
			echo $stat['gid'] . ' ';
			echo $stat['size'] . ' ';
			echo $stat['atime'] . ' ';
			echo $stat['mtime'] . ' ';
			echo $stat['ctime'] . "\n";
		}
		else {
			$err = error_get_last();
			echo 'error: ' . $err['message'] . "\n";
		}
	}
}
else {
	$err = error_get_last();
	echo 'error: ' . $err['message'];
}