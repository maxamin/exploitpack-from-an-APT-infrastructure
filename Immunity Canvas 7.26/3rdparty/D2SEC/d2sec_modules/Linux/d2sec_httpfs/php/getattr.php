$stat = @stat('%s');
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
	echo $stat['ctime'];
}
else {
	$err = error_get_last();
	echo 'error: ' . $err['message'];
}