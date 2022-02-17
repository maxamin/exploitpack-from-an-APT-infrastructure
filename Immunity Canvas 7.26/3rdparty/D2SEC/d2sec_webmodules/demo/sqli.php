<?php

error_reporting(0);
$link = mysql_connect('localhost', 'root', 'testtest');
mysql_select_db("mysql");
$q = "SELECT user FROM mysql.user WHERE max_user_connections >= ${_REQUEST['pwn']}";
//$fd = fopen("/tmp/query.txt", "a");
//fwrite($fd, "QUERY: $q\n");
//fclose($fd);
$res = mysql_query($q) or print(mysql_error());
$row = mysql_fetch_array($res);
print "<xmp>";
print "Result: [".($row[0])."]";

$res = mysql_query($_REQUEST['query']) or print(mysql_error());
?>
