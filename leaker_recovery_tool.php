<?php
	
	// Recovery tool for Leaker v2.0
	// https://github.com/antibiotics11/Leaker
	
	@error_reporting(E_ALL ^ E_NOTICE ^ E_WARNING); 
	
	if (isset($_SERVER["argv"][1])) {
		if (!is_file($_SERVER["argv"][1])) {
			echo "\033[1;31m ERROR: Input argument is not a file. \033[0m".PHP_EOL;
			exit();
		}
		if (!is_readable($_SERVER["argv"][1])) {
			echo "\033[1;31m ERROR: Input file is not readable. \033[0m".PHP_EOL;
			exit();
		}
	} else {
		echo "\033[1;31m ERROR: No input file detected. Try \"sudo php leaker_recovery_tool.php leaker.php\" \033[0m".PHP_EOL;
		exit();
	}
	
	echo "\033[1;32m Recovery Tool for leaker v2.0 \033[0m".PHP_EOL;
	
	echo "\033[1;32m Searching leaker files in this system... \033[0m".PHP_EOL;
	$leakerfiles = search_leakerfiles();
	if (count($leakerfiles) <= 0) {
		echo "\033[1;32m ERROR: No leaker files found. \033[0m".PHP_EOL;
		exit();
	}
	echo "\033[1;32m Total ".count($leakerfiles)." files found. \033[0m".PHP_EOL;
	
	$leaker_script = file($_SERVER["argv"][1]);
	$shm_key = search_shmkey($leaker_script);
	$decryption_key = base64_decode((string)get_decryption_key($shm_key));
	if ($decryption_key == NULL || empty($decryption_key)) {
		echo "\033[1;31m ERROR: Decryption key not found in the shared memory. \033[0m".PHP_EOL;
		exit();
	}
	echo "\033[1;32m Decryption key \"".$decryption_key."\" found. \033[0m".PHP_EOL;
	
	foreach($leakerfiles as $file) {
		file_decrypt($decryption_key, $file);
		echo "\033[1;32m ".substr($file, 1)." recoverd. \033[0m".PHP_EOL;
		
		$fileinfo = pathinfo($file);
		if ($fileinfo["filename"] == "index" && file_exists($fileinfo["dirname"].DIRECTORY_SEPARATOR."index.php")) {
			rename($fileinfo["dirname"].DIRECTORY_SEPARATOR."index.php", $fileinfo["dirname"].DIRECTORY_SEPARATOR."index.php.old.leaker");
		}
		rename($file, $fileinfo["dirname"].DIRECTORY_SEPARATOR.$fileinfo["filename"].".php");
	}
	 
	function search_leakerfiles() {
		$leakerfiles = array();
		$iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator("/"));
		foreach ($iterator as $file) {
			$filename = $file->getPathname();
			if (!is_file($filename)) {
				continue;
			}
			$fileinfo = pathinfo($filename);
			if (strtolower($fileinfo["extension"]) == "leaker") {
				array_push($leakerfiles, $filename);
			}
		}
		return $leakerfiles;
	}
	
	function search_shmkey($leaker_script) {
		for ($i = 0; $i < count($leaker_script); $i++) {
			if (strpos($leaker_script[$i], "define") === false) {
				continue;
			} 
			if (strpos($leaker_script[$i], "_SHMKEY") !== false) {
				$shm_key_tmp = explode(",", $leaker_script[$i]);
				$shm_key = preg_replace("/[^A-Za-z0-9-]/", "", $shm_key_tmp[1]);
				return $shm_key;
				break;
			}
		}
		return NULL;
	}
	
	function get_decryption_key($shm_key) {
		$shm_id = shmop_open(hexdec($shm_key), "a", 0644, 255);
		$shm_size = shmop_size($shm_id);
		$decryption_key_hashed = shmop_read($shm_id, 0, $shm_size);
		if (!empty($decryption_key_hashed)) {
			return (string)$decryption_key_hashed;
		} 
		return NULL;
	}
	
	function file_decrypt($decryption_key, $file) {
		$contents = file_get_contents($file);
		$iv = chr(0x0).chr(0x0).chr(0x0).chr(0x0).chr(0x0).chr(0x0).chr(0x0).chr(0x0).chr(0x0).chr(0x0).chr(0x0).chr(0x0).chr(0x0).chr(0x0).chr(0x0).chr(0x0);
		$decrypted_contents = openssl_decrypt($contents, "aes-256-cbc", $decryption_key, OPENSSL_RAW_DATA, $iv);
		$fp = fopen($file, "r+");
		fwrite($fp, $decrypted_contents);
		fclose($fp);
		return;
	}
	
	