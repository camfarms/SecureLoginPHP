<?php
function usage(){
	echo "\033[92mUsage: Type a command below to begin
		exit   ........................................  exit this script
		list   ........................................  list all saved login profiles
		add, [OPTIONAL NAME] ..........................  create a new profile, and save its encrypted login information		
		del, [OPTIONAL NAME] ..........................  delete an existing password
		look,  [OPTIONAL NAME] ........................  lookup the plaintext username and password of a profile
		update, [OPTIONAL NAME] .......................  update a profile's name, and plaintext username and password
			\033[39m\n\n";
}

function mainmenu(){
	echo "\033[39mReturning to main menu...\n";
	usage();
}

function encrypt($toencrypt){
	global $key;
	$ivlen = openssl_cipher_iv_length($cipher="AES-256-CBC");
	$iv = openssl_random_pseudo_bytes($ivlen);
	$ciphertext_raw = openssl_encrypt($toencrypt, $cipher, $key, $options=OPENSSL_RAW_DATA, $iv);
	$hmac = hash_hmac('sha256', $ciphertext_raw, $key, $as_binary=true);
	$ciphertext = base64_encode( $iv.$hmac.$ciphertext_raw );
	return $ciphertext;
}
	
function decrypt($todecrypt){
	global $key;
	$c = base64_decode($todecrypt);
	$ivlen = openssl_cipher_iv_length($cipher="AES-256-CBC");
	$iv = substr($c, 0, $ivlen);
	$hmac = substr($c, $ivlen, $sha2len=32);
	$ciphertext_raw = substr($c, $ivlen+$sha2len);
	$original_plaintext = openssl_decrypt($ciphertext_raw, $cipher, $key, $options=OPENSSL_RAW_DATA, $iv);
	$calcmac = hash_hmac('sha256', $ciphertext_raw, $key, $as_binary=true);
	if (hash_equals($hmac, $calcmac))//PHP 5.6+ timing attack safe comparison
	{
	    return $original_plaintext;
	}
}

interface Command{
	public function execute($args);
	public function isValid($args);
	public function help();
	public function error();
}

$exit = new class implements Command{
	public function execute($args){
		global $handle;
		echo "Exiting...";
		fclose($handle);
		exit;
	}

	public function isValid($args){
		return count($args) == 1;
	}

	public function help(){
		echo "exit - exits the program. Accepts no arguments\n";
	}

	public function error(){
		echo "\033[91mERROR: Invalid exit command syntax\n";
		echo "\033[39m";
	}
};

$list = new class implements Command{
	public function execute($args){
		echo "The following profiles are currently saved:\n";
		$file = fopen("encrypted_passwords.txt", "r");
		while(!feof($file)){
			$line = fgets($file);
			$arr = explode(':', $line);
			echo "\033[95m\t".$arr[0]."\n";
		}
		fclose($file);
		mainmenu();
	}

	public function isValid($args){
		return count($args) == 1;
	}

	public function help(){
		echo "list - lists all currently saved profiles. Accepts no arguments\n";
	}

	public function error(){
		echo "\033[91mERROR: Invalid list command syntax\n";
		echo "\033[39m";
	}
};

$add = new class implements Command{
	public function execute($args){
		global $handle;

		if(count($args) == 1){
			echo "What you would like to name this login profile?\n";
			$name = trim(fgets($handle));
		}
		else{
			$name = trim($args[1]);
		}

		$found = false;
		$file = file("encrypted_passwords.txt");
		foreach($file as $line){
			$arr = explode(':', $line);
			if($arr[0] == $name){
				$found = true;
			}
		}
		if($found == true){
			echo "\033[91mERROR: There already exists a profile with this name. Please choose a unique name.\n";
			mainmenu();
			return;
		}

		echo "Please enter the plain text username and password, deliminated by a single space (ex. Username123 Password123)\n";
		$line = fgets($handle);
		$arr = explode(' ', $line);
		$user = $arr[0];
		$pass = $arr[1];

		if(trim($user) != false && trim($pass) != false && count($arr) == 2){
			$file = fopen("encrypted_passwords.txt", "a") or die("Unable to open file!");
			echo "\033[96m************************* ENCRYPTING LOGIN INFORMATION *************************\n";
			$e_user = encrypt($user);
			$e_pass = encrypt($pass);
			fwrite($file, $name . ":" . $e_user . ":" . $e_pass . "\n");
			fclose($file);
			echo "\033[39mEncrypted and Saved:\033[95m\n" . "\t" . $name . " => " . $user . " " . $pass . "\n";
			mainmenu();
		}
		else{
			echo "\033[91mERROR: Invalid inputs for username and password.\nExpected: 'string string'\nReceived: {$line}";
			mainmenu();
		}

	}

	public function isValid($args){
		return (count($args) == 1 || count($args) == 2);
	}

	public function help(){
		echo "add[, OPTIONAL NAME] - adds a new profile. Accepts the name of the new profile, or nothing\n";
	}

	public function error(){
		echo "\033[91mERROR: Invalid add command syntax\n";
		echo "\033[39m";
	}
};

$del = new class implements Command{
	public function execute($args){
		global $handle;

		if(count($args) == 1){
			echo "What is the name of the login profile you want to delete?\n";
			$name = trim(fgets($handle));
		}
		else{
			$name = trim($args[1]);
		}

		$found = false;
		$tokeep = array();
		$removed = "";

		$file = file("encrypted_passwords.txt");
		foreach($file as $line){
			$arr = explode(':', $line);
			if($arr[0] == $name){
				$found = true;
				$removed = $line;
			}
			else{
				$tokeep[] = $line;
			}
		}
		if($found == false){
			echo "\033[91mERROR: Given name not found; check capitalization.\nExpected: a name that matches an output in list exactly.\nReceived: {$name}\n";
			mainmenu();
			return 0;
		}
		else{
			$fp = fopen("encrypted_passwords.txt", "w+");
			flock($fp, LOCK_EX);
			foreach($tokeep as $line) {
			    fwrite($fp, $line);
			}
			flock($fp, LOCK_UN);
			fclose($fp);
			$arr = explode(':', $removed);
			$name = $arr[0];
			$user = $arr[1];
			$pass = $arr[2]; 
			echo "The following login information has been deleted:\033[95m\n" . "\t" . $name . " => " . $user . " : " . $pass . "\n";

			$updating = $args[2];
			if(!$updating){
				mainmenu();
			}
			return 1;
		}
	}

	public function isValid($args){
		return (count($args) == 1 || count($args) == 2);
	}

	public function help(){
		echo "del[, OPTIONAL NAME] - deletes an existing profile. Accepts the name of the profile, or nothing\n";
	}

	public function error(){
		echo "\033[91mERROR: Invalid del command syntax\n";
		echo "\033[39m";
	}
};

$look = new class implements Command{
	public function execute($args){
		global $handle;

		if(count($args) == 1){
			echo "What you would like to name this login profile?\n";
			$name = trim(fgets($handle));
		}
		else{
			$name = trim($args[1]);
		}

		$found = false;

		$file = fopen("encrypted_passwords.txt", "r") or die("Unable to open file!");
		while(!feof($file)){
			$line = fgets($file);
			$arr = explode(':', $line);
			if($arr[0] == $name){
				echo "\033[96m************************* DECRYPTING LOGIN INFORMATION *************************\n";
				$user=decrypt($arr[1]);
				$pass=decrypt($arr[2]);
				echo "\033[39mDecrypted and Returned:\n\t" . "\033[95m{$name}" . " => " . $user . " : " . $pass . "\n\n" ;
				$found = true;
			}
		}
		fclose($file);

		if($found == false){
			echo "\033[91mERROR: Given name not found; check capitalization.\nExpected: a name that matches an output in list exactly.\nReceived: {$name}\n";
			mainmenu();
		}
		else{
			mainmenu();
		}
	}

	public function isValid($args){
		return (count($args) == 1 || count($args) == 2);
	}

	public function help(){
		echo "look[, OPTIONAL NAME] - looksup an existing profile's plaintext username and password. Accepts the name of the new profile, or nothing\n";
	}

	public function error(){
		echo "\033[91mERROR: Invalid look command syntax\n";
		echo "\033[39m";
	}
};

$update = new class implements Command{
	public function execute($args){
		global $del;
		global $add;
		global $handle;

		if(count($args) == 1){
			echo "What is the name of the login profile you want to update?\n";
			$name = trim(fgets($handle));
			array_push($args, $name);
		}
		else{
			$name = trim($args[1]);
		}

		array_push($args, true);

		if($del->execute($args) != 0){
			echo "\033[39mPlease enter the new name for this login profile:\n";
			$name = trim(fgets($handle));
			$add->execute(array("add", $name));
		}
	}

	public function isValid($args){
		return (count($args) == 1 || count($args) == 2);
	}

	public function help(){
		echo "update[, OPTIONAL NAME] - updates an existing profile's plaintext name, username and password. Accepts the name of the profile, or nothing\n";
	}

	public function error(){
		echo "\033[91mERROR: Invalid update command syntax\n";
		echo "\033[39m";
	}
};

//Map of acceptable commands 
$commands = array("exit" => $exit, "list" => $list, "add" => $add, "del" => $del, "look" => $look, "update" => $update);

//Open standard in
$handle = fopen ("php://stdin","r");
echo "Enter cryptographic key to encode and decode passwords:\n";
$key = trim(fgets($handle));
usage();

//user input loop
while(true){
	$in = trim(fgets($handle));
	$args = explode(',', $in);
	$command = $args[0];

	if (in_array($command, array_keys($commands))) {
		if($commands[$command]->isValid($args)){
			$commands[$command]->execute($args);
		}
		else{
			$commands[$command]-> error();
			$commands[$command]->help();
			mainmenu();

		}
	}	
	else{
		echo "\033[91mERROR: Not a valid command.\n";
		mainmenu();
	}
}
?>
