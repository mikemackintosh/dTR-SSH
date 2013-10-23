<?php

/*
 * dTR-SSH is an OpenSSH2 library
 * 
 * @author Mike Mackintosh
 * @license http://opensource.org/licenses/gpl-license.php GNU General Public Licence
 * @copyright (c) 2012 - Mike Mackintosh
 * @version 0.7.4
 * @package dTR
 */

namespace dTR\Networking;

/**
 * dTR-SSH is a wrapper class for PHP's SSH commands. 
 * It supports SSH Exec, SCP and more.
 * 
 * Support for tunneling is currently under development.
 * 
 * @author Mike Mackintosh
 *
 */
class SSH{
	private static $connection;
	private static $shell;
	private $error;

	var $port = 22;

	const PASS = 'password';
	const PUBKEY = 'publickey';

	/**
	 * @param array $options
	 */
	public function __construct(Array $options){
		foreach($options as $opt => $value){
			$this->$opt = $value;
		}

	}

	/**
	 * @param unknown_type $reason
	 * @param unknown_type $message
	 * @param unknown_type $language
	 */
	final function xdisconnect($reason, $message, $language) {
		printf("Server disconnected with reason code [%d] and message: %s\n",
		$reason, $message);
	}

	/**
	 * @throws SSH2FailedToConnectIPException
	 * @throws SSH2FailedToConnectException
	 * 
	 * @return true|false
	 */
	final function connect( ){
		$callbacks = []; //array('disconnect' => 'xdisconnect');

		try{

			if(($fs = @fsockopen($this->host, (empty($this->port) ? 22 : $this->port), $errno, $errstr, 5)) == false){

				throw new SSH2FailedToConnectIPException($this->host, $this->port);

				fclose( $fs );

				return;
			}
				
			fclose( $fs );

				
			self::$connection = @ssh2_connect($this->host, (empty($this->port) ? 22 : $this->port), NULL, $callbacks);
			if(self::$connection === FALSE){

				throw new SSH2FailedToConnectException($this->host, $this->port);

				return false;

			}
				
			$this->fingerprint = @ssh2_fingerprint(self::$connection);

			return true;

		}
		catch(\Exception $e){
			echo $e->getMessage();

			return;
		}

	}

	/**
	 * @throws SSH2FailedToAuthenticate
	 * 
	 * @return boolean
	 */
	final function authenticate(){
		$method = "ssh2_auth_{$this->auth['type']}";
		try{
			if(@$method(self::$connection, $this->auth['username'], $this->auth['password']) === FALSE){
				throw new SSH2FailedToAuthenticate($this->host, $this->auth['username'], $this->auth['type']);
				return false;
			}else{
				return true;
			}
		}
		catch(\Exception $e){
			echo $e->getMessage();
		}
	}

	/**
	 * @param string $cmd
	 * @return boolean|string
	 */
	public function exec($cmd){
		$response = '';

		if(is_array($cmd)){
			foreach($cmd as $command){
				$stream = @ssh2_exec(self::$connection, $command);
				$errorStream = @ssh2_fetch_stream($stream, SSH2_STREAM_STDERR);

				/* Enable Blocking */
				@stream_set_blocking($errorStream, true);
				@stream_set_blocking($stream, true);

				/* Grab Response */
				$response .= stream_get_contents($stream);
				$this->error .= stream_get_contents($errorStream);
			}
		}
		else{
			$stream = ssh2_exec(self::$connection, $cmd);
			$errorStream = @ssh2_fetch_stream($stream, SSH2_STREAM_STDERR);
				
			/* Enable Blocking */
			@stream_set_blocking($errorStream, true);
			@stream_set_blocking($stream, true);
				
			/* Grab Response */
			$response .= stream_get_contents($stream);
			$this->error .= stream_get_contents($errorStream);
		}

		if(is_null($response)){
			return false;
		}

		return $response;
	}

	/**
	 * @param unknown_type $cmd
	 * @return Ambigous <NULL, string>
	 */
	final function shell($cmd){
		if(is_null(self::$shell)){
			self::$shell = ssh2_shell(self::$connection, 'vt102', null, 80, 40, SSH2_TERM_UNIT_CHARS);
		}

		$stream = self::$shell;

		$output = NULL;

		if(is_array($cmd)){
			foreach($cmd as $command){
				fwrite($stream, $command.PHP_EOL);
				sleep(2);

				while(( $res = stream_get_contents($stream, -1)) !== false){
					sleep(1);
					$output .= $res;
					if(strstr($res, '--- more ---')){
						fwrite($stream, "\n");
						sleep(2);
					}
					elseif($res == ''){
						break;
					}
				}
			}
		}
		else{
			fwrite($stream, $cmd.PHP_EOL);
			sleep(2);

			while(( $res = stream_get_contents($stream, -1)) !== false){
				sleep(1);
				$output .= $res;

				if(strstr($res, '--- more ---')){
					fwrite($stream, "\n");
					sleep(2);
				}
				elseif($res == ''){
					break;
				}
			}
				
		}

		if($cmd == 'exit'){
			self::$shell = NULL;
		}

		return $output;
	}

	/**
	 * @param unknown_type $remote
	 * @param unknown_type $local
	 */
	final function scpGet($remote, $local){
		ssh2_scp_recv(self::$connection, $remote, $local);
	}

	final function scpSend($src, $dst, $chmod = 0644){
		ssh2_scp_send(self::$connection, $src, $dst, $chmod);
	}

	/**
	 * @param unknown_type $remote_file
	 * @param unknown_type $local_file
	 * @throws Exception
	 */
	public function sftp($remote_file, $local_file)
	{
		$sftp = ssh2_sftp(self::$connection);

		$stream = @fopen("ssh2.sftp://$sftp$remote_file", 'r');
		if (! $stream)
			throw new Exception("Could not open file: $remote_file");
		$size = $this->getFileSize($remote_file);
		$contents = '';
		$read = 0;
		$len = $size;
		while ($read < $len && ($buf = fread($stream, $len - $read))) {
			$read += strlen($buf);
			$contents .= $buf;
		}
		 
		file_put_contents ($local_file, $contents);
		@fclose($stream);
	}

	/**
	 * @param unknown_type $file
	 * @return number
	 */
	public function getFileSize($file){
		$sftp = $this->sftp;
		return filesize("ssh2.sftp://$sftp$file");
	}

	/**
	 * 
	 */
	public function disconnect(){
		@ssh2_exec(self::$connection, 'exit');
	}

	/**
	 * @return string
	 */
	public function getLastError(){
		return $this->error;
	}
}


/**
 * dTR-SSH Exceptions
 * @author Mike Mackintosh
 *
 */
final class SSH2FailedToConnectException extends \Exception
{
	/**
	 * Sets the error message
	 *
	 * @todo Add logger output
	 */
	public function __construct($host, $port)
	{
		$message = "Failed to connect to host '{$host}' on port {$port}\n";

		// Call the parent constructor
		parent::__construct($message);
	}
}

/**
 * @author Mike Mackintosh
 *
 */
final class SSH2FailedToAuthenticate extends \Exception
{
	/**
	 * Sets the error message
	 *
	 * @todo Add logger output
	 */
	public function __construct($host, $username, $type)
	{
		$message = "Failed to authenticate '{$username}' by '{$type}' on host '{$host}'\n";

		// Call the parent constructor
		parent::__construct($message);
	}
}

/**
 * @author Mike Mackintosh
 *
 */
final class SSH2FailedToConnectIPException extends \Exception
{
	/**
	 * Sets the error message
	 *
	 * @todo Add logger output
	 */
	public function __construct($host, $port)
	{

		$message = "Failed to connect TCP/IP to host '{$host}' on port {$port}\n";

		// Call the parent constructor
		parent::__construct($message);
	}
}

