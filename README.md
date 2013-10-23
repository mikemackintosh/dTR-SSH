dTR-SSH
=======

dTR-SSH is a wrapper class for SSH functions in PHP. It was designed to manage the blocking/non-blocking of both OpenSSH2 and net-sshd daemons to help manage responses, and allow an OOP interface for use in other projects.

-----------------------

### Example
	
	use dTR\Networking;
	
	$options = array(
		 'host' => $remote_host,
		 'port' => '22',
		 'auth' =>
		 array(
		 		'type' => SSH::PASS,
		 		'username' => 'admin',
		 		'password' => '',
		 )
	); 	
		
	try{
		$ssh = new SSH($options);
		$ssh->connect();
			
		if($ssh->authenticate()){	
			echo $ssh->exec('ls -la');
		}
								
		$ssh->disconnect();
					
	}
	catch(\Exception $e){
		echo $e->getMessage();
	}
