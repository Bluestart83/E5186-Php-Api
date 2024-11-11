<?php

/**
	Api client for Huawei modem like E5186
	Ported partially from https://github.com/pablo/huawei-modem-python-api-client/blob/master/huaweisms/
*/
class HuaweiModemApiClient
{
	private $modem_host;
	private $uri_scheme;
	private $verify;
	private $session_id = null;
	private $login_token = null;
	public $logged_in = false;
	private $proxy = null;
	private $tokens = [];
	private $cookie_file;

	public function __construct($modem_host = '192.168.8.1', $uri_scheme = 'http', $verify = true, $proxy = null, $cookie_file = null)
	{
		$this->modem_host = $modem_host;
		$this->uri_scheme = $uri_scheme;
		$this->verify = $verify;
		$this->proxy = $proxy;
		$this->cookie_file = $cookie_file;
		$this->tokens = [];
	}

	public function token()
	{
		if (empty($this->tokens)) {
			// Log a warning message if tokens are empty
			error_log("You ran out of tokens. You need to login again");
			return null;
		}
		// Return the last token and remove it from the array
		return array_pop($this->tokens);
	}

	private function getApiBaseUrl()
	{
		return "{$this->uri_scheme}://{$this->modem_host}/api";
	}

	private function commonHeaders()
	{
		$headers = [
			"X-Requested-With" => "XMLHttpRequest"
		];
		if ($this->session_id) {
			// Add the session cookie to headers if session ID is set
			$headers["Cookie"] = "SessionID={$this->session_id}";
		}
		return $headers;
	}

	function b64_sha256($data)
	{
		// Step 1: Hash the data with SHA-256
		$sha256Hash = hash("sha256", $data, true);
		// Step 2: Convert the binary hash to hexadecimal
		$hexHash = bin2hex($sha256Hash);
		// Step 3: Base64 encode the hexadecimal hash in a URL-safe way
		//return rtrim(strtr(base64_encode(hex2bin($hexHash)), '+/', '-_'), '=');
		//return rtrim(strtr(base64_encode($hexHash), '+/', '-_'), '=');
		return base64_encode($hexHash);
	}


	private function sendRequest($url, $data = "", $headers = [], $method = "POST")
	{
		$ch = curl_init($url);
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

		if ($method === "POST") {
			curl_setopt($ch, CURLOPT_POST, true);
			curl_setopt($ch, CURLOPT_POSTFIELDS, $data);
		}

		curl_setopt($ch, CURLOPT_HTTPHEADER, array_map(function ($key, $value) {
			return "$key: $value";
		}, array_keys($headers), $headers));

		if ($this->cookie_file != null) {
			curl_setopt($ch, CURLOPT_COOKIEJAR, $this->cookie_file);
			curl_setopt($ch, CURLOPT_COOKIEFILE, $this->cookie_file);
		}

		if ($this->proxy) {
			curl_setopt($ch, CURLOPT_PROXY, $this->proxy['host']);
			if (isset($this->proxy['port'])) {
				curl_setopt($ch, CURLOPT_PROXYPORT, $this->proxy['port']);
			}
			if (isset($this->proxy['username']) && isset($this->proxy['password'])) {
				curl_setopt($ch, CURLOPT_PROXYUSERPWD, "{$this->proxy['username']}:{$this->proxy['password']}");
			}
		}

		// Include headers in the output
		curl_setopt($ch, CURLOPT_HEADER, true);
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);


		// Define a callback function to process headers
		curl_setopt(
			$ch,
			CURLOPT_HEADERFUNCTION,
			function ($curl, $header) use (&$headers) {
				$len = strlen($header);
				$header = trim($header);

				// Ignore empty headers and the HTTP status line
				if (empty($header) || strpos($header, 'HTTP/') === 0) {
					return $len;
				}

				// Split the header into key and value
				list($key, $value) = explode(":", $header, 2) + [null, null];
				$key = trim($key);
				$value = trim($value);

				// Handle duplicate headers like Set-Cookie
				if (isset($headers[$key])) {
					if (is_array($headers[$key])) {
						$headers[$key][] = $value;
					} else {
						$headers[$key] = [$headers[$key], $value];
					}
				} else {
					$headers[$key] = $value;
				}

				return $len;
			}
		);

		$headers  = [];
		$body = '';
		$response = curl_exec($ch);

		// Check for errors
		if (curl_errno($ch)) {
			throw new Exception('cURL error: ' . curl_error($ch));
		} else {
			// Get header size
			$header_size = curl_getinfo($ch, CURLINFO_HEADER_SIZE);

			// Separate headers and body
			$header_text = substr($response, 0, $header_size);
			$body = substr($response, $header_size);

			// Parse headers into an associative array


			// Output headers and response body
			//echo "Headers:\n";
			//print_r($headers);
			//echo "\nBody:\n";
			//echo $body;
		}

		// Close the cURL session
		curl_close($ch);

		// Check for the "__RequestVerificationToken" header
		if (isset($headers['__RequestVerificationToken'])) {
			// Split the token by "#" and remove empty values
			$toks = array_filter(explode("#", $headers['__RequestVerificationToken']));

			// Process the tokens based on their count
			if (count($toks) > 1) {
				$this->tokens = array_slice($toks, 2);
			} elseif (count($toks) === 1) {
				$this->tokens[] = $toks[0];
			}
		}

		// Check for the "SessionID" cookie
		// Define a regular expression to capture the SessionID , prevent from using cookie file!
		if (isset($headers['Set-Cookie'])) {
			if (preg_match('/SessionID=([^;]+)/', $headers['Set-Cookie'], $matches)) {
				$sessionID = $matches[1];
				$this->session_id = $sessionID;
				//echo "SessionID: " . $sessionID;
			} else {
				//echo "SessionID not found in Set-Cookie header.";
			}
		} else {
			//echo "Set-Cookie header not found.";
		}

		return $body;
	}

	private function check_error($elem)
	{
		// Check if the element name is "error"
		if ($elem->getName() !== "error") {
			return null;
		}

		// Get the code and message elements
		$code = isset($elem->code) ? (string)$elem->code : null;
		$message = isset($elem->message) ? (string)$elem->message : null;

		// Return the error details
		return [
			"type" => "error",
			"error" => [
				"code" => $code,
				"message" => $message,
			],
		];
	}

	private function parseXmlResponse($response, $basic = true)
	{
		$xml = simplexml_load_string($response);
		if ($xml === false) {
			throw new Exception("Failed to parse XML response.");
		}

		// Check if the <error> element exists
		if ($xml->getName() == 'error') {
			$result = $this->check_error($xml);
			//print_r($result);
			return $result;
		} else if ($basic) { // Wait for OK child
			//echo "No error element found.\n";
			return (string) $xml[0];
		} else {
			//echo "No error element found.\n";
			return $xml[0];
		}
		//xml version="1.0" encoding="UTF-8"><response>OK</response>''''

		/*
		return {
        	"type": "response",
			"response": get_dictionary_from_children(xmldoc.documentElement),
		}*/
	}

	private function getToken()
	{
		$url = "{$this->getApiBaseUrl()}/webserver/SesTokInfo";
		$response = $this->sendRequest($url, "", $this->commonHeaders(), "GET");

		$xml = simplexml_load_string($response);
		if ($xml === false || !isset($xml->SesInfo) || !isset($xml->TokInfo)) {
			throw new Exception("Failed to retrieve session token and session ID.");
		}

		// Extract the session ID from SesInfo
		$session_info = (string) $xml->SesInfo;
		$session_id_parts = explode("=", $session_info);
		$this->session_id = count($session_id_parts) > 1 ? $session_id_parts[1] : $session_id_parts[0];

		// Set the login token from TokInfo
		$this->login_token = (string) $xml->TokInfo;
	}

	public function login($username, $password)
	{
		// Retrieve the session token and session ID first
		$this->getToken();


		//$hash =  hash("sha256", $password, true);
		$hash2 = $this->b64_sha256($password);
		$same  = $hash2 ==  '101559fcb2c1de178c7bf829297e667404a47f6c400178a3195dbb3f2b06366e';

		//$token = 'Xs/Owd5jN/9a01Mj/tsX6NBDJgXu//Mb';
		//$password_value = $this->b64_sha256($username . $this->b64_sha256($password) .  $token );
		// Prepare hashed password with retrieved login token
		$password_value = $this->b64_sha256($username . $this->b64_sha256($password) . $this->login_token);

		$xml_data = <<<XML
<?xml version="1.0" encoding="UTF-8"?>
<request>
    <Username>{$username}</Username>
    <Password>{$password_value}</Password>
    <password_type>4</password_type>
</request>
XML;

		$headers = $this->commonHeaders();
		$headers["__RequestVerificationToken"] = $this->login_token;

		$response = $this->sendRequest("{$this->getApiBaseUrl()}/user/login", $xml_data, $headers, "POST");

		$ret = $this->parseXmlResponse($response);
		if ($ret === "OK") {
			$this->logged_in = true;
		} else {
			// 108006: Username or Password wrong
			throw new Exception("Login failed: " . $response);
		}
	}

	public function reboot()
	{
		if (!$this->logged_in) {
			throw new Exception("You must be logged in to reboot the modem.");
		}

		$url = "{$this->getApiBaseUrl()}/device/control";
		$headers = $this->commonHeaders();
		$headers["__RequestVerificationToken"] = $this->token();

		$xml_data = <<<XML
<?xml version="1.0" encoding="UTF-8"?>
<request>
    <Control>1</Control>
</request>
XML;

		$response = $this->sendRequest($url, $xml_data, $headers, "POST");

		if ($this->parseXmlResponse($response) === "OK") {
			echo "Modem reboot initiated successfully.\n";
		} else {
			throw new Exception("Failed to initiate modem reboot: " . $response);
		}
	}

	function check_response_headers($resp)
	{
		// Check for the "__RequestVerificationToken" header
		if (isset($resp['headers']['__RequestVerificationToken'])) {
			// Split the token by "#" and remove empty values
			$toks = array_filter(explode("#", $resp['headers']['__RequestVerificationToken']));

			// Process the tokens based on their count
			if (count($toks) > 1) {
				$this->tokens = array_slice($toks, 2);
			} elseif (count($toks) === 1) {
				$this->tokens[] = $toks[0];
			}
		}

		// Check for the "SessionID" cookie
		if (isset($resp['cookies']['SessionID'])) {
			$this->session_id = $resp['cookies']['SessionID'];
		}
	}

	function send_sms($dest, $msg)
	{
		$this->sms_send($dest, $msg);
	}

	function sms_send($dest, $msg)
	{
		//$this->getToken();


		// $this->session_id = 'pWnMPN7WBts+YNmzDAmmGgaUnzoX9Nd6/BkkQUn9PpEMJsLIzCowAMTRJUYNnnJ+FzZowg5Kemcg2gQDs1m5PnZr8iSUD+yHAHe3J1MwIhUFPju5SG8F9f2Bc29UcNxv';
		//   $this->login_token = 'Ia3Q6h5KPhAgUN/gksnrXvEXSaASEQ3F';


		// Get the current date and time in the required format
		$now = new DateTime();
		$now_str = $now->format("Y-m-d H:i:s");

		// Ensure $dest is an array of phone numbers
		$dest = is_string($dest) ? [$dest] : $dest;

		// Create the XML content for phone numbers
		$phones_content = "";
		foreach ($dest as $phone) {
			$phones_content .= "<Phone>" . htmlspecialchars($phone) . "</Phone>\n";
		}

		// Construct the XML payload
		$xml_data = sprintf(
			'<request>
                <Index>-1</Index>
                <Phones>%s</Phones>
                <Sca></Sca>
                <Content>%s</Content>
                <Length>%d</Length>
                <Reserved>1</Reserved>
                <Date>%s</Date>
            </request>',
			$phones_content,
			htmlspecialchars($msg),
			strlen($msg),
			-1 //$now_str
		);


		$headers = $this->commonHeaders();
		$headers["__RequestVerificationToken"] = $this->token();

		$response = $this->sendRequest("{$this->getApiBaseUrl()}/sms/send-sms", $xml_data, $headers, "POST");

		$ret = $this->parseXmlResponse($response);
		if ($ret === "OK") {
			$this->logged_in = true;
		} else {
			// 108006: Username or Password wrong
			throw new Exception("SMS send failed: " . $response);
		}
	}


	/**
	 * Gets available SMS from the router.
	 *
	 * @param object $ctx ApiCtx object.
	 * @param int $box_type 1 for inbox, 2 for outbox.
	 * @param int $page Page number during pagination (used with qty). Start at 1 
	 * @param int $qty Maximum number of items per page. (max 50)
	 * @param bool $unread_preferred If true, unread SMS messages are listed first;
	 *                               otherwise, they are listed by date in descending order.
	 * @return SimpleXMLElement A collection of SMS records.
	 */
	function sms_get_all($box_type = 1, $page = 1, $qty = 2, $unread_preferred = true)
	{
		// Construct the XML payload
		$xml_data = "
        <request>
            <PageIndex>$page</PageIndex>
            <ReadCount>$qty</ReadCount>
            <BoxType>$box_type</BoxType>
            <SortType>0</SortType>
            <Ascending>0</Ascending>
            <UnreadPreferred>" . ($unread_preferred ? 1 : 0) . "</UnreadPreferred>
        </request>
    ";


		$headers = $this->commonHeaders();
		$headers["__RequestVerificationToken"] = $this->token();

		$response = $this->sendRequest("{$this->getApiBaseUrl()}/sms/sms-list", $xml_data, $headers, "POST");

		$xml = $this->parseXmlResponse($response, false);
		//echo "xml=";
		print_r($xml);
		// Process response
		if ($xml->getName() === 'response') {
			if ($xml->Count !== '0') {
				if (
					is_array($xml->Messages->Message) &&
					isset($xml->Messages->Message->id)
				) {
					$xml->Messages->Message = [$xml->Messages->Message];
				}
			}
			// Return JSON encoded response
			return $xml;
		} else {
			// 108006: Username or Password wrong
			throw new Exception("Gest SMS failed: " . $response);
		}
	}

	function sms_delete($index)
	{
		// Construct the XML payload
		$xml_data =
			"<request>
				<Index>$index</Index>
			</request>";


		$headers = $this->commonHeaders();
		$headers["__RequestVerificationToken"] = $this->token();

		$response = $this->sendRequest("{$this->getApiBaseUrl()}/sms/delete-sms", $xml_data, $headers, "POST");
		//print_r($response);
		$xml = $this->parseXmlResponse($response, true);
		//echo "xml=";
		//print_r($xml);
		// Process response
		if ($xml === 'OK') {
			return $xml;
		} else {
			// 108006: Username or Password wrong
			throw new Exception("Gest SMS failed: " . $response);
		}
	}

	function sms_set_read($index)
	{
		// Construct the XML payload
		$xml_data =
			"<request>
				<Index>$index</Index>
			</request>";


		$headers = $this->commonHeaders();
		$headers["__RequestVerificationToken"] = $this->token();

		$response = $this->sendRequest("{$this->getApiBaseUrl()}/sms/set-read", $xml_data, $headers, "POST");
		//print_r($response);
		$xml = $this->parseXmlResponse($response, true);
		//echo "xml=";
		//print_r($xml);
		// Process response
		if ($xml === 'OK') {
			return $xml;
		} else {
			// 108006: Username or Password wrong
			throw new Exception("Gest SMS failed: " . $response);
		}
	}

	function sms_count()
	{
		// Construct the XML payload


		$headers = $this->commonHeaders();
		$headers["__RequestVerificationToken"] = $this->token();

		$response = $this->sendRequest("{$this->getApiBaseUrl()}/sms/sms-count", null, $headers, "GET");
		//print_r($response);
		$xml = $this->parseXmlResponse($response, false);
		//echo "xml=";
		//print_r($xml);
		// Process response
		if ($xml->getName() === 'response') {
			return $xml;
		} else {
			// 108006: Username or Password wrong
			throw new Exception("Gest SMS failed: " . $response);
		}
	}
}
