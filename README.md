
# Php HTTP API client for Huawei Modems

This is a PHP library to interact with a Huawei modem over HTTP API. Ported partially from [huawei-modem-python-api-client] (https://github.com/pablo/huawei-modem-python-api-client/tree/master)

The library has been tested on these devices:
* E8372
* E5180, E5186
* E8372
* B315
* B529s-23a
* H122-373 (HUAWEI 5G CPE Pro 2 locoked to the UK Network Three)

Please let me know if you tested it successfully with other modems as well.

## Currently Supported

* webserver
   * Not Done
* user
   * login: creates a new session on the HTTP API
   * logout: deletes current session on the HTTP API
* sms
   * sms_get: get information from boxes: inbox, outbox
   * send_sms: sends an SMS through device's modem
   * sms_delete: deletes an sms from one of their boxes
   * sms_count: get the sms count on each box
   * sms_set_read: set the sms status to read
* ussd
   * Not Done
* wlan:
    * Not Done
* dialup:
    * Not Done
* device:
    * reboot: reboots the modem



### Example
```php
include 'HuaweiModemApiClient.php';
try {
	/* $proxy = [
        "host" => '127.0.01',
        "port" => 8080,
        "username" => null,
        "password" => null
    ];*/

	$modemClient = new HuaweiModemApiClient("192.168.8.1", "http", true, $proxy);
	$modemClient->login("admin", "myPassword");
	echo "Login successful.\n";
	//$modemClient->send_sms("+33600000000", "Hello !1");
	//$xml = $modemClient->reboot();
	$xml = $modemClient->sms_get_all();
	//$xml = $modemClient->sms_delete(40152);
	//$xml = $modemClient->sms_count();
	//$xml = $modemClient->sms_set_read(40151);
	print_r(json_encode($xml));

} catch (Exception $e) {
	echo "Operation failed: " . $e->getMessage();
}

```


## Contributing

Send me a PM if you want to contribute. 

## Authors

* **Arnaud LIGUORI** - *Owner* - [Bluestart83](https://github.com/Bluestart83)
* Big thanks to **Pablo Santa Cruz** [https://raw.githubusercontent.com/pablo/huawei-modem-python-api-client](https://github.com/pablo/huawei-modem-python-api-client/tree/master)

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details
