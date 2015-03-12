<?php
/**
 * generate.php
 * 
 * generate bitcoin address list file for ss-server/shadowsocks-libev.
 * 
 * @author Pan Zhibiao <panzhibiao@tangpool.com>
 * @since 2014-03
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful, 
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
date_default_timezone_set("Etc/GMT+0");

/*
 * config settings
 */
$_CFG = array();
// API Key for Chain.com
$_CFG['API-KEY-ID'] = "DEMO-4a5e1e4";
// server bitcoin address which receive btc transactions from customers 
$_CFG['server_baddress'] = "1LDjqcu3rSUkWjL219oZTsHg79S9K6vPwP";
$_CFG['cache_file']      = "/var/ss/{$_CFG['server_baddress']}-cached_txs.txt";
$_CFG['ss_server_file']  = "/var/ss/{$_CFG['server_baddress']}-list-ss-server.txt";
// price for one day, unit: satoshi
$_CFG['satoshi_per_day'] = 15000;

// load exist parsed txs
$exist_txs = get_exist_txs();
// try load new txs
$exist_txs = try_load_txs($exist_txs);
// write cache
put_exist_txs($exist_txs);
// dump file for ss-server
dump_for_ss_server($exist_txs);

exit;



function dump_for_ss_server($exist_txs) {
	global $_CFG;
	
	$address = array();
	$now = time();
	foreach ($exist_txs as $_tx) {
		// total days
		$days = bcdiv($_tx['value'], $_CFG['satoshi_per_day'], 2);
		
		// passed days
		assert($now > $_tx['timestamp']);
		$passed_days = bcdiv($now - $_tx['timestamp'], 86400, 2);
		
		if ($days <= $passed_days) {
			continue; // expired
		}
		$address[] = $_tx['address'];
	}
	$str = implode("\n", $address)."\n";
	LOGI("try dump ".count($address)." address to ss_server_file");
	
	$exist = file_exists($_CFG['ss_server_file']);
	$fp = fopen($_CFG['ss_server_file'], $exist ? "r+" : "w");
	if (!$fp) {
		LOGI("write file failure: {$_CFG['ss_server_file']}");
		return;
	} 

	// use flock when write file
	for ($i = 0; $i < 3; $i++) {  // try 3 times if need
		if (!flock($fp, LOCK_EX | LOCK_NB)) {
			sleep(3);continue;
		}
		ftruncate($fp, 0);
		fwrite($fp, $str);
		fflush($fp);
		flock($fp, LOCK_UN);
		
		LOGI("write file success: {$_CFG['ss_server_file']}");
		break;
	}
	fclose($fp);
}


function try_load_txs($exist_txs) {
	global $_CFG;
	
	$next_range = "";
	$run_flag = 1;
	while ($run_flag) {
		$res = get_address_list(100/*limit*/, $next_range);
		// 	var_dump($res);
		usleep(500000);  // 500ms

		if (empty($res['body'])) {
			break;  // no more records
		}
		if (!empty($res['next_range'])) {
			$next_range = $res['next_range'];
		} else {
			$run_flag = 0;  // next page is empty
		}

		$new_cnt = 0;
		foreach ($res['body'] as $_tx) {
			if (!empty($exist_txs[$_tx['hash']])) {
				continue;  // already exist
			}
			if (empty($_tx['inputs'][0]['addresses'][0])) {
				continue;  // can't get first input address
			}
			// use first input address as payment address
			$input_addr = $_tx['inputs'][0]['addresses'][0];

			// check server address
			foreach ($_tx['outputs'] as $_output) {
				if (empty($_output['addresses'][0]) || 
					$_output['addresses'][0] != $_CFG['server_baddress']) {
					continue;
				}
				$exist_txs[$_tx['hash']] = array(
						'address'   => $input_addr,
						'value'     => $_output['value'],
						'timestamp' => strtotime($_tx['chain_received_at']),
				);
				$new_cnt++;
				LOGI("find new tx: {$_tx['hash']}, value: {$_output['value']}, address: {$input_addr}, received: {$_tx['chain_received_at']}");
				break;
			}
		}

		if ($new_cnt == 0 && count($res['body']) > 0) {
			break;  // stop, mean all records are exists
		}
	}
	return $exist_txs;
}

function get_exist_txs() {
	global $_CFG;
	if (is_readable($_CFG['cache_file'])) {
		return json_decode(file_get_contents($_CFG['cache_file']), 1);
	}
	return array();
}

function put_exist_txs($exist_txs) {
	global $_CFG;
	if (!file_put_contents($_CFG['cache_file'], json_encode($exist_txs))) {
		LOGI("file put contents fail, file: {$_CFG['cache_file']}");
	}
}

function get_address_list($limit, $range) {
	global $_CFG;
	
	$res = array();
	$custom_headers = array();
	
	$url = "https://api.chain.com/v2/bitcoin/addresses/";
	$url .= rawurlencode($_CFG['server_baddress'])."/transactions?api-key-id=";
	$url .= rawurlencode($_CFG['API-KEY-ID']);
	$url .= "&limit=".intval($limit);
	if ($range != "") {
		$custom_headers[] = "Range: ".$range; 
	}
	
	$ch = curl_init();
	curl_setopt($ch, CURLOPT_AUTOREFERER, TRUE);
	curl_setopt($ch, CURLOPT_HEADER, 1);
	curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
	curl_setopt($ch, CURLOPT_FOLLOWLOCATION, TRUE);
	curl_setopt($ch, CURLOPT_URL, $url);
	curl_setopt($ch, CURLOPT_TIMEOUT, 30);
	if (!empty($custom_headers)) {
		curl_setopt($ch, CURLOPT_HTTPHEADER, $custom_headers);
	}
	
	$r = curl_exec($ch);
	$curl_errno = curl_errno($ch);
	$curl_error = curl_error($ch);
	curl_close($ch);
	
	if ($curl_errno > 0) {
		LOGI("curl request fail, errno: {$curl_errno}, error: {$curl_error}");
		return false;
	}
	
	list($header, $body) = explode("\r\n\r\n", $r, 2);
	// find next range
	preg_match("/Next-Range: ([^\r]*)/", $header, $matches);
	if (!empty($matches[1])) {
		$res['next_range'] = $matches[1];
	}
	$res['body'] = json_decode($body, 1);	
	return $res;
}


function LOGI($msg) {
	echo date("Y-m-d H:i:s"), " $msg\n"; 	
}
