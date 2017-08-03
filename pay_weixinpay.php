<?php
/*
 *微信支付
 *扫码支付和jsapi支付app支付
 * @author The Wings
 */
final class pay_weixinpay{
	//返回jsapi数据
	public $jsapiData = null;
	//设置存放属性的数组
	private $values = array();
	//订单返回数据
	private $ordervalues = array();
	private $OPEN_APPID = '';//开放平台appid
	private $OPEN_MCHID = '';//开放平台商户id
	private $OPEN_KEY = '';//开发平台密钥key
	private $_APPID = '';
	private $_MCHID = '';
	private $_KEY = '';//公众平台密钥key
	private $_APPSECRET = '';
	private $_SSLCERT_PATH = '/cert/apiclient_cert.pem';//暂时未使用
	private $_SSLKEY_PATH = '/cert/apiclient_key.pem';//暂时未使用
	private $_CURL_PROXY_HOST = "0.0.0.0";//"10.152.18.220";
	private $_CURL_PROXY_PORT = 0;//8080;
	private $_REPORT_LEVENL = 1;
	private $notify_url = '/notify_url.php';//回调地址
	private $qrcode = '/lib/qrcode.php?data=';//二维码生成地址
    private $tradeType = "";

	/*
	 * 设置订单参数
	 * @param payment Array 支付信息
	 * @param type String  支付类型
	 */
	public function dopay($payment,$type){
		//由于请求参数不能空格将空格去除 
		$payment['goods_name'] = str_replace(" ","",$payment['goods_name']);
		$this->SetParamer('body',$payment['goods_name']);
		$this->SetParamer('attach',$payment['attach']);
		$this->SetParamer('out_trade_no',$payment['order_id']);
		$price = number_format($payment['amount'],2,".","")*100;//不可省略格式步骤
		$this->SetParamer('total_fee',$price);
		$this->SetParamer('time_start',date("YmdHis"));
		$this->SetParamer('time_expire',date("YmdHis", time() + 600));
		$this->SetParamer('goods_tag',$payment['goods_name']);
		$this->SetParamer('notify_url',$payment['notify_url']);
		//判断调用接口类型
		switch ($type) {
			case 'app':
				$this->SetParamer('trade_type',"APP");
				$order = $this->unifiedOrder();
				//获取签名
                $sginList = $this->getSginApp($order);
				return $sginList;
			break;
			case 'native':
				$this->SetParamer('trade_type',"NATIVE");
				$this->SetParamer('product_id',$payment['M_OrderNO']);
				$result = $this->GetPayUrl();
				$url = $result["code_url"];
				$rtn = array();
				$rtn['url'] = $this->qrcode.urlencode($url);
				$rtn['out_trade_no'] = $payment['M_OrderId'];
				return $rtn;
			break;
			case 'jsapi':
				$openId = $this->GetOpenid();
				$this->SetParamer('trade_type',"JSAPI");
				$this->SetParamer('product_id',$payment['M_OrderNO']);
				$this->SetParamer('openid',$openId);
				$order = $this->unifiedOrder();
				$jsApiParameters = $this->GetJsApiParameters($order);
				return $jsApiParameters;
			break;
		}
	}
	
	/*
	 * 回调入口
	 * @param bool $needSign  是否需要签名输出
	 */
	public function Handle($needSign = true){
		//当返回false的时候，表示notify中调用NotifyCallBack回调失败获取签名校验失败，此时直接回复失败
		$result = $this->notify();
		if($result == false){
			return false;
		} 
		//该分支在成功回调到NotifyCallBack方法，处理完成之后流程
		return $this->ordervalues;
	}

	//统一查询订单外部入口
	public function outQueryOrder($transaction_id=null,$out_trade_no=null){
		if($this->Queryorder($transaction_id,$out_trade_no)){
			if(isset($this->values['trade_state']) && ($this->values['trade_state'] == 'SUCCESS')){
				return true;
			}
			return false;
		}
		return false;
	}
	
	//查询订单
	private function Queryorder($transaction_id=null,$out_trade_no=null){
		if(!empty($transaction_id)){
			$this->SetParamer('transaction_id',$transaction_id);
		}else{
			$this->SetParamer('out_trade_no',$out_trade_no);
		}
		$this->ordervalues = $this->values;
		if(isset($this->values['transaction_id'])){
			unset($this->values['out_trade_no']);
		}
		$result = $this->orderQuery();
		if(array_key_exists("return_code", $result)
			&& array_key_exists("result_code", $result)
			&& $result["return_code"] == "SUCCESS"
			&& $result["result_code"] == "SUCCESS")
		{
			return true;
		}
		return false;
	}

	/*
	 * 生成直接支付url，支付url有效期为2小时,模式二
	 */
	private function GetPayUrl(){
		if($this->values['trade_type'] == "NATIVE")
		{
			$result = $this->unifiedOrder();
			return $result;
		}
	}
	/*
	 * 统一下单，WxPayUnifiedOrder中out_trade_no、body、total_fee、trade_type必填
	 * appid、mchid、spbill_create_ip、nonce_str不需要填入
	 * @param WxPayUnifiedOrder $inputObj
	 * @param int $timeOut
	 * @throws Exception
	 * @return 成功时返回，其他抛异常
	 */
	private function unifiedOrder($timeOut = 6){
		$url = "https://api.mch.weixin.qq.com/pay/unifiedorder";
		//检测必填参数
		if(!$this->IsParamerSet('out_trade_no')) {
			throw new Exception("缺少统一支付接口必填参数out_trade_no！");
		}else if(!$this->IsParamerSet('body')){
			throw new Exception("缺少统一支付接口必填参数body！");
		}else if(!$this->IsParamerSet('total_fee')) {
			throw new Exception("缺少统一支付接口必填参数total_fee！");
		}else if(!$this->IsParamerSet('trade_type')) {
			throw new Exception("缺少统一支付接口必填参数trade_type！");
		}
		
		//关联参数
		if($this->GetParamer('trade_type') == "JSAPI" && !$this->IsParamerSet('openid')){
			throw new Exception("统一支付接口中，缺少必填参数openid！trade_type为JSAPI时，openid为必填参数！");
		}
		if($this->GetParamer('trade_type') == "NATIVE" && !$this->IsParamerSet('product_id')){
			throw new Exception("统一支付接口中，缺少必填参数product_id！trade_type为NATIVE时，product_id为必填参数！");
		}
		//异步通知url未设置，则使用配置文件中的url
		if(!$this->IsParamerSet('notify_url')){
			$this->SetNotify_url($this->_NOTIFY_URL);//异步通知url
		}
		if($this->GetParamer('trade_type') == 'APP'){
			$this->SetParamer('appid',$this->OPEN_APPID);//开放平台appid
			$this->SetParamer('mch_id',$this->OPEN_MCHID);//开放平台商户号id	
		}else{
			$this->SetParamer('appid',$this->_APPID);//公众账号ID
			$this->SetParamer('mch_id',$this->_MCHID);//商户号	
		}
		$this->SetParamer('spbill_create_ip',$_SERVER['REMOTE_ADDR']);//终端ip	
		$this->SetParamer('nonce_str',$this->getNonceStr());//随机字符串
		
		//签名
		$sign = $this->MakeSign();
		$this->SetParamer('sign',$sign);
		$xml = $this->ToXml();
		
		$startTimeStamp = $this->getMillisecond();//请求开始时间
		$response = $this->postXmlCurl($xml, $url, false, $timeOut);
		$result = $this->Init($response);
		$this->reportCostTime($url, $startTimeStamp, $result);//上报请求花费时间
		
		return $result;
	}
	
	/*
	 * 通过跳转获取用户的openid，跳转流程如下：
	 * 1、设置自己需要调回的url及其其他参数，跳转到微信服务器https://open.weixin.qq.com/connect/oauth2/authorize
	 * 2、微信服务处理完成之后会跳转回用户redirect_uri地址，此时会带上一些参数，如：code
	 * @return 用户的openid
	 */
	private function GetOpenid(){
		//通过code获得openid
		if (!isset($_GET['code'])){
			//触发微信返回code码
			$baseUrl = urlencode('http://'.$_SERVER['HTTP_HOST'].$_SERVER['PHP_SELF'].$_SERVER['QUERY_STRING']);
			$url = $this->__CreateOauthUrlForCode($baseUrl);
			Header("Location: $url");
			exit();
		} else {
			//获取code码，以获取openid
		    $code = $_GET['code'];
			$openid = $this->getOpenidFromMp($code);
			return $openid;
		}
	}
	
	/*
	 * 获取jsapi支付的参数
	 * @param array $UnifiedOrderResult 统一支付接口返回的数据
	 * @throws WxPayException
	 * @return json数据，可直接填入js函数作为参数
	 */
	private function GetJsApiParameters($UnifiedOrderResult){
		if(!array_key_exists("appid", $UnifiedOrderResult)
		|| !array_key_exists("prepay_id", $UnifiedOrderResult)
		|| $UnifiedOrderResult['prepay_id'] == "")
		{
			throw new Exception("参数错误");
		}
		$jsapiValues['appId'] = $UnifiedOrderResult["appid"];//公众账号ID
		$jsapiValues['timeStamp'] = time();
		$jsapiValues['nonceStr'] = $this->getNonceStr();
		$jsapiValues['package'] = "prepay_id=" . $UnifiedOrderResult['prepay_id'];
		$jsapiValues['signType'] = "MD5";
		//签名步骤一：按字典序排序参数
		ksort($jsapiValues);
		$string = "";
		foreach ($jsapiValues as $k => $v)
		{
			if($k != "sign" && $v != "" && !is_array($v)){
				$string .= $k . "=" . $v . "&";
			}
		}
		$string = trim($string, "&");
		//签名步骤二：在string后加入KEY
		$string = $string . "&key=".$this->_KEY;
		//签名步骤三：MD5加密
		$string = md5($string);
		//签名步骤四：所有字符转为大写
		$string = strtoupper($string);
		$jsapiValues['paySign'] = $string;
		$parameters = json_encode($jsapiValues);
		return $parameters;
	}
	
	/*
	 * 上报数据， 上报的时候将屏蔽所有异常流程
	 * @param string $usrl
	 * @param int $startTimeStamp
	 * @param array $data
	 */
	private function reportCostTime($url, $startTimeStamp, $data){
		//如果不需要上报数据
		if($this->_REPORT_LEVENL == 0){
			return;
		} 
		//如果仅失败上报
		if($this->_REPORT_LEVENL == 1 &&
			 array_key_exists("return_code", $data) &&
			 $data["return_code"] == "SUCCESS" &&
			 array_key_exists("result_code", $data) &&
			 $data["result_code"] == "SUCCESS")
		 {
		 	return;
		 }
		 
		//上报逻辑
		$endTimeStamp = $this->getMillisecond();
		//$objInput = new WxPayReport();
		$this->values['interface_url'] = $url;
		$this->values['execute_time_'] = $endTimeStamp - $startTimeStamp;
		//返回状态码
		if(array_key_exists("return_code", $data)){
			$this->values['return_code'] = $data["return_code"];
		}
		//返回信息
		if(array_key_exists("return_msg", $data)){
			$this->values['return_msg'] = $data["return_msg"];
		}
		//业务结果
		if(array_key_exists("result_code", $data)){
			$this->values['result_code'] = $data["result_code"];
		}
		//错误代码
		if(array_key_exists("err_code", $data)){
			$this->values['err_code'] = $data["err_code"];
		}
		//错误代码描述
		if(array_key_exists("err_code_des", $data)){
			$this->values['err_code_des'] = $data["err_code_des"];
		}
		//商户订单号
		if(array_key_exists("out_trade_no", $data)){
			$this->values['out_trade_no'] = $data["out_trade_no"];
		}
		//设备号
		if(array_key_exists("device_info", $data)){
			$this->values['device_info'] = $data["device_info"];
		}
		
		try{
			$this->report();
		} catch (Exception $e){
			//不做任何处理
		}
	}
	
	/*
	 * 测速上报，该方法内部封装在report中，使用时请注意异常流程
	 * WxPayReport中interface_url、return_code、result_code、user_ip、execute_time_必填
	 * appid、mchid、spbill_create_ip、nonce_str不需要填入
	 * @param WxPayReport $inputObj
	 * @param int $timeOut
	 * @throws Exception
	 * @return 成功时返回，其他抛异常
	 */
	private function report($timeOut = 1){
		$url = "https://api.mch.weixin.qq.com/payitil/report";
		//检测必填参数
		if(!$this->values['interface_url']) {
			throw new Exception("接口URL，缺少必填参数interface_url！");
		} if(!$this->values['return_code']) {
			throw new Exception("返回状态码，缺少必填参数return_code！");
		} if(!$this->values['result_code']) {
			throw new Exception("业务结果，缺少必填参数result_code！");
		} if(!$this->values['user_ip']) {
			throw new Exception("访问接口IP，缺少必填参数user_ip！");
		} if(!$this->values['execute_time_']) {
			throw new Exception("接口耗时，缺少必填参数execute_time_！");
		}
		$this->values['appid'] = $this->_APPID;//公众账号ID
		$this->values['mch_id'] = $this->_MCHID;//商户号
		$this->values['user_ip'] = $_SERVER['REMOTE_ADDR'];//终端ip
		$this->values['time'] = date("YmdHis");//商户上报时间	 
		$this->values['nonce_str'] = $this->getNonceStr();//随机字符串
		//签名
		$sign = $this->MakeSign();
		$this->SetParamer('sign',$sign);
		$xml = $this->ToXml();
		
		$startTimeStamp = $this->getMillisecond();//请求开始时间
		$response = $this->postXmlCurl($xml, $url, false, $timeOut);
		return $response;
	}
	
	/*
     * 将xml转为array
     * @param string $xml
     * @throws Exception
     */
	private function Init($xml){	
		$this->FromXml($xml);
		if($this->values['return_code'] != 'SUCCESS'){
			 return $this->values;
		}
		$this->CheckSign();
        return $this->values;
	}
	
	/*
	 * 检测签名
	 */
	private function CheckSign(){
		//fix异常
		if(!$this->IsParamerSet('sign')){
			throw new Exception("签名错误！");
		}
		
		$sign = $this->MakeSign();
		if($this->IsParamerSet('sign') == $sign){
			return true;
		}
		throw new Exception("签名错误！");
	}

	/*
     * 将xml转为array
     * @param string $xml
     * @throws Exception
     */
	private function FromXml($xml){	
		if(!$xml){
			throw new Exception("xml数据异常！");
		}
        //将XML转为array
        //禁止引用外部xml实体
        libxml_disable_entity_loader(true);
        $this->values = json_decode(json_encode(simplexml_load_string($xml, 'SimpleXMLElement', LIBXML_NOCDATA)), true);
        saveLog("weixinpay_client", 'http://'.$_SERVER['HTTP_HOST'].$_SERVER['PHP_SELF'].'?'.json_encode($this->values));
        return $this->values;
	}
	
	/*
	 * 以post方式提交xml到对应的接口url
	 * @param string $xml  需要post的xml数据
	 * @param string $url  url
	 * @param bool $useCert 是否需要证书，默认不需要
	 * @param int $second   url执行超时时间，默认30s
	 * @throws Exception
	 */
	private function postXmlCurl($xml, $url, $useCert = false, $second = 30){		
		$ch = curl_init();
		//设置超时
		curl_setopt($ch, CURLOPT_TIMEOUT, $second);
		
		//如果有配置代理这里就设置代理
		if($this->_CURL_PROXY_HOST != "0.0.0.0" 
			&& $this->_CURL_PROXY_PORT != 0){
			curl_setopt($ch,CURLOPT_PROXY, $this->_CURL_PROXY_HOST);
			curl_setopt($ch,CURLOPT_PROXYPORT, $this->_CURL_PROXY_PORT);
		}
		curl_setopt($ch,CURLOPT_URL, $url);
		curl_setopt($ch,CURLOPT_SSL_VERIFYPEER,TRUE);
		curl_setopt($ch,CURLOPT_SSL_VERIFYHOST,2);//严格校验
		//设置header
		curl_setopt($ch, CURLOPT_HEADER, FALSE);
		//要求结果为字符串且输出到屏幕上
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, TRUE);
	
		if($useCert == true){
			//设置证书
			//使用证书：cert 与 key 分别属于两个.pem文件
			curl_setopt($ch,CURLOPT_SSLCERTTYPE,'PEM');
			curl_setopt($ch,CURLOPT_SSLCERT, $this->_SSLCERT_PATH);
			curl_setopt($ch,CURLOPT_SSLKEYTYPE,'PEM');
			curl_setopt($ch,CURLOPT_SSLKEY, $this->_SSLKEY_PATH);
		}
		//post提交方式
		curl_setopt($ch, CURLOPT_POST, TRUE);
		curl_setopt($ch, CURLOPT_POSTFIELDS, $xml);
		//运行curl
		$data = curl_exec($ch);
		//返回结果
		if($data){
			curl_close($ch);
			return $data;
		} else { 
			$error = curl_errno($ch);
			curl_close($ch);
			throw new Exception("curl出错，错误码:$error");
		}
	}
	
	/*
	 * 获取毫秒级别的时间戳
	 */
	private function getMillisecond(){
		//获取毫秒的时间戳
		$time = explode ( " ", microtime () );
		$time = $time[1] . ($time[0] * 1000);
		$time2 = explode( ".", $time );
		$time = $time2[0];
		return $time;
	}
	
	/*
	 * 输出xml字符
	 * @throws Exception
	 */
	private function ToXml(){
		if(!is_array($this->values) 
			|| count($this->values) <= 0)
		{
    		throw new Exception("数组数据异常！");
    	}
    	
    	$xml = "<xml>";
    	foreach ($this->values as $key=>$val)
    	{
    		if (is_numeric($val)){
    			$xml.="<".$key.">".$val."</".$key.">";
    		}else{
    			$xml.="<".$key."><![CDATA[".$val."]]></".$key.">";
    		}
        }
        $xml.="</xml>";
        return $xml; 
	}
	
	/*
	 * 格式化参数格式化成url参数
	 */
	private function ToUrlParams(){
		$buff = "";
		foreach ($this->values as $k => $v)
		{
			if($k != "sign" && $v != "" && !is_array($v)){
				$buff .= $k . "=" . $v . "&";
			}
		}
		
		$buff = trim($buff, "&");
		return $buff;
	}
	
	/*
	 * 生成签名
	 * @return 签名，本函数不覆盖sign成员变量，如要设置签名需要调用SetSign方法赋值
	 */
	private function MakeSign(){
		//签名步骤一：按字典序排序参数
		ksort($this->values);
		$string = $this->ToUrlParams();
		//签名步骤二：在string后加入KEY
        if(isset($this->tradeType) && $this->tradeType == 'APP'){
            $string = $string . "&key=".$this->OPEN_KEY;//开放平台
        }else{
            if($this->GetParamer('trade_type') == 'APP'){
                $string = $string . "&key=".$this->OPEN_KEY;//开放平台
            }else{
                $string = $string . "&key=".$this->_KEY;//公众号
            }
        }
		//签名步骤三：MD5加密
		$string = md5($string);
		//签名步骤四：所有字符转为大写
		$result = strtoupper($string);
		return $result;
	}
	
	/*
	 * 产生随机字符串，不长于32位
	 * @param int $length
	 * @return 产生的随机字符串
	 */
	private function getNonceStr($length = 32) {
		$chars = "abcdefghijklmnopqrstuvwxyz0123456789";  
		$str ="";
		for ( $i = 0; $i < $length; $i++ )  {  
			$str .= substr($chars, mt_rand(0, strlen($chars)-1), 1);  
		} 
		return $str;
	}
	
	
	//支付回调
	/*
	 * 查询订单，WxPayOrderQuery中out_trade_no、transaction_id至少填一个
	 * appid、mchid、spbill_create_ip、nonce_str不需要填入
	 * @param WxPayOrderQuery $inputObj
	 * @param int $timeOut
	 * @throws WxPayException
	 * @return 成功时返回，其他抛异常
	 */
	private function orderQuery($timeOut = 6){
		$url = "https://api.mch.weixin.qq.com/pay/orderquery";
		//检测必填参数
		if(!$this->IsParamerSet('out_trade_no') && !$this->IsParamerSet('transaction_id')) {
			throw new Exception("订单查询接口中，out_trade_no、transaction_id至少填一个！");
		}
		if($this->GetParamer('trade_type') == 'APP'){
			$this->SetParamer('appid',$this->OPEN_APPID);//开放平台appid
			$this->SetParamer('mch_id',$this->OPEN_MCHID);//开放平台商户号id
            $this->tradeType = 'APP';
		}else{
			$this->SetParamer('appid',$this->_APPID);//公众账号ID
			$this->SetParamer('mch_id',$this->_MCHID);//商户号
            $this->tradeType = 'PUBLIC';
		}
		$this->SetParamer('nonce_str',$this->getNonceStr());//随机字符串
		foreach($this->values as $key=>$item){
			if(($key != 'transaction_id') && 
			   ($key != 'out_trade_no') && 
			   ($key != 'appid') && 
			   ($key != 'mch_id') &&
			   ($key != 'nonce_str')){
				unset($this->values[$key]);
			}
		}
		//签名
		$sign = $this->MakeSign();
		$this->SetParamer('sign',$sign);
		$xml = $this->ToXml();
		
		$startTimeStamp = $this->getMillisecond();//请求开始时间
		$response = $this->postXmlCurl($xml, $url, false, $timeOut);
		$result = $this->Init($response);
		$this->reportCostTime($url, $startTimeStamp, $result);//上报请求花费时间
		return $result;
	}
	
	//重写回调处理函数
	private function NotifyProcess($data, &$msg){
		if(!array_key_exists("transaction_id", $data)){
			$msg = "输入参数不正确";
			return false;
		}
		//查询订单，判断订单真实性
		if(!$this->Queryorder($data["transaction_id"])){
			$msg = "订单查询失败";
			return false;
		}
		return true;
	}
	
	/*
	 * notify回调方法，该方法中需要赋值需要输出的参数,不可重写
	 * @param array $data
	 * @return true回调出来完成不需要继续回调，false回调处理未完成需要继续回调
	 */
	private function NotifyCallBack($data){
		$msg = "OK";
		$result = $this->NotifyProcess($data, $msg);
		if($result == true){
			$this->SetParamer('return_code','SUCCESS');
			$this->SetParamer('return_msg','OK');
		} else {
			$this->SetParamer('return_code','FAIL');
			$this->SetParamer('return_msg',$msg);
		}
		return $result;
	}
	
	/*
 	 * 支付结果通用通知
 	 * @param function $callback
 	 * 直接回调函数使用方法: notify(you_function);
 	 * 回调类成员函数方法:notify(array($this, you_function));
 	 * $callback  原型为：function function_name($data){}
 	 */
	private function notify(){
		//获取通知的数据
		$xml = $GLOBALS['HTTP_RAW_POST_DATA'];
		//如果返回成功则验证签名
		try {
			$result = $this->Init($xml);
		} catch (Exception $e){
			$msg = $e->getMessage();
			return false;
		}
		return $this->NotifyCallBack($result);
	}
	
	/*
	 * 回复通知
	 * @param bool $needSign 是否需要签名输出
	 */
	private function ReplyNotify($needSign = true){
		//如果需要签名
		if($needSign == true && 
			$this->SetParamer('return_code') == "SUCCESS")
		{
			//签名
			$sign = $this->MakeSign();
			$this->SetParamer('sign',$sign);
		}
		echo $this->ToXml();
	}
	
	/*
	 * 通过code从工作平台获取openid机器access_token
	 * @param string $code 微信跳转回来带上的code
	 * @return openid
	 */
	private function GetOpenidFromMp($code){
		$url = $this->__CreateOauthUrlForOpenid($code);
		//初始化curl
		$ch = curl_init();
		//设置超时
		curl_setopt($ch, CURLOPT_TIMEOUT, $this->curl_timeout);
		curl_setopt($ch, CURLOPT_URL, $url);
		curl_setopt($ch, CURLOPT_SSL_VERIFYPEER,FALSE);
		curl_setopt($ch, CURLOPT_SSL_VERIFYHOST,FALSE);
		curl_setopt($ch, CURLOPT_HEADER, FALSE);
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, TRUE);
		if($this->_CURL_PROXY_HOST != "0.0.0.0" 
			&& $this->_CURL_PROXY_PORT != 0){
			curl_setopt($ch,CURLOPT_PROXY, $this->_CURL_PROXY_HOST);
			curl_setopt($ch,CURLOPT_PROXYPORT, $this->_CURL_PROXY_PORT);
		}
		//运行curl，结果以jason形式返回
		$res = curl_exec($ch);
		curl_close($ch);
		//取出openid
		$data = json_decode($res,true);
		$this->jsapiData = $data;
		$openid = $data['openid'];
		return $openid;
	}
	
	/*
	 * 构造获取open和access_toke的url地址
	 * @param string $code，微信跳转带回的code
	 * @return 请求的url
	 */
	private function __CreateOauthUrlForOpenid($code)
	{
		$urlObj["appid"] = $this->_APPID;
		$urlObj["secret"] = $this->_APPSECRET;
		$urlObj["code"] = $code;
		$urlObj["grant_type"] = "authorization_code";
		$bizString = $this->ToJsapiUrlParams($urlObj);
		return "https://api.weixin.qq.com/sns/oauth2/access_token?".$bizString;
	}
	
	/*
	 * 构造获取code的url连接
	 * @param string $redirectUrl 微信服务器回跳的url，需要url编码
	 * @return 返回构造好的url
	 */
	private function __CreateOauthUrlForCode($redirectUrl)
	{
		$urlObj["appid"] = $this->_APPID;
		$urlObj["redirect_uri"] = "$redirectUrl";
		$urlObj["response_type"] = "code";
		$urlObj["scope"] = "snsapi_base";
		$urlObj["state"] = "STATE"."#wechat_redirect";
		$bizString = $this->ToJsapiUrlParams($urlObj);
		return "https://open.weixin.qq.com/connect/oauth2/authorize?".$bizString;
	}
	
	
	/*
	 * 拼接签名字符串
	 * @param array $urlObj
	 * @return 返回已经拼接好的字符串
	 */
	private function ToJsapiUrlParams($urlObj)
	{
		$buff = "";
		foreach ($urlObj as $k => $v)
		{
			if($k != "sign"){
				$buff .= $k . "=" . $v . "&";
			}
		}
		$buff = trim($buff, "&");
		return $buff;
	}
	
	//设置属性
	private function SetParamer($key,$value){
		$this->values[$key] = $value;
	}
	
	//获取属性
	private function GetParamer($key){
		return $this->values[$key];
	}
	
   /*
	* 判断属性是否存在
	* @return true 或 false
	*/
	private function IsParamerSet($key){
		return array_key_exists($key, $this->values);
	}

	/*
	 *生成app支付调用sgin
	 */
    private function getSginApp($order){
        $sginList = array();
        $sginList['appid'] = $order['appid'];
        $sginList['partnerid'] = $order['mch_id'];
        $sginList['prepayid'] = $order['prepay_id'];
        $sginList['package'] = 'Sign=WXPay';
        $sginList['noncestr'] = $order['nonce_str'];
        $sginList['timestamp'] = time();
        //参数名ASCII字典序排序
        ksort($sginList);
        //初始化
        $sginStr = "";
        foreach($sginList as $key => $item){
            $sginStr .= "&" . $key . '=' . $item;
        }
        $sginStr = trim($sginStr,'&');
        $sginStr .= '&key=' . $this->OPEN_KEY;
        $sign = md5($sginStr);
        $sign = strtoupper($sign);
        $sginList['sign'] = $sign;
        return $sginList;
    }
}