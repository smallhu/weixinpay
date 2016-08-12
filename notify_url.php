<?php
require_once './pay_weixinpay.php';
$weixinpay = new pay_weixinpay();
$rtnList = $weixinpay->Handle(false);
//$rtnList['out_trade_no']; //支付单号 
//获取支付单号修改业务逻辑