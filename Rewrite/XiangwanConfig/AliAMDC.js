/*
# > AMDC
# 用于阿里系应用，拦截AMDC请求，并修改响应内容；
# 由向晚重写维护；

# 更新时间: 20250521
# 规则链接: https://raw.githubusercontent.com/XiangwanGuan/Shadowrocket/main/Rewrite/XiangwanConfig/AliAMDC.js

[rewrite_local]
^https?:\/\/amdc\.m\.taobao\.com url script-response-body https://xiangwanguan.github.io/Shadowrocket/Rewrite/JavaScript/AliAMDC.js 

[mitm]
hostname = amdc.m.taobao.com
*/

var ua = decodeURIComponent(($request.headers["user-agent"] || "")).toLowerCase();
var url = $request.url;
var uaKeywords = ["amap", "alibaba", "cainiao", "hema", "moon", "天猫", "闲鱼", "飞猪"];
var blockAppKeys = ["23782110"];
var uaMatched = uaKeywords.some(keyword => ua.includes(keyword));
var appkeyMatch = url.match(/[?&]appkey=(\d+)/);
var appkey = appkeyMatch ? appkeyMatch[1] : "";
var appkeyMatched = blockAppKeys.includes(appkey);
if (uaMatched || appkeyMatched) {
    $done({ status: "HTTP/1.1 404 Not Found", body: "Not Found" });
} else {
    $done({});
}
