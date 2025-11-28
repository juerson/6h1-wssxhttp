# 6h1-wssxhttp

基于 Cloudflare Workers  的多协议 Serverless Tunnel。

### 一、支持协议

| 协议        | ws（WebSocket） | xhttp（GRPC over HTTP2） |
| ----------- | --------------- | ------------------------ |
| VLESS       | ✅               | ✅                        |
| Trojan      | ✅               | ✅                        |
| Shadowsocks | ✅               | ✅                        |
| VMess       | ❌               | ❌                        |

<img src="images\1.png" title="v2rayN"/>

注意：Shadowsocks协议，原则上使用**V_UUID4**值作为密码，实际它**无密码**的，输入**任意字符串都可以**，目前只靠**WS_PATH**或**XHTTP_PATH**的路径设置复杂或真实一点保护你的节点。

### 二、使用

1、修改Config的配置参数后，部署到 Cloudflare Workers 中（也可以参照下面的**各个字段**，在**变量和机密**中选择性添加）

```jsonc
{
  "V_UUID4": "8640655f-7920-437a-9b91-2ec452b74b03",
  "USER_PROXY": "", 					// PROXYIP，格式：host[:port]
  "LOG_LEVEL": "none",
  "TIME_ZONE": "8",
  "BUFFER_SIZE": "64",
  "IP_QUERY_PATH": "/ip", 				// GET请求，查看您的IP
  "WS_PATH": "/8640655f/ws", 			// ws路径，节点中用到
  "XHTTP_PATH": "/8640655f/xhttp", 		// xhttp路径，节点中用到
  "XPADDING_RANGE": "100-1000", 		// xhttp所用的参数
  "RELAY_SCHEDULER": "pipe", 			// 选择哪个写法中继数据：pipe(官方提供的) 或 yield（自定义的精细流量管理）
  "YIELD_SIZE": "64",
  "YIELD_DELAY": "5",
  "PREFERRED_ADDRESS": [
    "r2.dev",
    "mqtt.dev",
    "cloudflare.dev",
    "devprod.cloudflare.dev",
    "preview.devprod.cloudflare.dev",
    "radar.cloudflare.com",
    "cloudflareclient.com",
    "www.visa.com.sg",
    "www.visa.com.hk",
    "usa.visa.com"
  ]
}
```

2、XHTTP传输协议的，需要添加**自定义域**，并且在您的域名中的 **网络** => 开启**gRPC**

<img src="images\gRPC.png" />

3、查看自己的IP，还需要Config中的IP_QUERY_PATH参数值，个人感觉用处不大，有其他网站查询

```
{"IP_QUERY_PATH": "/ip"}

GET https://youDomain.com/ip
```

4、查看分享链接

| 协议  | Config参数值                      | 使用示例                                                     |
| ----- | --------------------------------- | ------------------------------------------------------------ |
| ws    | {"WS_PATH": "/8640655f/ws"}       | https://youDomain.com/8640655f/ws?uuid=8640655f-7920-437a-9b91-2ec452b74b03 |
| xhttp | {"XHTTP_PATH": "/8640655f/xhttp"} | https://youDomain.com/8640655f/xhttp?uuid=8640655f-7920-437a-9b91-2ec452b74b03 （无Shadowsocks协议的分享链接，要手动在代理客户端中添加） |

注意：xhttp传输协议的，暂时只支持xray内核使用，如：v2rayN、v2rayNG。

### 三、感谢项目

感谢 https://github.com/vrnobody/cfws/blob/main/src/err1101.js 提供的cfxhttp源码，本项目的代码是基于它修改。使用时，不要优选太好的Cloudflare IP，传输流媒体很容易出现"Worker exceeded CPU time limit."。

### 四、免责声明

该项目仅供学习/研究网络技术之用，**严禁用于任何非法目的**。任何使用者在使用本项目时，均应遵守其所在国家或地区的法律法规。对于任何因使用或滥用本项目而导致的任何直接或间接的法律责任和风险，**均由使用者本人承担**，作者及贡献者不对任何第三方使用本项目进行的任何非法活动及其造成的任何损害承担责任。

如果您开始使用本项目，即表示您已充分理解并同意上述条款。

