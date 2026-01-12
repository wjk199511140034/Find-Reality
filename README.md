## 扫描Reality站点<br>
Usage:<br>
```
-ip <ip_addr>		Manually specify IP
-d <file_addr>	Check local domains
-e <num>		    Epend IP C-segments
-m <num>		    multithreading, default is 20
-dp			        Enable deep check
-h, --help		  Show this help message
```
用法:<br>
                默认无参数执行，表示获取本机公网ip，扫描ip/24段可能存在的域名，并检查reality适用性，通过测试的域名放在check_result.txt
-ip <ip_addr>		扫描指定ip/24段可能存在的域名，并检查reality适用性，通过测试的域名放在check_result.txt
-d <file_addr>	Check local domains"
-e <num>		    Epend IP C-segments"
-m <num>		    multithreading, default is 20."
-dp			        Enable deep check "
-h, --help		  Show this help message"
