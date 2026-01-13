**请勿在生产环境运行该脚本，请勿短时间多次运行该脚本，请勿尝试将并发数（-m）设置过大<br>
请遵守当地法律法规，运行前仔细研读代码，盲目使用脚本造成的一切后果自负！**<br>
## Find Reality<br>
```
wget -O - https://raw.githubusercontent.com/wjk199511140034/Find-Reality/main/find_reality.sh
```
Or<br>
```
curl -sSL https://raw.githubusercontent.com/wjk199511140034/Find-Reality/main/find_reality.sh
```
Usage:<br>
```
When executed without parameters, the script will perform the following procedures:
Defaults mode is IP scanning, using the server's public IP, scans the /24 subnet of that IP for potential domains and checks their REALITY compatibility, domains that pass the test are saved in check_result.txt
-ip <ip_addr>		Manually specify IP
-d <file_addr>  	Check local domains
-e <num>		    Epend IP C-segments
-m <num>		    multithreading, default is 20
-dp			        Enable deep check
-h, --help          Show this help message
```
## WARNING<br>
Do not run this script in a production environment. Do not run this script multiple times within a short period. Do not attempt to set the concurrency limit (-m) too high.<br>
Please comply with local laws and regulations. Read the code carefully before execution. Use this script at your own risk; the user is solely responsible for any consequences caused by the abuse of this script!<br>
## 扫描Reality站点<br>
用法:<br>
```
无参数直接执行时，脚本将进行以下操作：
默认ip扫描模式，使用本机公网IP，扫描/24段可能存在的域名，并检查Reality适用性，通过测试的域名放在check_result.txt
-ip <ip_addr>      指定IP
-d <file_addr>     域名检查模式（本地文件）
-e <num>           扩充IP C段
-m <num>           设置并发数（默认20）
-dp                启用深度检测
-h, --help         显示帮助
```
## 说明<br>
支持多参数运行，如：使用-ip <ip_addr>	-d <file_addr>，可检测域名列表在指定IP段的匹配性<br>
域名列表支持的分割方式：换行，空格，逗号（半角），分号（半角）<br>
扩展C段一般设置为1~3即可，更大的数字没有意义<br>
CDN检测原理：通过```getent ahosts <hostname>```，查看响应IP是否与公网IP/指定IP在同一个C段<br>
深度检测在不同模式下表现不同：<br>
&emsp;&emsp;ip扫描模式：会尝试从SAN获取更多域名，默认只从CN获取域名<br>
&emsp;&emsp;域名检查模式：会检查是否为x25519，默认只检测tls1.3和h2，通常情况下，使用tls1.3默认x25519<br>
最后：请勿在生产环境运行该脚本，请勿短时间多次运行该脚本，请勿尝试将并发数（-m）设置过大<br>
请遵守当地法律法规，运行前仔细研读代码，滥用脚本造成的一切后果自负！<br>
