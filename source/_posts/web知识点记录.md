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





















































































