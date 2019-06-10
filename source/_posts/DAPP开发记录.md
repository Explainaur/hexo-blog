---
title: DAPP开发记录
date: 2019-03-19 19:24:29
tags:
    - thinking
---

### DAPP的简单原理  

---  

&emsp;&emsp;DAPP实在是神奇，理解他的工作原理还是需要熟悉区块链的运作方式，在此记录一下我的心路历程。  

#### 后端在哪  

&emsp;&emsp;每次一想到应用开发就觉得需要前后端的配合，后端总得在一台机器上吧，要不然我咋访问，咋交互？但是DAPP就不是这样，我们似乎只能访问其中的节点，以以太坊为例，每一个参与活动的客户端同时又是一个节点，我们自然可以在本地建立轻节点或者全节点，甚至是测试链，由于贫穷，我们在开发调试时就在测试链上进行。  

&emsp;&emsp;那么所谓的后端实际上是整个区块链，当合约被部署到区块链上时，整个区块链将成为他的数据库，我们将数据称之为负载，将代码称之为合约。合约之所以称之为合约是因为其不可篡改性以及调用时需要付出代价，即**gas**。gas可由eth(以太币)进行兑换，gas将用于奖励确认交易的矿工。这里需要注意，所谓交易的确认不过是新的区块的生成，可能有多个交易被打包在一个区块内，由于去中心化所导致的节点间完全不信任，但是新的区块总需要有个人进行确认，这时，就需要引入一种限制方式，或者说证明自己不是 **骗子** 的条件，即**工作量证明**(Proof of Work)。你如果要添加一个新的区块，你就要付出工作量的代价，因此就会有挖矿这么一说。  

&emsp;&emsp;当然，以上只是简单解释，其中的数学问题相当复杂，比如拜占庭将军问题的处理，等等。而且证明方式也不只是 Proof of work 这么一种。  


#### 合约在哪  

&emsp;&emsp;当你理解了上面的原理之后，这个问题其实很简单，合约自然是在整个区块链上。在remix中进行deploy时，此合约就已经被添加到了区块中，我们在等待区块被确认后，我们通过 **ABI**(Application Binary Interface),即应用二进制接口和**合约的地址**来进行调用。没错，合约本身就是一个地址，也是一个账户，当调用它是要给它冲钱。这个时候我们将数据参数发送至某个节点，在EVM运行合约并处理数据后，可能会将数据添加到链上做数据负载，或者将一些负载返回给客户端。我们也可以调用合约的接口来访问visable的状态变量，以面向对象的思想进行思考总是会得到新的体验，这就是设计模式的魅力所在。

#### 开始构建  

&emsp;&emsp;在做了一部分背景介绍后，我们来进行开发，所需工具如下：  

- **remix-ide**  

- **MetaMask**  

- **geth**  

- **lite-server**  


1. 合约的部署  

&emsp;&emsp;首先我们使用remix-ide，我个人建议本地安装，去github上下载。接下来我们将合约进行编译，目前的通用版本是0.5.5,这里**Environment**应该选择**Injected Web3**。开发的环境选择Ropsten测试链，因为在这条链上我们可以免费获得eth，实在是穷人啊！至于如何获得免费的以太币我们最后再讲。总的设置如下：  

![remix-ide](https://github.com/Explainaur/hexo-blog/blob/master/source/pictures/dapp_1.png?raw=true)  

&emsp;&emsp;合约会自动编译，接下来我们将合约部署到区块链上，点击下面的deploy：  

![deploy](https://github.com/Explainaur/hexo-blog/blob/master/source/pictures/dapp_3.png?raw=true)  

&emsp;&emsp;会出现MetaMask的弹框，让你确认是否进行交易，我们可以看到虽然没有向合约支付，但是却要为矿工支付gas。接下来我们等待一段时间后可以看到交易被确认：  

![commit](https://github.com/Explainaur/hexo-blog/blob/master/source/pictures/dapp_2.png?raw=true)  

```solidity
pragma solidity >= 0.4.0 < 0.6.0;

contract human{
    uint age;
    string name = "dyf";

    function setInfo(uint256 _age, string memory _name) public {
        age =_age;
        name = _name;
    }

    function getInfo() public view returns(uint256,string memory ){
        return (age,name);
    }

}
```
&emsp;&emsp; **请注意这里函数的view**


&emsp;&emsp;以上是我的交易记录，到这里我们的合约已经部署完毕。下一步是在前端引用合约。

---  

2. 合约的调用  

&emsp;&emsp;在html中，要实现与区块链的交互我们还是需要Web3的api，就像geth一样，只是被迁移到了前端，这里给出api库：  

```html
 <script src="https://cdn.jsdelivr.net/gh/ethereum/web3.js/dist/web3.min.js"></script>
```
&emsp;&emsp;有时间还得读读他的文档，为了方便起见我们最好使用jQuery库，我觉得挺舒服的，直接给出前端代码：  

```html
<html>
    <head>
        <script src="https://code.jquery.com/jquery-3.3.1.min.js"></script>
        <script
            src="https://cdn.jsdelivr.net/gh/ethereum/web3.js/dist/web3.min.js"></script>
        <meta charset=utf-8>
    </head>
    <body>
        <h1>my dapp</h1>
        <div class="container">
            <h3 id='info'>info</h3>
            <label>name:</label>
            <input type="text" id="name">
            <label>age:</label>
            <input type="text" id="age">
            <button id="button">Go</button>
            <button id="get"> Get info</button>

        </div>
    </body>
    <script>
    console.log("web3"+web3);
    if(typeof web3 != 'undifined'){
        web3 = new Web3(web3.currentProvider);
    }
    else{
        web3 = new Web3(new Web3.providers.HttpProvide("http://localhost:8545"));
    }

    var infoContract = web3.eth.contract(
       [
	    {
        "constant": true,
        "inputs": [],
        "name": "getInfo",
        "outputs": [
          {
            "name": "",
            "type": "uint256"
          },
          {
            "name": "",
            "type": "string"
          }
        ],
        "payable": false,
        "stateMutability": "view",
        "type": "function"
      },
      {
        "constant": false,
        "inputs": [
          {
            "name": "_age",
            "type": "uint256"
          },
          {
            "name": "_name",
            "type": "string"
          }
        ],
        "name": "setInfo",
        "outputs": [],
        "payable": false,
        "stateMutability": "nonpayable",
        "type": "function"
      }
]
  )

  var info = infoContract.at('0x3d2f4d5eb88848e75c966118c98f4928aa188f21');

  $("#button").click(function(){
      var name = $("#name").val();
      var age = $("#age").val()
      info.setInfo(age,name,function(error,result){
          if(!error){
              console.log("ok");
          }
      })
  })
    $('#get').click(function(){
        info.getInfo(function(error,result){
          $('#info').html("name:"+result[1]+"&emsp;age:"+result[0]);
      })
    })
    </script>
</html>
```

&emsp;&emsp;首先验证引入web3成功  
```javascript
console.log("web3"+web3);
```

&emsp;&emsp;接着我们链接web3的provider或本的链，在这里就是lite-server所创建的服务器环境，lite-server的作用是建立服务器连接，因为MetaMask存在保护，这样才能引入Web3，反正windows用户应该挺难受的。  

```javascript
 if(typeof web3 != 'undifined'){
        web3 = new Web3(web3.currentProvider);
    }
    else{
        web3 = new Web3(new Web3.providers.HttpProvide("http://localhost:8545"));
    }
```
&emsp;&emsp;然后我们生成一个合约对象，这里我们需要编译合约时生成的ABI和地址：  

```javascript

/** 注入合约ABI **/

var infoContract = web3.eth.contract(
       [
	    {
        "constant": true,
        "inputs": [],
        "name": "getInfo",
        "outputs": [
          {
            "name": "",
            "type": "uint256"
          },
          {
            "name": "",
            "type": "string"
          }
        ],
        "payable": false,
        "stateMutability": "view",
        "type": "function"
      },
      {
        "constant": false,
        "inputs": [
          {
            "name": "_age",
            "type": "uint256"
          },
          {
            "name": "_name",
            "type": "string"
          }
        ],
        "name": "setInfo",
        "outputs": [],
        "payable": false,
        "stateMutability": "nonpayable",
        "type": "function"
      }
]
  )

  /** 注入合约地址 **/
  var info = infoContract.at('0x3d2f4d5eb88848e75c966118c98f4928aa188f21');
```

&emsp;&emsp;这是我们就得到了一个合约实例，我们可以按照通常面向对象的方式来调用他们的接口。比如：  

```javascript
$("#button").click(function(){
      var name = $("#name").val();
      var age = $("#age").val()
      info.setInfo(age,name,function(error,result){
          if(!error){
              console.log("ok");
          }
      })
  })
    $('#get').click(function(){
        info.getInfo(function(error,result){
          $('#info').html("name:"+result[1]+"&emsp;age:"+result[0]);
      })
    })
```
&emsp;&emsp;这里是基于jQuery的信息交互，我们可以清晰的理解这种调用方式，我们向节点服务器发送交易请求，当交易被确认后，前端的数据可以通过调用接口的方式进行刷新，但是数据的更新会有延迟，毕竟交易的确认需要时间。  

&emsp;&emsp;到这里，一个极端简单的DAPP已经开发完成，但是区块链神奇的思想可见一斑，由此看来我们还是要好好学设计模式和数学才能更加深刻的理解这个神奇的生态环境。
