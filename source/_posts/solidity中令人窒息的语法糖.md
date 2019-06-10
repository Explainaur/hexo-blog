---
title: solidity中令人窒息的语法糖
date: 2019-03-18 17:25:26
tags:
    - tutorial
---

### Solidity函数的困惑  

---  

&emsp;&emsp;关于Solidity我看的是不明不白，主要是web3的api几乎一无所知，而且对区块链的理解也不够深刻，在此记录一下一些令我窒息的语法糖。  

#### 1. 关于函数的可见型与访问控制  

&emsp;&emsp;Solidity封装了两种函数调用方式 **`internal`** 与 **`external`**   

- **internal** 

&emsp;&emsp;internal调用，实现时转为简单的EVM跳转，所以他能够直接访问上下文的数据，对于引用传递是十分高效，例如memory之间的值传递，实际上是引用的传递(妈耶，storage和memory又是坑，不同版本真是令人窒息)。  

&emsp;&emsp;当前代码单元内，比如同一个合约内的函数，引入的library库，以及父类函数的直接调用即为internal调用，比如：  

```solidity
pragma solidity >=0.4.0 < 0.6.0;

contract test{
    function a() internal {}

    function b() internal {
        a();
    }
}
```

&emsp;&emsp;在上述代码中的b()对a()的调用即为internal方式调用，函数在不显式声明访问类型时,以目前的版本来看会报错。

- **external**  

&emsp;&emsp;external调用实现了合约的外部消息调用。所以合约在初始化时不能以external的方式调用自身函数，因为此时合约仍未构造完成，此处可类比struct类型，一个结构体不能包含自身对象。但是可以以this的方式强制进行external调用。  

```solidity
pragma solidity >= 0.4.0 < 0.6.0;
contract test{
    function  a() external {}

    function b() public {
        a();  //此时会报错
    }

    contract ext{
        function callA(test tmp) public {
            tmp.a();
        }
    }
}
```
- **public**  

&emsp;&emsp;public的特点是，函数既可以以internal方式调用，也可以用internal方式调用。public函数可以被外部接口访问，是合约对外接口的一部分。 
```solidity
pragma solidity >= 0.4.0 < 0.6.0

contract test{
    function fun1() public{}

    funciton fun2() public {
        fun1();
        this.fun2();
    }
}
```
&emsp;&emsp;可以看到没有报错，既然public这么舒服，那为啥我还要用external？？？  

&emsp;&emsp;经过对比后我们可以发现，external方法消耗的gas要比public少，因为Solidity在调用public函数时会将代码复制到EVM的内存中，而external则是以calldata的方式进行调用的。内存分配在EVM中是十分宝贵的，而读取calldata则十分廉价，因此在处理大量外部数据，并反复调用函数时，应当考虑用external方法。  

&emsp;&emsp;这里应当注意的是，public属于可见性。函数的可见性分为四种：**public private internal external** .  

- **private**  

&emsp;&emsp;对于private，与internal的区别是，private的方法在子类中无法调用，即使被声明为private也不能阻止数据的查看。访问权限仅仅是限制其他合约对函数的访问和数据修改的权限。而private方法也默认以internal的方式调用。  

```solidity
pragma solidity >= 0.4.0 < 0.6.0;

contract test{
    function fun1() private{}

    function fun2() public{
        fun1();
        //this.fun1()
    }
}

//合约的继承为is，这一点很容易理解，如果你明白设计模式的话，实际上继承是A is B 的关系,我很喜欢这种写法。

contract ext is test{   
    function callFun() public {
        //fun1();   
        fun2();
    }
}
```
&emsp;&emsp;这里我们可以明确的看到private的效果，和internal类似，但是代价会更大。  

&emsp;&emsp;然而 **public** 与 **private** 还可以被作用于其他的变量，用于设置外部访问权限。  

&emsp;&emsp;请大家务必不要弄混 **调用方式** 与 **可见性(visable)** 。  


- **this** 

&emsp;&emsp;在Solidity中，this与其他高级语言意义不同，这里的this指的是当前合约的一个实例化对象，而并不是只的合约本身，this可以理解为实现external调用的一种方式，在初始化未完成时强制调用external类型方法。而并不能指代当前合约类型。
```solidity
pragma solidity >= 0.4.0 < 0.6.0;

contract test{
    function fun1() external{}

    function fun2() public{
        this.fun1();
    }
}
```
- **getter**  

&emsp;&emsp;编译器会为公共状态变量提供一个getter(访问器)函数，对mapping和数组以及枚举类型也提供了对应的getter，mapping的key 数组的下标 枚举的名都具有getter，访问器的visable为external。  

---  

#### 2. 关于 view pure constant  

&emsp;&emsp;在0.4.1之前只有constant这一种可爱的语法，就是有一些屁事很多的人觉得constant指的是变量，作用于函数不太合适，所以就把constant拆成了view和pure。  

&emsp;&emsp;在Solidity中，**constant view pure** 的作用是告诉编译器，函数 **不改变**，**不读取**状态变量，这样一来函数的执行就不再消耗gas了，因为不再需要矿工去验证。  

&emsp;&emsp;然而这三个东西有点有意思，在官方文档中用 **restrictive** 这一词来对函数的严格性进行描述，在函数类型转换时对严格行有一定的要求，高严格性函数可以被转化为低严格性函数：  

- ** pure ** 类型可被转化为 **view** 和 **non-payable** 函数  

- **view** 类型可被转化为 **non-payable** 函数  

- **payable** 类型可被转化为 **non-payable** 函数  


&emsp;&emsp;真是令人头秃！

![toutu](https://github.com/Explainaur/hexo-blog/blob/master/source/pictures/toutu.jpg?raw=true)  

