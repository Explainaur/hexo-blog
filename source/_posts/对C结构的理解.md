---
title: 对C结构的理解
date: 2018-12-02 21:07:16
tags:
    - thinking
categories:
    - C
---
### 记录一下学习C结构的想法  
---  
  
 我认为结构这种数据类型为C++奠定了面向对象的基础。这是一种很自由的数据类型，我们甚至可以用指针和结构实现面向对象。  
   
   * **关于结构的声明**    
   
   ```c  
   struct name{  
     　type1 a;
     　type2 b;　　
   };       //注意这里的分号   
```

  这里的声明并未创建一个实际的数据对象，而是描述了这类对象的元素形式，我们也可以将结构声明称之为模板，因为他勾勒出数据将如何存储。  
  之后我们声明name结构的变量：  
 
 ```c  
  struct name dyf;    
 ```
  当编译器读到这条指令时，它将以name模板为dyf分配内存空间，即使未初始化，该结构的大小也由type1 与 type2 的大小决定。这就意味着结构的大小可能会大于数据集本身，因为系统对数据的对齐要求会导致存储裂缝。  
  再者，我们可以如下声明：  

  ```c  
  struct name {  
  　　type1 a;  
  　　type2 b;　　  
  } dyf;  
    ```
  即声明结构与定义结构的过程合二为一，如果要多次使用一个模板我们也可以用typedef。  
  ---  
    
      
 * **关于结构的初始化**  
```c
 struct book {  
   char name[20];
   int  weight[20];
 };  
 
 struct book math{
   "高等数学"，
   20
 };
```
 
非指定初始化应当保持初始化项目与结构成员类型一一对应。  
而指定初始化则类似于数组：  
     
 
```c  
     
    struct book dyf{
      .name="高等数学",
      .weight=10      
    }；  
```
  
其中的.name类似于数组的下标，寻址自然与数组类似。  

---  

* **关于结构数组的声明**  

```c  
struct book library[20];
library[2].name="高等数学";  //代表library的第三个元素的那么成员
```
此时，[2]是library的下标，应当注意区别：  
```c  
library[2].name;
library.name[2];  
```

后者指的是library的第一个成员的name的第三个字符。  

---  

* **关于嵌套结构**  

有时候我们会在一个结构中嵌套另一个结构例如：  

```c  
struct name{ 
  char firstname[20];
  char lastname[20];
};

struct person {
  struct name dyf;
  int age;
  int height;
};  
```

只需在外层结构中声明即可，同理，使用两次点运算符进行访问：  

```c  
person.dyf.name="dyf";  
```
---  

*  **指向结构的指针**  
我们可以通过指针来传递并访问结构，这种操作非常舒服。  
* 声明与初始化指针： 
    

```c  
      struct person {
        struct name dyf;
        int age;
        int height;
      };

      struct person * p;    //定义一个只想person结构类型的指针p

      p = &dyf;    //将dyf的地址赋值给指针p  
```
    
p指针在被定义后只能指向person的结构类型，储存person结构的地址。  
与数组不同的是，结构的名并不代表首个成员的地址，因此必须使用&操作符。  
      
                                  
* **指向结构的指针**  
    
我们可以通过指针来传递并访问结构，这种操作非常舒服。  

*   声明与初始化指针： 

```c  
      struct person {
        struct name dyf;
        int age;
        int height;
      };
     
      struct person * p;    //定义一个指向person结构类型的指针p
     
      p = &dyf;    //将dyf的地址赋值给指针p  
      
      struct book * m;
      m = &library[2];    //同理，结构数组内的结构如图赋值
```
p指针在被定义后只能指向person的结构类型，储存person结构的地址。  
与数组不同的是，结构的名并不代表首个成员的地址，因此必须使用&操作符。  
     
* 使用指针访问成员：  
此时我们可以引入一个新的运算符"->"。例如：  
     
     ```c  
      m->name == library[2].name;
      
      m == &library[2];  //m存的地址即为library[2]的地址
     
      printf("%d",m->name);   //打印library[2].name 即高等数学  
      ```
m -> value 此操作符意味着取m地址中存的结构的成员，即：  
    
    ```c  
     m -> value.name == (*m).name == library[2].name;  
     ```
     注意：`' * '` 的运算级大于` ' . '`　使用时注意加()  

---  

* **向函数传递结构**  

只要结构具有单个值的数据类型，即：int及其相关类型、char、float、double、指针等，就可以把它作为一个参数传递给函数，如：  

```c  
#include<stdio.h>
struct name{
  char firstname[20];
  char lastname[20];
};
struct person {
  struct name myname;
  int age;
  int height;
};
void getInfo(struct person * p);
void outIbfo(struct person * p);
int main(void){ 
  struct person dyf;
  struct person * p;
  p = &dyf;
  getInfo(p);
  outInfo(p);
return 0;
}

void getInfo(struct person * p){
  printf("please enter your firstname\n");
  scanf("%s",&((*p).myname.firstname));        //注意理解这里
  printf("please enter your last name\n");
  scanf("%s",&((p->myname).lastname));         //注意理解这里
  printf("please enter your age\n");
  scanf("%d",&(p->age));
  printf("please enter your height\n");
  scanf("%d",&(p->height));
}

void outInfo(struct person * p){
  printf("\nname\t);
  printf("%s %s\n",(p->myname).firstname,(p->myname).lastname);
  printf("age   %d\n",p->age);
  printf("height    %d\n",p->height);
}
```
以上是利用指针来传递结构参数，应当深刻理解'->'的意义。  

```c
p->dyf;    //这仅仅是获得dyf变量的名而不是其地址  等价于(*dyf)  
```

但`scanf()`需要传递给地址，因此我们需要使用&操作符。如果你理解了以上两种寻址方式，那么你对->的理解算是合格了。但距离用结构和指针实现面向对象还有一定距离。顺便说一句，我们通常用结构和指针实现队列的数据结构，好好理解指针吧。  

当然除了以上这种用指针传递参数的方式，我们还可以直接用结构的名传递参数。  
```c  
struct yourmark {
  int math;
  int English;
};

double mark(struct yourmark mark ){
  return mark.math + mark.English;
}  
```
这种传参方式很自然也很好理解，但是这毕竟只是赋值给形参，因此如果想改变元数据，我们依旧要使用指针。  
  
  如果要返回struct则： 
  ```c 
  struct yourmark{
    int math;
    int English;
  };
  struct yourmark getmark(struct yourmark mark){      // 此处的返回类型为yourmark结构类型
    printf("please enter your math mark and English mark\n");
    scanf("%d%d",&(mark.math),&(mark.English));
    return mark
  }
  
  struct yourmark mark;
  mark = getmark(mark);   // 注意，给结构赋值时直接用其名而不是其地址  
  ```
  同理，要返回指针只需要`struct yourmark * mark getmark(struct yourmark mark)`
  
好了到这里，把结构在函数里传来传去已经差不多说完了。  

---  

* **复合文字和结构** 

C99引入了一些新的概念，比如变长数组(VLA)、复合文字(compound literal)、指针的兼容性等。  
  
  复合文字的意思：  
  假如我要给函数传递参数，我可以传递一个变量也可以传递一个常量，例如：  
  ```c  
  int a=2,b=3;
  sum(a,b)==sum(2,3);  
  ```
  但是对于数组或者结构来讲我们之前没有说过常量这个概念，在传递参数时或者向另一结构传递时可能要定义新的变量，很浪费内存。此时，便引入了复合文字这一概念。  
  声明如下：  
  ```c  
  struct person {
    char name[20];
    int age;
  };
  
  struct person guy;     //定义一个person结构类型的结构
  
  guy = (struct person){"dyf",18};   //把复合文字赋值给guy  
  
  outInfo((struct person){"麂皮"，18})；  //将一个匿名结构作为实参传递给函数  
  
  struct class23 {
    (struct person){"dyf",18};
    (struct person){"麂皮"，18};
  };                                    //将两个匿名结构传递给class23
  
  -------------------------------------------------------------------  
  
  #include <stdio.h>
  struct mark {
    int math;
    int English;
  };
  int mark(struct mark * p);       //声明一个参数为mark结构的指针的函数
  int main(void){
    printf("%d",mark(&(struct mark ){150，150}))；   //传递复合文字的地址
    return 0;
  }
  int mark(struct mark * p){
    return p->math + p->English；
  }
  
  /* 注：用G++编译会报错，因为其地址是temporary 而C99版本的GCC是可行的,因为临时具有自动储存时期，而在函数外具有静态储存时期 */
  ```
这是复合文字的大概用法，他能够创建一个匿名常量对象，直接在结构体或者函数中传递的常量。  

---  

* **伸缩性数组成员**  

C99加入了一个成为伸缩性数组成员(flexible array member)的新特性,该特性允许结构的最后一个成员是一个具有特殊属性的数组结构，
该数组的属性之一就是他并不立即存在。创建规则如下：  
  
1. 伸缩性数组成员必须是最后一个成员  
2. 结构中至少有一个其他成员  
3. 像普通数组那样声明，只是长度不定，例：`int a[];`  

如下：  
```c  
struct mark{
  int average;
  char subjects[]   //伸缩数组成员
}；  
```

此时subjects[]并未被创建，系统没有为他分配足够的内存空间。通常我们要使用伸缩数组时，都会为其先分配足够的内存空间。

```c
    struct mark * p;
    p=malloc(sizeof(struct mark) + 20 * sizeof(char));
```
这时我们已经有足够的内存来存放一个mark型结构，并且他可以存放一个19个字符的字符串。没错，开辟的内存空间要能存放结构本身和所需大小的数组。

```c
    #include <stdio.h>
    #include <malloc.h>
    int main(void) {
        struct flex{
            int age;
            char * name;
            char * favobook[20];    //思考一下，他在main()中能直接赋值吗
            int favonumber[];
        };
        struct flex * p;
        p = malloc(sizeof(struct flex)+6* sizeof(int));
        p->age=18;
        p->favonumber[7]=1;
        p->name="dyf";
        printf("%s \t %d \t %d",p->name,p->age,p->favonumber[7]);
        return 0;
    }
```
这里我们声明里一个指针name，要注意在C语言中，字符串以数组的形式存储，也就是说其变量名实际是个地址，在我们对其进行声明时计算机已经为他在内存中开辟了空间，所以其地址实际上是个常量，即name是个常量。假如我要进行`name="dyf";`操作，编译器将报错。`"dyf"`的地址很明显与`name`本身冲突，故不能直接赋值。
这里我们看到favonumber能存8个整数，我也不知道为什么，回去查查资料再来修改。

---

* **将结构存到文件中**  

结构的整套信息我们称之为记录(record),单个的项目称之为字段(field)，下面，我们来进行讨论。  
第一种方法，也是最笨拙的方法，使用`fprinf()`函数，例如：

```c
    struct book{
    char title[20];
    char author[20];
    double value;
    };
    struct book math;
    fprintf(books, "%9s %9s %7.2d",math.title,math.author,math.value);
```

我们使用`%9s`来固定输入格式，以便于下一次读取,这里的books是文件流。
  
第二种方法，我们可以使用fread()和fwrite()以结构大小为单位来进行读写，例如：
```c
    fwrite(&math,sizeof(struct book),1,books)
```
这时我们将定位到math的地址`sizeof(struct book)`将返回一块book结构的大小，`'1'`则告诉函数只需复制一块结构，最后将整个record写入`books`相关联的文件。同样`fread()`将record写入`&math`地址。  
  
---  
    
*  **衍生出的其他数据类型**
  
通过对结构体进行封装，C中还有联合又称为共用体(union)、枚举(enumerated type)两种类型。首先，union声明如下：
```c
    union id{
        char id_string[20];
        int id_int;
    };
```
假如一个物体的id有可能是整数，也有可能是字符串，那么我们可以用以上操作。  
union并不是复合结构,这其中的声明的类型只能同时存在一种，也就是说id可以是字符串类型，也可以是int类型。
因此，我们可以声明一个union数组来存放不同类型的数据，这样就实现了混合数据类型存储。这种数据类型封装的方法与结构相同，同样支持`. ->`等运算符，但是其意义却完全不同。
其次，枚举类型声明如下：
```c
    
    enum subjects {math=,English=2,Chinese,CS};
    enum subjects my_favo_subject;
    for(my_favo_subject=math;my_favo_subject<=CS;my_favo_subject++){
      printf("%d\n",my_favo_subject);
    }
```
我们通常用枚举创建符号常量，例如，
`math，CS`是枚举常量，默认为int类型，math是枚举对象的首元素，其默认值为0，这就好比数组的下标，方便我们进行枚举。我们也可以给枚举常量一个指定值，例如上面`English=2`，那么，其后面的元素依次从2递增。由于枚举类型是一个整数类型，所以我们常将其用于表达式当中，方便进行逻辑判断或者运算。  
**注：**  
C语言支持枚举变量自增，即`my_favo_subject++;`但是C++不支持，注意代码兼容性。

--- 

*  **用结构实现链表**  
  

dyf is cool.

  
     
     
---

*  **用结构实现面向对象**  

    
