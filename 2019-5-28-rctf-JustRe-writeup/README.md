# JustRe

### 初步分析

使用32位的IDA打开文件

按 `shift+F12` 搜索字符串，找到了带有 `flag{%.26s}` 字样的字符串。根据交叉引用找到该字符串被引用的代码段

![](https://github.com/DayJun/Blogs/blob/master/2019-5-28-rctf-JustRe-writeup/Pics/0.PNG)

发现 `test eax,eax` 这句代码上方的代码IDA识别不出来。按下 `[space]` ，查看上方的代码是什么样的

![](https://github.com/DayJun/Blogs/blob/master/2019-5-28-rctf-JustRe-writeup/Pics/1.PNG)

我们发现它调用了这个函数，跟进去看一下

![](https://github.com/DayJun/Blogs/blob/master/2019-5-28-rctf-JustRe-writeup/Pics/2.PNG)

发现端倪了，这里使用了[SMC][0]技术。那么返回，查看上方的函数调用

经过分析，得知 `sub_401CE0` 的作用是获取输入；`sub_401610` 的作用就是对函数 `sub_4018A0` 进行解密

在 `sub_401610` 中看到这两个调用

![](https://github.com/DayJun/Blogs/blob/master/2019-5-28-rctf-JustRe-writeup/Pics/3.PNG)

`GetCurrentProcess` 的作用是获取当前进程的一个伪句柄  
`WriteProcessMemory` 的作用就是向进程的指定偏移写入内容

在这两个调用的上方就是解密的过程，其内使用了大量的 `xmm` 寄存器，IDA与OD都不能很好地识别这些指令，于是就转战x64debug

### 分析SMC解密函数

在 `401C2C` 处下断点，根据 `ECX` 的值得到了输入在内存中的位置，同时得知输入将会在 `sub_401610` 被使用

![](https://github.com/DayJun/Blogs/blob/master/2019-5-28-rctf-JustRe-writeup/Pics/4.PNG)

跟进函数一步步查看，就得到了函数的逻辑：

1. 将输入的前八位转换成数字，比如输入为 "12345678" ，就将它转换为 0x12345678，将其看作Num_0
2. 将转换后的数字拓展到128位，比如将 0x12345678 拓展为  0x12345678123456781234567812345678，将其看作Num_1
3. 将输入的第 9、10 位转换成数字，比如 "90" 转换成 0x90
4. 将转换后的数字拓展到128位，比如 0x90 拓展为 0x90909090909090909090909090909090，将其看作Num_2
5. 在 `403040` 有一个表，表中有总共 $128 * 4$ 字节的数据，将其看作数组A，共四项，每项128字节

![](https://github.com/DayJun/Blogs/blob/master/2019-5-28-rctf-JustRe-writeup/Pics/5.PNG)
6. `405018` 有一个表，该表有总共 $128 * 6$ 字节的数据，将其看作数组B，共六项，每项128字节，其中每项也是一个数组，该数组每项32字节

![](https://github.com/DayJun/Blogs/blob/master/2019-5-28-rctf-JustRe-writeup/Pics/6.PNG)
7. 进行如下运算
    * $B[0] = ( B[0] + Num_2 ) ^ ( A[0] + Num_1 )$
    * $B[1] = ( B[1] + Num_2 ) ^ ( A[0] + A[1] + Num_1 )$
    * $B[2] = ( B[2] + Num_2 ) ^ ( A[0] + A[2] + Num_1 )$
    * $B[3] = ( B[3] + Num_2 ) ^ ( A[0] + A[3] + Num_1 )$
8. 将输入的第 9、10 位拓展到32位，就此例，0x90 拓展为 0x90909090，将其看作 Num_3
9. 进行如下运算  
    ```
    for(int i = 0; i < 8; i++)  
    {
        B[4][i] = (B[4][i] + Num_3) ^ (Num_0 + 0x10 + i);
        B[5][i] = (B[5][i] + Num_3) ^ (Num_0 + 0x10 + 4 + i);
    }
    ```
10. 将运算完成的数据与 `404148` 的数据进行比对，如果全部比对成功，就开始将数据写入 `sub_4018A0` 的指定位置

![](https://github.com/DayJun/Blogs/blob/master/2019-5-28-rctf-JustRe-writeup/Pics/7.PNG)

### 得到前十位

使用Z3来解决这个方程，就实际而言，只需要解出第7步中第一个方程即可得到结果

由于Python的Z3模块我不会使用，所以我学习了一下Z3，用Z3官方教程页面的在线IDE [rise4fun][1] 进行了求解

代码如下  
```
(define-fun a() (_ BitVec 32) #x416214C8)
(define-fun b() (_ BitVec 32) #x01120DF0)
(define-fun c() (_ BitVec 32) #xED93C08B)
(define-fun d() (_ BitVec 32) #x7EB6971B)
(define-fun e() (_ BitVec 32) #x00000003)
(define-fun f() (_ BitVec 32) #x00000002)
(define-fun g() (_ BitVec 32) #x00000001)
(define-fun h() (_ BitVec 32) #x00000000)
(define-fun e0 () (_ BitVec 32) #x254e98b6)
(define-fun e1 () (_ BitVec 32) #x258e9db3)
(define-fun e2 () (_ BitVec 32) #x01121164)
(define-fun e3 () (_ BitVec 32) #x0a6210cf)
(declare-const x (_ BitVec 32))
(declare-const y (_ BitVec 32))
(declare-const x1 (_ BitVec 2))
(declare-const x2 (_ BitVec 2))
(assert (bvugt x #x00000000))
(assert (bvule x #xffffffff))
(assert (bvugt y #x00000000))
(assert (bvule y #x000000ff))
(define-fun c1 ((b1 (_ BitVec 32)) (b2 (_ BitVec 32)) (b3 (_ BitVec 32)) (b4 (_ BitVec 32))) (_ BitVec 32)
  (bvnot (bvxnor (bvadd b3 (bvmul b2 #x01010101)) (bvadd b4 b1)))
)
(define-fun c2 ((b1 (_ BitVec 32)) (b2 (_ BitVec 32)) (b3 (_ BitVec 32)) (b4 (_ BitVec 32))) (_ BitVec 32)
  (bvnot (bvxnor (bvadd b3 (bvmul b2 #x01010101)) (bvadd b1 b4)))
)
(assert (= (c1 x y a e) #x405004A1))
(assert (= (c1 x y b f) #x00000278))
(assert (= (c1 x y c g) #xEC81F0E4))
(assert (= (c1 x y d h) #x83EC8B55))
(check-sat)
(get-model)
```
最终得到了结果：`1324227812`

接下来重新启动程序，在 `401C38` 下断点，并清除原来的断点，接着进入 `sub_4018A0` 分析该函数的内容

### 3DES解密

`sub_4018A0` 是3DES解密的一个过程，找到key以后直接解密即可

![](https://github.com/DayJun/Blogs/blob/master/2019-5-28-rctf-JustRe-writeup/Pics/8.PNG)

上图从第9个字节开始即为key

[解密脚本][2]

### 总结

这题我没做出来，前面SMC部分还好说，后面这个3DES直接就不认识，也因为见识不广吃了大亏。不过还好，下次就认识了

[0]: https://baike.baidu.com/item/%E8%87%AA%E4%BF%AE%E6%94%B9%E4%BB%A3%E7%A0%81/1218702?fr=aladdin 
[1]: https://rise4fun.com/Z3/tutorial/guide
[2]: https://github.com/DayJun/Blogs/blob/master/2019-5-28-rctf-JustRe-writeup/Src/3DESdecrypt.py
