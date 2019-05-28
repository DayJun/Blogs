# JustRe

### ��������

ʹ��32λ��IDA���ļ�

�� `shift+F12` �����ַ������ҵ��˴��� `flag{%.26s}` �������ַ��������ݽ��������ҵ����ַ��������õĴ����

![](https://github.com/DayJun/Blogs/blob/master/2019-5-28-rctf-JustRe-writeup/Pics/0.PNG)

���� `test eax,eax` �������Ϸ��Ĵ���IDAʶ�𲻳��������� `[space]` ���鿴�Ϸ��Ĵ�����ʲô����

![](https://github.com/DayJun/Blogs/blob/master/2019-5-28-rctf-JustRe-writeup/Pics/1.PNG)

���Ƿ������������������������ȥ��һ��

![](https://github.com/DayJun/Blogs/blob/master/2019-5-28-rctf-JustRe-writeup/Pics/2.PNG)

���ֶ����ˣ�����ʹ����[SMC][0]��������ô���أ��鿴�Ϸ��ĺ�������

������������֪ `sub_401CE0` �������ǻ�ȡ���룻`sub_401610` �����þ��ǶԺ��� `sub_4018A0` ���н���

�� `sub_401610` �п�������������

![](https://github.com/DayJun/Blogs/blob/master/2019-5-28-rctf-JustRe-writeup/Pics/3.PNG)

`GetCurrentProcess` �������ǻ�ȡ��ǰ���̵�һ��α���  
`WriteProcessMemory` �����þ�������̵�ָ��ƫ��д������

�����������õ��Ϸ����ǽ��ܵĹ��̣�����ʹ���˴����� `xmm` �Ĵ�����IDA��OD�����ܺܺõ�ʶ����Щָ����Ǿ�תսx64debug

### ����SMC���ܺ���

�� `401C2C` ���¶ϵ㣬���� `ECX` ��ֵ�õ����������ڴ��е�λ�ã�ͬʱ��֪���뽫���� `sub_401610` ��ʹ��

![](https://github.com/DayJun/Blogs/blob/master/2019-5-28-rctf-JustRe-writeup/Pics/4.PNG)

��������һ�����鿴���͵õ��˺������߼���

1. �������ǰ��λת�������֣���������Ϊ "12345678" ���ͽ���ת��Ϊ 0x12345678�����俴��Num_0
2. ��ת�����������չ��128λ�����罫 0x12345678 ��չΪ  0x12345678123456781234567812345678�����俴��Num_1
3. ������ĵ� 9��10 λת�������֣����� "90" ת���� 0x90
4. ��ת�����������չ��128λ������ 0x90 ��չΪ 0x90909090909090909090909090909090�����俴��Num_2
5. �� `403040` ��һ�����������ܹ� $128 * 4$ �ֽڵ����ݣ����俴������A�������ÿ��128�ֽ�

![](https://github.com/DayJun/Blogs/blob/master/2019-5-28-rctf-JustRe-writeup/Pics/5.PNG)
6. `405018` ��һ�����ñ����ܹ� $128 * 6$ �ֽڵ����ݣ����俴������B�������ÿ��128�ֽڣ�����ÿ��Ҳ��һ�����飬������ÿ��32�ֽ�

![](https://github.com/DayJun/Blogs/blob/master/2019-5-28-rctf-JustRe-writeup/Pics/6.PNG)
7. ������������
    * $B[0] = ( B[0] + Num_2 ) ^ ( A[0] + Num_1 )$
    * $B[1] = ( B[1] + Num_2 ) ^ ( A[0] + A[1] + Num_1 )$
    * $B[2] = ( B[2] + Num_2 ) ^ ( A[0] + A[2] + Num_1 )$
    * $B[3] = ( B[3] + Num_2 ) ^ ( A[0] + A[3] + Num_1 )$
8. ������ĵ� 9��10 λ��չ��32λ���ʹ�����0x90 ��չΪ 0x90909090�����俴�� Num_3
9. ������������  
    ```
    for(int i = 0; i < 8; i++)  
    {
        B[4][i] = (B[4][i] + Num_3) ^ (Num_0 + 0x10 + i);
        B[5][i] = (B[5][i] + Num_3) ^ (Num_0 + 0x10 + 4 + i);
    }
    ```
10. ��������ɵ������� `404148` �����ݽ��бȶԣ����ȫ���ȶԳɹ����Ϳ�ʼ������д�� `sub_4018A0` ��ָ��λ��

![](https://github.com/DayJun/Blogs/blob/master/2019-5-28-rctf-JustRe-writeup/Pics/7.PNG)

### �õ�ǰʮλ

ʹ��Z3�����������̣���ʵ�ʶ��ԣ�ֻ��Ҫ�����7���е�һ�����̼��ɵõ����

����Python��Z3ģ���Ҳ���ʹ�ã�������ѧϰ��һ��Z3����Z3�ٷ��̳�ҳ�������IDE [rise4fun][1] ���������

��������  
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
���յõ��˽����`1324227812`

�������������������� `401C38` �¶ϵ㣬�����ԭ���Ķϵ㣬���Ž��� `sub_4018A0` �����ú���������

### 3DES����

`sub_4018A0` ��3DES���ܵ�һ�����̣��ҵ�key�Ժ�ֱ�ӽ��ܼ���

![](https://github.com/DayJun/Blogs/blob/master/2019-5-28-rctf-JustRe-writeup/Pics/8.PNG)

��ͼ�ӵ�9���ֽڿ�ʼ��Ϊkey

[���ܽű�][2]

### �ܽ�

������û��������ǰ��SMC���ֻ���˵���������3DESֱ�ӾͲ���ʶ��Ҳ��Ϊ��ʶ������˴�����������ã��´ξ���ʶ��

[0]: https://baike.baidu.com/item/%E8%87%AA%E4%BF%AE%E6%94%B9%E4%BB%A3%E7%A0%81/1218702?fr=aladdin 
[1]: https://rise4fun.com/Z3/tutorial/guide
[2]: https://github.com/DayJun/Blogs/blob/master/2019-5-28-rctf-JustRe-writeup/Src/3DESdecrypt.py
