## ��openssl��������PKCS1#��ʽ��RSA��Կ��

``` openssl genrsa -out prikey.pem 1024 ```

> �������������������һ��PKCS#1��ʽ�ģ�PEM����ģ�1024λ��RSA˽Կ

## ��˽Կ�е�����Կ

``` openssl rsa �Cin prikey.pem �CRSAPublicKey_out �Cout pubkey.pkcs1.pem ```

> ����������Դ�RSA˽Կ��PKCS#1��ʽ�ġ�PEM�����RSA��Կ

## ��ǰ���PKCS#1�����RSA˽ԿתΪPKCS#8�����RSA˽Կ

``` openssl pkcs8 -topk8 -in prikey.pem -out prikey.pkcs8.pem -nocrypt ```

## ��ǰ���PKCS#1�����RSA��ԿԿתΪX509�е�RSA��Կ

``` openssl rsa �Cin prikey.pem -pubout -out pubkey.x509.pem ```

