## 用openssl命令生成PKCS1#格式的RSA密钥对

``` openssl genrsa -out prikey.pem 1024 ```

> 上面这条命令可以生成一个PKCS#1格式的，PEM编码的，1024位的RSA私钥

## 从私钥中导出公钥

``` openssl rsa –in prikey.pem –RSAPublicKey_out –out pubkey.pkcs1.pem ```

> 这条命令可以从RSA私钥中PKCS#1格式的、PEM编码的RSA公钥

## 将前面的PKCS#1编码的RSA私钥转为PKCS#8编码的RSA私钥

``` openssl pkcs8 -topk8 -in prikey.pem -out prikey.pkcs8.pem -nocrypt ```

## 将前面的PKCS#1编码的RSA公钥钥转为X509中的RSA公钥

``` openssl rsa –in prikey.pem -pubout -out pubkey.x509.pem ```

