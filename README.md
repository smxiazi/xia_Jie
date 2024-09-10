# xia Jie (瞎解)
```
市面上很多类似的插件了，为什么还要重复造轮子呢
因为很多情况下
总有各种乱七八糟的问题，如不好查看最终修改后都数据包等信息
```
********************
* 通常用于自动化流量加密或解密
* 对burp的 请求包 和 响应包 用python完全自定义修改数据包的流量
********************
0x01 界面截图

<img width="1642" alt="image" src="https://github.com/user-attachments/assets/ef264d1f-e731-414d-a181-322d35e64351">

## 0x02 使用教程

1、启动插件
2、自定义修改好python脚本后运行，如下：我在头部添加了（abcd:1234）和 body体添加了 （&abcd=654321）

<img width="1718" alt="image" src="https://github.com/user-attachments/assets/bda9766d-7f66-40b7-ab01-fbcfb4370b20">

点击发送

<img width="1151" alt="image" src="https://github.com/user-attachments/assets/b671fe21-eff5-489f-b3d3-7c600507d0c7">


<img width="1418" alt="image" src="https://github.com/user-attachments/assets/98f1700d-021f-47d2-af31-ec4efaf93e21">

很多网站不是全部加密的，所以有些数据包需要解密or加密，需要多写几个if判断，哪些需要解密or解密 哪些不用

比如：

<img width="1249" alt="image" src="https://github.com/user-attachments/assets/2a83025d-a263-44ab-9839-0efcc186dfe7">

<img width="1174" alt="image" src="https://github.com/user-attachments/assets/ca7231c9-2ea4-43be-8648-baddc140f222">

<img width="1317" alt="image" src="https://github.com/user-attachments/assets/3994ec75-7589-4d73-9c81-24aae47a7746">

当然也支持右键加解密

<img width="1121" alt="image" src="https://github.com/user-attachments/assets/a4606b1c-82db-4134-abc8-b64a4e7fa390">

点击后会 加密

<img width="1218" alt="image" src="https://github.com/user-attachments/assets/ba98456d-f3f8-4db3-9c0d-ebc071c02123">

正常使用的话，先拿一段 待加密or解密 的数据测试

<img width="1045" alt="image" src="https://github.com/user-attachments/assets/8feda7bc-c128-4282-b066-3f2b20422ac1">

测试通过在注释掉，在运行run方法


