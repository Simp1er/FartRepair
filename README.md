# FartRepair
依赖于寒冰师傅的FART的针对函数抽取壳的修复脚本
## 使用方法
```
python repair.py -d <dumpdexfile> -i <insfile> (-m <method_name> | -a)
```
`-d`参数后跟FART dump下来的dex
`-i`参数后跟FART 主动执行产生的bin文件
`-m`参数后跟想要修复的函数名
`-a`参数，依据bin文件修复所有函数
如果apk采用的函数抽取壳并未删去抽取的空间，此时`-a`参数可以正常使用，但是如果apk中抽取函数的空间都没有了，如果想一次性修复所有函数，建议还是使用寒冰师傅的[fart.py](https://github.com/hanbinglengyue/FART)，不过如果修复单个函数，使用`-m`参数即可

## 最后
如有bug，欢迎指摘
