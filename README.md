# Pintools

## 摘要
基于malloctrace和一些其他例程，编写了对于\*alloc函数和free函数，以及R/W指令的tracer——rwcount.cpp*（后续改名）*

## 功能
- 按目标程序的image分类，追踪其调用的\*alloc和free函数，将参数和返回值写入文件。
- 按目标程序的image分类，追踪其调用的R/W指令，将指令读写的地址写入文件。

## 文件名规约
- 对函数的trace写入`*.func.out`
- 对指令的trace写入`*.inst.out`
- image全限定名与\*的对应关系写入`out.map`，格式为`"* ${full-qualified name}"`

**注：** 上述通配符\*表示由0开始递增的整数
