<h4 align="center" dir="rtl">
  Rumi
  &#x200F;<br>گفتم به نگار من کز جور مرا مشکن     ,     گفتا به صدف مانی کو دُر به شکم دارد
  <br>تا نشکنی ای شیدا آن دُر نشود پیدا     ,      آن دُر بُتِ من باشد یا شکل بُتم دارد
  <br>
</h4>


<br>



<h6 align="center" dir="ltr">
  &#x200F; میتوانید زبان داکیومنت را تغییر دهید📖
  <br><a href="/README.md">1️⃣English</a> &nbsp; | &nbsp; <a href="/README-FA.md">2️⃣فارسی</a>
</h6>


<br>




<h1 align="center" dir="rtl">
  &#x200F;🚀Sonchain - ابزاری مبتنی بر شبکه 
  <br> 
</h1>

<p align="center" dir="rtl">
  <img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License">
  <img src="https://img.shields.io/badge/Version-4.0.0-green.svg" alt="Version">
  <img src="https://img.shields.io/badge/Python->=3.7-blue.svg" alt="Python">
</p>



<a id="about"></a>
## <br><br>🕵🏻‍♂️ از ‏نمای کلی : 
&#x200F;**Sonchain یک اسکریپت در حال توسعه است که با ترکیب نرم افزار های wrapper قدرتمند , و ابزار های vpn-proxy داخلی ( فعلا tor و Psiphon) یا خارجی , و ابزار های دیگر
<br>امکان اجرای دستورات , برنامه‌ها و... از طریق پروکسی و رفع محدودیت‌های ارتباطی مبتنی بر IP  , DNS و جغرافیایی و قابلیت های گسترده تر دیگر را فراهم می‌کند. این ابزار برای سهولت ارتباط ، تست‌های امنیتی و استفاده‌های تخصصی طراحی شده است.**


<br><br><br>














<a id="Introduction"></a>

<table dir="rtl" width="100%">
<tr>
<td>

&#x200F; ****SonChain نسخه 4.0.0****

## 🔍 معرفی و قابلیت‌ها

&#x200F; <br> **SonChain** اسکریپتی در حال توسعه است که با ترکیب نرم‌افزارهای wrapper قدرتمند و ابزارهای VPN/Proxy (فعلاً Tor و Psiphon) به شما امکان می‌دهد دستورات و برنامه‌ها را از طریق پروکسی اجرا کنید و محدودیت‌های ارتباطی مبتنی بر IP، DNS، جغرافیایی و... را رفع کنید. در ادامه به برخی از کاربردهای کلیدی و جزئیات فنی آن می‌پردازیم:

&#x200F;<br> ─| **اجرای دستورات از طریق پروکسی :**

دستورات قابل استفاده با توجه به ابزار های موجود : dnsson - proxyson - proxychains4 - socksify

  <ul dir="rtl" style="text-align: right;">
    <li> <b>dnsson :</b> به‌طور موقت تنظیمات DNS سیستم را به DNS پروکسی تور تغییر می‌دهد تا درخواست‌های DNS مانند <code>dig</code> از طریق پروکسی ارسال شوند.</li>
    <li> <b>proxyson :</b> علاوه بر تغییر DNS، ترافیک TCP دستورات شما را از طریق پروکسی هدایت می‌کند؛ این ابزار به صورت داخلی از <code>socksify</code> یا <code>proxychains4</code> استفاده می‌کند (بنابراین یکی از آن‌ها باید نصب شده باشد).</li>
    <li> <b>proxychains4 و socksify :</b> این ابزارها نیز برای هدایت ترافیک نرم‌افزار و دستورات از طریق پروکسی کاربرد دارند، اما استفاده مستقیم از <code>socksify</code> ممکن است باعث نشت DNS شود.</li>

  </ul>

   &#x200F;<br> ─| **مثال از نحوه استفاده :**  
**▪️ برای استفاده کافیست "دستور فراخوانی ابزار" را قبل از "دستور اصلی" قرار دهید :**  

`proxyson apt update`    
`proxychains4 apt update`  
`dnsson dig example.com`  
`socksify curl example.com`  

&#x200F; `و یا نصب پکیج ها از مخازن محدود شده , و...`


&#x200F;<br> ─| **نمونه  مثال استفاده از قابلیت پورت‌های اختصاصی Tor و Psiphon  :** 
  
  - &#x200F;**DNS پروکسی تور:** می‌توانید از IP و PORT اختصاص یافته به DNS پروکسی تور به عنوان nameserver یا resolver پروکسی با قابلیت رفع محدودیت های مختلف بهره ببرید؛ این تنظیمات تنها محدودیت‌های لایه DNS را برطرف می‌کند.
  - &#x200F;**پروکسی TOR و Psiphon :** با IP و PORT مربوط به SOCKS TOR یا  Psiphon SOCKS|HTTP به عنوان خروجی امن برای انتقال ترافیک برنامه یا ترافیک مورد نظر یا سایر کاربردهای شبکه‌ای مورد استفاده قرار می‌گیرد.

&#x200F;<br> ─| **رفع محدودیت‌های ارتباطی در سطح سرور یا بخش‌های خاص :**  
   - با استفاده از DNS یا socks داخلی Tor هدایت ترافیک و یا حل دامنه از طریق پروکسی، امکان رفع محدودیت‌ها را در کل سرور یا قسمت‌هایی مانند پنل‌های VPN و... فراهم می‌کند.
   - همچنین، این ابزار به شما اجازه می‌دهد چندین لایه پروکسی را به‌صورت همزمان, زنجیره‌ای, رندوم, و... اجرا کنید تا باعث کاهش ریسک شناسایی و... در تست‌های امنیتی یا استفاده‌های تخصصی شود.
 - &#x200F;SonChain یک راه‌حل منعطف برای عبور از محدودیت‌های ارتباطی است که به کاربران امکان می‌دهد بدون نیاز به تغییرات دستی، دستورات خود را به‌سادگی از طریق پروکسی اجرا کنند و در عین حال از مزایای استفاده از پورت‌های اختصاصی تور بهره‌مند شوند.    

  

&#x200F;<br> ─| **محدودیت‌ها :**  
  - **برخی برنامه‌ها ممکن است به دلیل مکانیزم عملکرد proxychains-Ng و socksify اجرا نشوند.**  
  - **درحال حاظر socksify امکان انتقال ترافیک udp را دارد اما به دلیل محدودیت های Tor امکان انتقال ترافیک udp بر بستر socks پروکسی Tor وجود ندارد مگر اینکه از socks دیگری استفاده کنید .**  
---

## جمع‌بندی

&#x200F;**SonChain** در یک نگاه,  
راهکاری کاربردی برای عبور از محدودیت‌های شبکه‌ای مبتنی بر IP, DNS جغرافیایی و... است.  
با ترکیب ابزارهای گوناگون و ارائه قابلیت‌هایی نظیر اجرای موقت دستورات از طریق پروکسی, تغییر موقت, DNS, و پشتیبانی از SOCKS|DNS داخلی Tor, و Psiphon SOCKS|HTTP این اسکریپت انعطاف‌پذیری بالایی در مدیریت ترافیک شبکه فراهم می‌کند.  
امکان استفاده از چندین لایه پروکسی به‌صورت زنجیره‌ای , رندوم و... علاوه بر سهولت استفاده، در سناریوهای امنیتی یا تخصصی، سطح پنهان‌کاری و مقاومت در برابر شناسایی را افزایش می‌دهد , همچنین در آینده قابلیت های بیشتری به این پروژه اضافه خواهد شد.

</td>
</tr>
</table>























<br><br><br>
<a id="list"></a>

## 📑 فهرست مطالب

- [🚀 نمای کلی پروژه](#about)
- [🔍 معرفی و قابلیت‌ها](#Introduction)
- [📜 مجوز](#license)
- [⚠️ رفع مسئولیت](#Caution)
- [⚠️ راهنما/داکیومنت](#docs)
- [✨ ویژگی‌ها](#features)
- [🛠️ پیش‌نیازها](#prerequisites)
- [⚙️ نصب](#installation)
- [📖 راهنمای منو و گزینه ها](#guide)
- [📞 تماس](#contact)
- [🙏 با تشکر از](#thanks)
- [🤝 حمایت مالی](#Financialsupport)
---



<br><br><br>

<a id="license"></a>
## 📜 مجوز (MIT License)
**این پروژه تحت مجوز MIT منتشر شده است.**
- حق نشر متعلق به Kalilovers  [https://github.com/kalilovers] است و هرگونه حذف نام توسعه‌دهنده، انتشار و تغییر و... بدون ذکر منبع ممنوع است.
- فورک , اصلاح و... پروژه با حفظ مشخصات و درج اطلاعات مالک مجاز است.
- برای مشاهده متن کامل مجوز MIT، به [LICENSE](/LICENSE) مراجعه کنید.



<br><br><br>

<a id="Caution"></a>
## ⚠️ رفع مسئولیت :
این پروژه برای سهولت در ارتباط توسعه دهنده ها و کاربران با مخازن محدود شده و استفاده های مشابه , تست های شبکه ای و موارد مشابه , کاربرد های امنیتی و... و همچنین استفاده جداگانه از تمام قابلیت های ابزار های **فعلی** قرار گرفته در اسکریپت ;
- &#x200F;**Tor - Psiphon - ProxyChains - Dante/Socksify** [نرم افزار های رسمی]  
- **DNSSon & ProxySon**  [ایجاد شده توسط سازنده پروژه]

<br> با ترکیب ابزار های مختلف رسمی یا ارتقا یافته غیر رسمی و اسکریپت های اختصاصی طراحی شده ,
<br> در بخشی از موارد نیاز به دانش فنی بیشتری میباشد - همچنین توصیه میشود که **قسمت اسناد/راهنما را حتما مطالعه کنید** ,

⚠️ **مسئولیت هرگونه استفاده و یا سو استفاده از این پروژه به طور کامل بر عهده کاربر می‌باشد. سازنده و توسعه‌دهندگان پروژه هیچ مسئولیتی در قبال مشکلات و.. ناشی از استفاده نادرست یا سوء استفاده از این ابزارها نمی‌پذیرند.**

- [↪️ بازگشت به فهرست مطالب](#list)







&nbsp;
<br><br><br>
<a id="features"></a>
## 🚀 جزییات عملکرد فعلی خود اسکریپت :
&nbsp;
<br>**🔥 "تمام موارد زیر به مرور بهینه تر شده و ارتقا خواهد یافت"**
<br>**🔥 "بسیاری از ویژگی ها از نسخه فعلی حذف شده که در نسخه های بعدی در صورت لزوم با بهینه سازی به نسبت نیاز کاربران افزوده خواهد شد"**
- **✅ نصب/حذف , مدیریت و پیکربندی Tor , Psiphon , ProxyChain-Ng و Socksify**
- **✅اسکریپت های ProxySon و DnsSon توسط Kalilovers برای سهولت بیشتر , جلوگیری از نشت DNS هنگام اجرای دستورات و کاربرد های دیگر برای کاربر طراحی شده.**
- **&#x200F;✅ Status های مخصوص برای بررسی وضعیت ابزار های موجود.**
- **📜 کانفیگ Tor  , Psiphon , ProxyChain-Ng و Socksify در ابتدای نصب به صورت پیشفرض توسط اسکریپت به صورت ابتدایی انجام میشود که پس از نصب امکان تغییر و ارتقای امنیت و.. توسط کاربر وجود دارد.**
- **✅ استفاده از منوهای تعاملی و نمایش گزارش‌های رنگی برای تجربه کاربری بهتر.**
- **✅ قابلیت اجرای مستقیم پس از نصب با دستور "sonchain"**
- **🐧 تست شده با سیستم عامل های Ubuntu +18  و +8 Debian**
- **✅ امکان شخصی سازی بیشتر در ابزار های موجود.**
- **✅ در مراحل مختلف عملیات های مختلف , پیام های مناسب برای اطلاعات بیشتر نمایش داده میشود.**
- **✅ تنظیم خودکار DNS موقت هنگام نصب , در صورت اشکال در تنظیمات DNS فعلی سرور.**
- **✅ برطرف کردن خودکار مشکلات ابزار APT سرور هنگام نصب.**
- **✅ حذف موارد نصب شده به صورت خودکار , در صورت اشکال در عملیات نصب یا کنسل شدن توسط کاربر.**
- **✅ هنگام ویرایش فایل های کانفیگ به صورت دستی بخصوص فایل کانفیگ Psiphon و TOR  ابتدا بکاپ گرفته میشود و سپس قبل از ذخیره بررسی اجمالی'کلی محتویات کانفیگ جهت اطمینان از صحت محتوا , توسط اسکریپت انجام شده و در صورت نیاز قابل برگشت است.**
- **✅ تمام عملیات تغییر DNS یا ایجاد Rule برای Iptables توسط DNSSON و PROXYSON تا حد ممکن با استاندارد مناسبی صورت گرفته و در پایان به حالت عادی برمیگردد , به صورت موقت و بدون از بین رفتن قفل یا سابلینک فایل یا تداخل در رول های Iptables**
- **✅ در طراحی و کدنویسی و... این اسکریپت تلاش شده تا توانایی هندل کردن شرایط مختلف افزایش یابد , افزایش سرعت عملیات و برخی موارد نیاز به ارتقا است که به مرور انجام خواهد شد .**

<br> **🔥توضیحات بیشتر قابلیت ها و راهنمای استفاده را در بخش های بعدی (پایین صفحه) مطالعه کنید.**


- [↪️ بازگشت به فهرست مطالب](#list)








&nbsp;
<br><br><br>

<a id="docs"></a><
                   
<div dir="rtl" style="text-align: right;">

<h2>📜 داکیومنت/راهنما :</h2>

<ul>
  <li>
    <strong>رسمی ProxyChain-Ng:</strong><br>
    <a href="https://github.com/rofl0r/proxychains-ng/blob/master/README">
      لینک README
    </a>
  </li>
  
  <li>
    <strong>رسمی Dante | Socksify:</strong><br>
    <a href="https://www.inet.no/dante/doc/1.4.x/socks.conf.5.html">
      socks.conf.5.html
    </a><br>
    <a href="https://www.inet.no/dante/doc/1.4.x/socksify.1.html">
      socksify.1.html
    </a><br>
    <a href="https://www.inet.no/dante/doc/">
      صفحه اصلی داکیومنت
    </a>
  </li>
  
  <li>
    <strong>رسمی Psiphon:</strong><br>
    <a href="https://pkg.go.dev/github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon#Config">
      Configuring Psiphon
    </a>
  </li>

  <li>
    <strong>رسمی Tor:</strong><br>
    <a href="https://docs.lightning.engineering/lightning-network-tools/lnd/configuring_tor">
      Configuring Tor with LND
    </a>
  </li>
</ul>

</div>



- [↪️ بازگشت به فهرست مطالب](#list)







&nbsp;
<br><br><br>
<a id="prerequisites"></a>

## 🛠️ پیش‌نیازها
- **&#x200F;Ubuntu 18+ / Debian 8+** 🐧
- **دسترسی sudo** 👑
- **Python 3.7+** 🐍
- [↪️ بازگشت به فهرست مطالب](#list)





&nbsp;
<br><br>
<a id="installation"></a>
## ⚙️ نصب|حذف|اجرا از طریق خط فرمان|ترمینال
<br> &#x200F;📦 **نصب اسکریپت** :
```bash
bash <(curl -fsSL https://raw.githubusercontent.com/kalilovers/sonchain/main/install.sh)
```
<br> **اجرای اسکریپت**:
```bash
sonchain
```
<br> **حذف اسکریپت**:
```bash
sudo sonchain --uninstall
```

---

<br> ▶️ اجرای دستورات با **proxychains** :
```bash
proxychains4 
```
نمونه :
```bash
proxychains4 apt update
```


<br> ▶️ اجرای دستورات با **Socksify** :
```bash
socksify 
```
نمونه :
```bash
socksify apt update
```


<br> ▶️ اجرای دستورات با **Prosyson** :
```bash
prosyson 
```
نمونه :
```bash
prosyson apt update
```

<br> ▶️ اجرای دستورات با **Dnsson** :
```bash
dnsson 
```
نمونه :
```bash
dnsson dig google.com
```

<br> ▶️ استفاده از ابزار **nyx** برای پایش حرفه ای تر **Tor** :
```bash
nyx 
```


- [↪️ بازگشت به فهرست مطالب](#list)




&nbsp;
<br><br><br>
<a id="guide"></a>

 ## 📋 راهنمای منوها و گزینه‌ها 

![image](https://github.com/kalilovers/sonchain/blob/main/assets/images/menu/main.png)

&nbsp;

⚠️ **این بخش ممکن است شامل برخی قابلیت و تغییرات جدید نباشد.**

<br>

<details>
<summary>1️⃣ Status</summary>
 
   
 🧰 **این منو برای 'بررسی وضعیت سرویس ها (Tor، ProxyChains و غیره)' استفاده می‌شود.**
 <br><br>⚠️**احتیاط: لغو/کنسل در حین تست اتصال در منوهای وضعیت می تواند باعث ایجاد مشکلاتی در تنظیماتی مانند DNS و غیره در سرور شود، بنابراین تا پایان تست اتصال صبر کنید.**

 &nbsp;
 
 ![image](https://github.com/kalilovers/sonchain/blob/main/assets/images/menu/status.png)












 &nbsp;
 
<details>
  <summary dir="rtl" style="text-align: right;">1 | Tor Status </summary>

  <p dir="rtl" style="text-align: right;">
   
  🧰 **این گزینه برای بررسی 'وضعیت Tor' استفاده می‌شود.**  
  <br><br> برای مثال طبق تصویر زیر:
  </p>

  <p align="center">
    <img src="https://github.com/kalilovers/sonchain/blob/main/assets/images/menu/torstatus.png">
  </p>

  <ul dir="rtl" style="text-align: right;">
    <li><b>بخش Tor Service:</b> وضعیت سرویس تور (Running فعال هست)</li>
    <li><b>بخش SOCKS Proxy Settings:</b> بخش پورت و آیپی ساکس تور (که فقط در صورت معتبر بودن یا وجود داشتن نمایش داده می‌شود)</li>
    <li><b>بخش DNS Proxy Settings:</b> بخش پورت و آیپی DNS Proxy تور (که فقط در صورت معتبر بودن یا وجود داشتن نمایش داده می‌شود)</li>
    <li><b>بخش General Settings:</b> تنظیمات دیگر کانفیگ Tor - مثل نمایش مسیر لاگ در صورت فعال بودن و...</li>
    <li><b>در صورت عدم وجود:</b> اگر Tor یا فایل کانفیگ <code>torrc</code> وجود نداشته باشد یا مشکلات دیگری پیش بیاید، پیغام مناسب نمایش داده می‌شود.</li>
  </ul>

</details>

&nbsp;










<details>
  <summary dir="rtl" style="text-align: right;">2 | Socksify Status</summary>

  <p dir="rtl" style="text-align: right;">
   
  🧰 **این گزینه برای بررسی 'وضعیت Socksify' استفاده می‌شود.**  
  <br><br> برای مثال طبق تصویر زیر:
  </p>

  <p align="center">
    <img src="https://github.com/kalilovers/sonchain/blob/main/assets/images/menu/socksifystatus.png">
  </p>

  <ul dir="rtl" style="text-align: right;">
    <li><b>بخش Config File:</b> مسیر فایل کانفیگ</li>
    <li><b>بخش SOCKS Settings:</b> پورت و آیپی ساکس خروجی (که فقط در صورت معتبر بودن یا وجود داشتن نمایش داده می‌شود)</li>
    <li><b>بخش  DNS Settings:</b> پروتکل حل دامنه (که فقط در صورت معتبر بودن یا وجود داشتن نمایش داده می‌شود)</li>
    <li><b>بخش Logging:</b> نمایش مسیر لاگ در صورت فعال بودن و...</li>
    <li><b>بخش Connection Status:</b> وضعیت اتصال را نشان می دهد - نتیجه حداکثر تا 10 ثانیه نمایش داده می شود.</li>
    <li><b>در صورت عدم وجود:</b> اگر <code>dante-client</code> یا فایل کانفیگ <code>socks.conf</code> وجود نداشته باشد یا مشکلات دیگری پیش بیاید، پیغام مناسب نمایش داده می‌شود.</li>
  </ul>

</details>

&nbsp;










<details>
  <summary dir="rtl" style="text-align: right;">3 | ProxyChains Status</summary>

  <p dir="rtl" style="text-align: right;">
   
  🧰 **این گزینه برای بررسی 'وضعیت ProxyChains' استفاده می‌شود.**  
  <br><br> برای مثال طبق تصویر زیر:
  </p>

  <p align="center">
    <img src="https://github.com/kalilovers/sonchain/blob/main/assets/images/menu/chainsstatus.png">
  </p>

  <ul dir="rtl" style="text-align: right;">
    <li><b>بخش Config File:</b> مسیر فایل کانفیگ</li>
    <li><b>بخش  General Settings:</b> نمایش حالت های مختلف مقادیر مورد نظر برای مثال در این تصویر active proxies نمایانگر تعداد پروکسی های فعال هست (که فقط در صورت معتبر بودن یا وجود داشتن نمایش داده می‌شود)</li>
    <li><b>بخش Recent Proxies:</b> پورت و آیپی ساکس خروجی (تا 5 پروکسی نمایش داده میشود) , در صورت وجود پسوورد و.. نمایش داده میشود </li>
    <li><b>بخش Connection Status:</b> ابتدا یک تست ارتباط از طریق پروکسی ها به ادرس 1.1.1.1 با پورت 80 انجام میشود و در نهایت نتیجه نمایش داده میشود , احتمال خطا وجود دارد</li>
    <li><b>در صورت عدم وجود:</b> اگر <code>PROXYCHAINS</code> یا فایل کانفیگ <code>proxychains.conf</code> وجود نداشته باشد یا مشکلات دیگری پیش بیاید، پیغام مناسب نمایش داده می‌شود.</li>
  </ul>

</details>

&nbsp;











<details>
  <summary dir="rtl" style="text-align: right;">4 | ProxySon Status</summary>

  <p dir="rtl" style="text-align: right;">
   
  🧰 **این گزینه برای بررسی 'وضعیت ProxySon' استفاده می‌شود.**  
  <br><br> برای مثال طبق تصویر زیر:
  </p>

  <p align="center">
    <img src="https://github.com/kalilovers/sonchain/blob/main/assets/images/menu/proxysonstatus.png">
  </p>

  <ul dir="rtl" style="text-align: right;">
    <li><b>بخش  Destination:</b> مقصد مربوط به DNS تنظیم شده , که برای تنظیم موقت در فایل <code>resolv.conf</code> و همچنین در <code>iptables</code> هنگام استفاده از این ابزار به صورت موقت به عنوان dns تنظیم خواهد شد .</li>
    <li><b>بخش Command:</b> نمایش 'دستور' تنظیم شده که توسط دستور <code>proxyson</code> اجرا خواهد شد.</li>
    <li><b>بخش IPTables Rules:</b> وضعیت فعلی رول های <code>iptables</code> را نمایش میدهد - طبق تصویر فعلی <code>Not Active</code> به این معنی است که در حال حاظر رول ها در حال استفاده نیستند که عادیست و زمان اجرای این ابزار به صورت موقت مورد استفاده قرار میگیرند .</li>
    <li><b>بخش Connection Status:</b> وضعیت اتصال را نشان می دهد - نتیجه حداکثر تا 10 ثانیه نمایش داده می شود.</li>
    <li><b>در صورت عدم وجود:</b> اگر فایل <code>proxyson</code> وجود نداشته باشد یا مشکلات دیگری پیش بیاید، پیغام مناسب نمایش داده می‌شود.</li>
  </ul>

</details>

&nbsp;











<details>
  <summary dir="rtl" style="text-align: right;">5 | DnsSon Status</summary>

  <p dir="rtl" style="text-align: right;">
   
  🧰 **این گزینه برای 'بررسی وضعیت DnsSon' استفاده می‌شود.**  
  <br><br> برای مثال طبق تصویر زیر:
  </p>

  <p align="center">
    <img src="https://github.com/kalilovers/sonchain/blob/main/assets/images/menu/dnssonstatus.png">
  </p>

  <ul dir="rtl" style="text-align: right;">
    <li><b>بخش  Destination:</b> مقصد مربوط به DNS تنظیم شده , که برای تنظیم موقت در فایل <code>resolv.conf</code> و همچنین در <code>iptables</code> هنگام استفاده از این ابزار به صورت موقت به عنوان DNS تنظیم خواهد شد .</li>
    <li><b>بخش IPTables Rules:</b> وضعیت فعلی رول های <code>iptables</code> را نمایش میدهد - طبق تصویر فعلی <code>Not Active</code> به این معنی است که در حال حاظر رول ها در حال استفاده نیستند که عادیست و زمان اجرای این ابزار به صورت موقت مورد استفاده قرار میگیرند .</li>
    <li><b>در صورت عدم وجود:</b> اگر فایل <code>DnsSon</code> وجود نداشته باشد یا مشکلات دیگری پیش بیاید، پیغام مناسب نمایش داده می‌شود.</li>
  </ul>

</details>

&nbsp;












</details>

&nbsp;

<details>
<summary>2️⃣ Auto Setup</summary>

   
 🧰 **این منو برای 'نصب و همگام سازی خودکار ProxyChains یا Socksify با Tor' استفاده میشود.**
 
 <br> 🔹 **در صورت شکست عملیات یا لغو توسط کاربر > موارد نصب شده حذف خواهند شد**
 <br> 🔹 **در صورت عدم اتصال به دلیل اشکال در DNS > ابتدا خود اسکریپت برای رفع مشکل و تنظیم موقت DNS اقدام میکند**
 <br> 🔹**اسکریپت پس از بررسی امکان اتصال سرور شما به مخزن رسمی تور در صورت موفقیت آخرین نسخه مربوطه را نصب خواهد کرد و در صورت عدم موفقیت (سانسور - مسدود بودن مقصد و..)  برای نصب از طریق مخازن رسمی سرور - سیستم عامل شما اقدام میکند .**


 &nbsp;
 
 ![image](https://github.com/kalilovers/sonchain/blob/main/assets/images/menu/autosetup.png)









<details>
  <summary dir="rtl" style="text-align: right;">1 | Socksify + Tor + Proxyson+Dnsson</summary>

  <p dir="rtl" style="text-align: right;">
   
  🧰 **این گزینه برای 'نصب و همگام سازی خودکار Socksify + dnsson + proxyson با Tor' استفاده میشود.**
<br> 🔹 **پیشنهاد می شود پس از اتمام نصب، دستور <code>source ~/.bashrc</code> را اجرا کنید.**
<br> 🔹 **توصیه می شود پس از اتمام نصب، سرور را ریبوت کنید.**
<br> 🔹 **بعد از اتمام نصب، چند دقیقه صبر کنید تا اتصال Tor برقرار شود. همچنین می توانید وضعیت اتصال را در منوهای وضعیت بررسی کنید.**

  
  <br><br> برای شروع پس از انتخاب گزینه 1:
  <br><br> 1_ پرسش مربوطه را تایید کنید > در صورت تایید "Tor, Socksify , Dnsson, and Proxyson" برای نصب تمیز حذف خواهند شد .
  <p align="center">
    <img src="https://github.com/kalilovers/sonchain/blob/main/assets/images/menu/socksify+tor1.png">
  </p>

  <br> 2_ پس از پایان نصب نوبت تعیین پورت-آیپی مربوط به <code>Socksport</code> و <code>Dnsport</code> نرم افزار <code>tor</code> است **درصورتی که مقدار اشتباه یا غیر مجاز وارد کنید هشدار داده میشود , در صورتی که مقداری وارد نکرده و 'enter' را فشار دهید مقدار مناسبی به صورت خودکار تعیین خواهد شد(توصیه میشود)** .
  <br> در نمونه زیر من 3 مورد را با 'Enter (برای تنظیم خودکار)' و 1 مورد را به اشتباه با مقدار '0' وارد کردم که پس از هشدار و درخواست مجدد اینبار از 'Enter' استفاده کردم:
  <p align="center">
    <img src="https://github.com/kalilovers/sonchain/blob/main/assets/images/menu/socksify+tor2.png">
  </p>



  <br> 3_ پس از پایان نصب اطلاعات مربوط به مقادیر تنظیم شده را مشاهده میکنید (همچنین در منوی Status قابل مشاهده است) .
  <p align="center">
    <img src="https://github.com/kalilovers/sonchain/blob/main/assets/images/menu/socksify+tor3.png">
    <img src="https://github.com/kalilovers/sonchain/blob/main/assets/images/menu/socksify+tor4.png">
  </p>

</details>







&nbsp;

<details>
  <summary dir="rtl" style="text-align: right;">2 | Setup ProxyChains + Tor </summary>

  <p dir="rtl" style="text-align: right;">
   
🧰 **این گزینه برای 'نصب و همگام سازی خودکار ProxyChains-Ng با Tor' استفاده میشود.**  
<br> 🔹 **بعد از اتمام نصب، چند دقیقه صبر کنید تا اتصال Tor برقرار شود. همچنین می توانید وضعیت اتصال را در منوهای وضعیت بررسی کنید.**

  <br><br> برای شروع پس از انتخاب گزینه 2:
  <br><br> 1_ پرسش مربوطه را تایید کنید > در صورت تایید "Tor and Proxychains" برای نصب تمیز حذف خواهند شد .
  <p align="center">
    <img src="https://github.com/kalilovers/sonchain/blob/main/assets/images/menu/chains+tor1.png">
  </p>


  <br> 2_ پس از پایان نصب نوبت تعیین پورت-آیپی مربوط به <code>Socksport</code> و <code>Dnsport</code> نرم افزار <code>tor</code> است **درصورتی که مقدار اشتباه یا غیر مجاز وارد کنید هشدار داده میشود , در صورتی که مقداری وارد نکرده و 'enter' را فشار دهید مقدار مناسبی به صورت خودکار تعیین خواهد شد(توصیه میشود)** .
  <br> در نمونه زیر من 3 مورد را با 'Enter (برای تنظیم خودکار)' و 1 مورد را به اشتباه با مقدار '0' وارد کردم که پس از هشدار و درخواست مجدد اینبار از 'Enter' استفاده کردم:
  <p align="center">
    <img src="https://github.com/kalilovers/sonchain/blob/main/assets/images/menu/chains+tor2.png">
  </p>


  <br> 3_ پس از پایان نصب اطلاعات مربوط به مقادیر تنظیم شده را مشاهده میکنید (همچنین در منوی Status قابل مشاهده است) .
  <p align="center">
    <img src="https://github.com/kalilovers/sonchain/blob/main/assets/images/menu/chains+tor3.png">
  </p>

</details>




</details>

&nbsp;













<details>
<summary>3️⃣ Tor Setup</summary>

  <p dir="rtl" style="text-align: right;">
   
 🧰 **این منو برای 'مدیریت Tor' طراحی شده.**

![image](https://github.com/kalilovers/sonchain/blob/main/assets/images/menu/tormenu.png)












&nbsp;

<details>
  <summary dir="rtl" style="text-align: right;">1 | Tor Status</summary>

  <p dir="rtl" style="text-align: right;">

🧰 **این گزینه برای 'بررسی وضعیت Tor' استفاده میشود.**  
  <br><br> برای مثال طبق تصویر زیر:
  </p>

  <p align="center">
    <img src="https://github.com/kalilovers/sonchain/blob/main/assets/images/menu/torstatus.png">
  </p>

  <ul dir="rtl" style="text-align: right;">
    <li><b>بخش Tor Service:</b> وضعیت سرویس تور (Running فعال هست)</li>
    <li><b>بخش SOCKS Proxy Settings:</b> بخش پورت و آیپی ساکس تور (که فقط در صورت معتبر بودن یا وجود داشتن نمایش داده می‌شود)</li>
    <li><b>بخش DNS Proxy Settings:</b> بخش پورت و آیپی DNS Proxy تور (که فقط در صورت معتبر بودن یا وجود داشتن نمایش داده می‌شود)</li>
    <li><b>بخش General Settings:</b> تنظیمات دیگر کانفیگ Tor - مثل نمایش مسیر لاگ در صورت فعال بودن و...</li>
    <li><b>در صورت عدم وجود:</b> اگر Tor یا فایل کانفیگ <code>torrc</code> وجود نداشته باشد یا مشکلات دیگری پیش بیاید، پیغام مناسب نمایش داده می‌شود.</li>
  </ul>

</details>












&nbsp;

<details>
  <summary dir="rtl" style="text-align: right;"> 2 | Install Tor</summary>

  <p dir="rtl" style="text-align: right;">
   
🧰 **این گزینه برای 'نصب Tor' استفاده میشود.**

 <br> 🔹 **در صورت شکست عملیات یا لغو توسط کاربر > موارد نصب شده حذف خواهند شد**
 <br> 🔹 **در صورت عدم اتصال به دلیل اشکال در DNS > ابتدا خود اسکریپت برای رفع مشکل و تنظیم موقت DNS اقدام میکند**
 <br> 🔹**اسکریپت پس از بررسی امکان اتصال سرور شما به مخزن رسمی تور در صورت موفقیت آخرین نسخه مربوطه را نصب خواهد کرد و در صورت عدم موفقیت (سانسور - مسدود بودن مقصد و..)  برای نصب از طریق مخازن رسمی سرور - سیستم عامل شما اقدام میکند .**
 <br> 🔹 **بعد از اتمام نصب، چند دقیقه صبر کنید تا اتصال Tor برقرار شود. همچنین می توانید وضعیت اتصال را در منوهای وضعیت بررسی کنید.**

  <br><br> برای شروع پس از انتخاب گزینه 2:
  <br><br> 1_ پرسش مربوطه را تایید کنید > در صورت تایید "Tor" برای نصب تمیز حذف خواهند شد .
  <p align="center">
    <img src="https://github.com/kalilovers/sonchain/blob/main/assets/images/menu/torsetup2.png">
  </p>




  <br> 2_ پس از پایان نصب نوبت تعیین پورت-آیپی مربوط به <code>Socksport</code> و <code>Dnsport</code> نرم افزار <code>tor</code> است **درصورتی که مقدار اشتباه یا غیر مجاز وارد کنید هشدار داده میشود , در صورتی که مقداری وارد نکرده و enter را فشار دهید مقدار مناسبی به صورت خودکار تعیین خواهد شد(توصیه میشود)** .
  <br> در نمونه زیر من 3 مورد را با 'Enter (برای تنظیم خودکار)' و 1 مورد را به اشتباه با مقدار '0' وارد کردم که پس از هشدار و درخواست مجدد اینبار از 'Enter' استفاده کردم:
  <p align="center">
    <img src="https://github.com/kalilovers/sonchain/blob/main/assets/images/menu/torsetup2-2.png">
  </p>


  <br> 3_ پس از پایان نصب اطلاعات مربوط به مقادیر تنظیم شده را مشاهده میکنید (همچنین در منوی Status قابل مشاهده است) .
  <p align="center">
    <img src="https://github.com/kalilovers/sonchain/blob/main/assets/images/menu/torsetup2-3.png">
  </p>

</details>








&nbsp;

<details>
  <summary dir="rtl" style="text-align: right;"> 3 | Manual Configuration</summary>

  <p dir="rtl" style="text-align: right;">
   
🧰 **این گزینه برای 'ویرایش دستی کانفیگ Tor' در مسیر "etc/tor/torrc" استفاده میشود.**

 <br> 🔹 **پس از اتمام و بررسی خودکار کانفیگ جدید توسط اسکریپت , در صورت معتبر نبودن محتویات ویرایش شده اسکریپت پیشنهاد بازیابی فایل کانفیگ را خواهد داد**
 <br> 🔹 **در صورت عدم وجود فایل کانفیگ یا خود tor پیام مناسب نمایش داده میشود**
 <br> 🔹 **از تغییرات غیر استاندارد و اشتباه خودداری کنید**


  <br><br> برای شروع پس از انتخاب گزینه 3:
  <br><br> 1_ پس از اتمام ویرایش با دکمه ctrl+c و تایید با y در صورت معتبر بودن محتویات جدید , 3 پرسش در خصوص همگام سازی 'Socksify - dnsson - proxyson' با تنظیمات جدید tor انجام میشود که میتوانید با دکمه 'y یا enter' تایید و با 'n' رد کنید .
  <p align="center">
    <img src="https://github.com/kalilovers/sonchain/blob/main/assets/images/menu/torsetup3.png">
  </p>
  
  <br> برای مثال طبق تصویر مقدار '127.119.179.222:9038' به عنوان 'DNS' برای 'proxyson - dnsson' همگام سازی شده ولی برای 'Socksify' خیر (احتمالا به دلیل عدم وجود فایل کانفیگ یا خود Socksify)




  <br> 2_ در صورتی که خطایی در کانفیگ 'tor' (توجه کنید اسکریپت فقط قسمت ساکس و 'dns' را برای اعتبارسنجی بررسی میکند) کرده باشید اسکریپت پیشنهاد ریستور کردن تنظیمات را میدهد که میتوانید تایید کنید , در صورت عدم تایید تنظیمات اعمال میشود اما امکان همگاسازی وجود نخواهد داشت.
  <br> در نمونه زیر من 3 مورد را با 'Enter (برای تنظیم خودکار)' و 1 مورد را به اشتباه با مقدار '0' وارد کردم که پس از هشدار و درخواست مجدد اینبار از 'Enter' استفاده کردم:
  <p align="center">
    <img src="https://github.com/kalilovers/sonchain/blob/main/assets/images/menu/torsetup3-2.png">
  </p>


</details>








&nbsp;

<details>
  <summary dir="rtl" style="text-align: right;"> 4 | Stop Tor </summary>

  <p dir="rtl" style="text-align: right;">
   
🧰 **این گزینه برای توقف سرویس Tor استفاده میشود , در صورت عدم وجود Tor پیام مناسب نمایش داده میشود .**
&nbsp;

  <p align="center">
    <img src="https://github.com/kalilovers/sonchain/blob/main/assets/images/menu/torsetup4.png">
  </p>

</details>









&nbsp;

<details>
  <summary dir="rtl" style="text-align: right;"> 5 | Restart Tor </summary>

  <p dir="rtl" style="text-align: right;">
   
🧰 **این گزینه برای 'شروع مجدد سرویس Tor' استفاده میشود , در صورت عدم وجود Tor پیام مناسب نمایش داده میشود .**

**🔹 همچنین برای تغییر نود و خروجی Tor از این گزینه میتوانید استفاده کنید**

&nbsp;

  <p align="center">
    <img src="https://github.com/kalilovers/sonchain/blob/main/assets/images/menu/torsetup5.png">
  </p>


</details>














&nbsp;

<details>
  <summary dir="rtl" style="text-align: right;"> 6 | Remove Tor</summary>

  <p dir="rtl" style="text-align: right;">
   
🧰 **این گزینه برای 'حذف Tor' استفاده میشود .**

&nbsp;

پرسش مربوطه را تایید کنید > در صورت تایید "Tor" حذف خواهند شد .


  <p align="center">
    <img src="https://github.com/kalilovers/sonchain/blob/main/assets/images/menu/torsetup6.png">
  </p>

</details>



</details>









&nbsp;

<details>
<summary>4️⃣ Dante'Socksify' Setup</summary>

  <p dir="rtl" style="text-align: right;">
   
 🧰 **این منو برای 'مدیریت Socksify' طراحی شده.**
&nbsp;

![image](https://github.com/kalilovers/sonchain/blob/main/assets/images/menu/socksifymenu.png)






&nbsp;

<details>
  <summary dir="rtl" style="text-align: right;"> 1 | Socksify Status</summary>

  <p dir="rtl" style="text-align: right;">
   
  🧰 **این گزینه برای 'بررسی وضعیت Socksify' استفاده می‌شود.**  
  <br><br> برای مثال طبق تصویر زیر:
  </p>

  <p align="center">
    <img src="https://github.com/kalilovers/sonchain/blob/main/assets/images/menu/socksifystatus.png">
  </p>

  <ul dir="rtl" style="text-align: right;">
    <li><b>بخش Config File:</b> مسیر فایل کانفیگ</li>
    <li><b>بخش SOCKS Settings:</b> پورت و آیپی ساکس خروجی (که فقط در صورت معتبر بودن یا وجود داشتن نمایش داده می‌شود)</li>
    <li><b>بخش  DNS Settings:</b> پروتکل حل دامنه (که فقط در صورت معتبر بودن یا وجود داشتن نمایش داده می‌شود)</li>
    <li><b>بخش Logging:</b> نمایش مسیر لاگ در صورت فعال بودن و...</li>
    <li><b>بخش Connection Status:</b> وضعیت اتصال را نشان می دهد - نتیجه حداکثر تا 10 ثانیه نمایش داده می شود.</li>
    <li><b>در صورت عدم وجود:</b> اگر <code>dante-client</code> یا فایل کانفیگ <code>socks.conf</code> وجود نداشته باشد یا مشکلات دیگری پیش بیاید، پیغام مناسب نمایش داده می‌شود.</li>
  </ul>

</details>









&nbsp;

<details>
  <summary dir="rtl" style="text-align: right;"> 2 | Install Socksify</summary>

  <p dir="rtl" style="text-align: right;">
   
🧰 **این گزینه برای 'نصب Socksify' استفاده میشود.**
 <br> 🔹 **پیشنهاد می شود پس از اتمام نصب، دستور <code>source ~/.bashrc</code> را اجرا کنید.**
 <br> 🔹 **توصیه می شود پس از اتمام نصب، سرور را ریبوت کنید.**
 <br> 🔹 **در صورت شکست عملیات یا لغو توسط کاربر > موارد نصب شده حذف خواهند شد**
 <br> 🔹 **در صورت عدم اتصال به دلیل اشکال در DNS > ابتدا خود اسکریپت برای رفع مشکل و تنظیم موقت DNS اقدام میکند**


  <br><br> برای شروع پس از انتخاب گزینه 2:
  <br><br> 1_ پرسش مربوطه را تایید کنید > در صورت تایید "Dante|Socksify" برای نصب تمیز حذف خواهند شد .
  <p align="center">
    <img src="https://github.com/kalilovers/sonchain/blob/main/assets/images/menu/socksifysetup2.png">
  </p>



  <br> 2_ پس از پایان نصب پرسشی برای همگام سازی تنظیمات Socksify با تنظیمات Tor انجام میشود , در صورتی که تایید کنید در صورت وجود Tor و تنظیمات معتبر , همگام سازی انجام خواهد شد , در غیر اینصورت باید مقادیر آیپی و پورت خروجی Socksify را به صورت دستی وارد کنید.
  <br> در نمونه زیر من همگام سازی را تایید کردم :
  <p align="center">
    <img src="https://github.com/kalilovers/sonchain/blob/main/assets/images/menu/socksifysetup2-2.png">
  </p>



</details>








&nbsp;

<details>
  <summary dir="rtl" style="text-align: right;"> 3 | Edit Configuration</summary>

  <p dir="rtl" style="text-align: right;">
   
🧰 **این گزینه برای 'ویرایش دستی کانفیگ Socksify' در مسیر "etc/socks.conf" استفاده میشود.**

 <br> 🔹 **در صورت عدم وجود فایل کانفیگ یا خود Socksify پیام مناسب نمایش داده میشود**
 <br> 🔹 **از تغییرات غیر استاندارد و اشتباه خودداری کنید**


  <br><br> برای شروع پس از انتخاب گزینه 3:
  <br><br> پس از اتمام ویرایش با دکمه ctrl+c و تایید با y تنظیمات بدون بررسی صحت محتوا ذخیره میشود **بنابراین در ویرایش تنظیمات احتیاط کنید**.
  <p align="center">
    <img src="https://github.com/kalilovers/sonchain/blob/main/assets/images/menu/socksifysetup3.png">
  </p>

</details>











&nbsp;

<details>
  <summary dir="rtl" style="text-align: right;"> 4 | Change SOCKS IP/Port</summary>

  <p dir="rtl" style="text-align: right;">
   
🧰 **این گزینه برای 'ویرایش مقادیر Socks و Port' مربوط به خروجی کانفیگ Socksify در مسیر "etc/socks.conf" استفاده میشود.**

 <br> 🔹 **در صورت عدم وجود فایل کانفیگ یا خود Socksify پیام مناسب نمایش داده میشود**
 <br> 🔹 **اسکریپت تا حدودی از ورود اطلاعات اشتباه توسط شما جلوگیری میکند**
 <br> 🔹 **از تغییرات غیر استاندارد و اشتباه خودداری کنید**



  <br><br> برای شروع پس از انتخاب گزینه 4:
  <br><br> مقادیر مورد نظر خود را وارد کنید , مثال نمونه زیر.
  <p align="center">
    <img src="https://github.com/kalilovers/sonchain/blob/main/assets/images/menu/socksifysetup4.png">
  </p>

</details>








&nbsp;

<details>
  <summary dir="rtl" style="text-align: right;"> 5 | Change DNS Protocol</summary>

  <p dir="rtl" style="text-align: right;">
   
🧰 **این گزینه برای 'تغییر حالت DNS PROTOCOL' کانفیگ Socksify در مسیر "etc/socks.conf" استفاده میشود.**

 <br> 🔹 **در صورت عدم وجود فایل کانفیگ یا خود Socksify پیام مناسب نمایش داده میشود**
 <br> 🔹 **برای اطلاعات بیشتر به داکیومنت مراجعه کنید**
 <br> 🔹 **از اعمال تغییراتی که اطلاعات کافی ندارید خودداری کنید**



  <br><br> برای شروع پس از انتخاب گزینه 5:
  <br><br> پروتکل مورد نظر خود را انتخاب کنید , در نمونه زیر من پروتکل Tcp را انتخاب کردم.
  <p align="center">
    <img src="https://github.com/kalilovers/sonchain/blob/main/assets/images/menu/socksifysetup5.png">
  </p>

</details>










&nbsp;

<details>
  <summary dir="rtl" style="text-align: right;"> 6 | Sync with Tor</summary>

  <p dir="rtl" style="text-align: right;">
   
🧰 **این گزینه برای 'همگام سازی مقادیر Socks و Port' کانفیگ Socksify در مسیر "etc/socks.conf" با تنظیمات Tor استفاده میشود.**

 <br> 🔹 **در صورت عدم وجود فایل کانفیگ یا خود Tor یا Socksify پیام مناسب نمایش داده میشود**
 <br> 🔹 **برای اطلاعات بیشتر به داکیومنت مراجعه کنید**





  <br><br> برای شروع پس از انتخاب گزینه 6:
  <br><br> در نمونه زیر همگام سازی انجام شده و خروجی جدید نمایش داده شده.
  <p align="center">
    <img src="https://github.com/kalilovers/sonchain/blob/main/assets/images/menu/socksifysetup6.png">
  </p>

</details>









&nbsp;

<details>
  <summary dir="rtl" style="text-align: right;"> 7 | Remove Dante</summary>

  <p dir="rtl" style="text-align: right;">
   
🧰 **این گزینه برای 'حذف Socksify' استفاده میشود .**

&nbsp;

پرسش مربوطه را تایید کنید > در صورت تایید "Socksify" حذف خواهند شد .


  <p align="center">
    <img src="https://github.com/kalilovers/sonchain/blob/main/assets/images/menu/socksifysetup7.png">
  </p>

</details>



</details>












&nbsp;

<details>
<summary>5️⃣ ProxyChains Setup</summary>

  <p dir="rtl" style="text-align: right;">
   
 🧰 **این منو برای 'مدیریت ProxyChains-Ng' طراحی شده.**
&nbsp;

![image](https://github.com/kalilovers/sonchain/blob/main/assets/images/menu/chainsmenu.png)








&nbsp;

<details>
  <summary dir="rtl" style="text-align: right;"> 1 | Status</summary>

  <p dir="rtl" style="text-align: right;">
   
  🧰 **این گزینه برای 'بررسی وضعیت ProxyChains' استفاده می‌شود.**  
  <br><br> برای مثال طبق تصویر زیر:
  </p>

  <p align="center">
    <img src="https://github.com/kalilovers/sonchain/blob/main/assets/images/menu/chainsstatus.png">
  </p>

  <ul dir="rtl" style="text-align: right;">
    <li><b>بخش Config File:</b> مسیر فایل کانفیگ</li>
    <li><b>بخش  General Settings:</b> نمایش حالت های مختلف مقادیر مورد نظر برای مثال در این تصویر active proxies نمایانگر تعداد پروکسی های فعال هست (که فقط در صورت معتبر بودن یا وجود داشتن نمایش داده می‌شود)</li>
    <li><b>بخش Recent Proxies:</b> پورت و آیپی ساکس خروجی (تا 5 پروکسی نمایش داده میشود) , در صورت وجود پسوورد و.. نمایش داده میشود </li>
    <li><b>بخش Connection Status:</b> ابتدا یک تست ارتباط از طریق پروکسی ها به ادرس 1.1.1.1 با پورت 80 انجام میشود و در نهایت نتیجه نمایش داده میشود , احتمال خطا وجود دارد</li>
    <li><b>در صورت عدم وجود:</b> اگر <code>PROXYCHAINS</code> یا فایل کانفیگ <code>proxychains.conf</code> وجود نداشته باشد یا مشکلات دیگری پیش بیاید، پیغام مناسب نمایش داده می‌شود.</li>
  </ul>

</details>










&nbsp;

<details>
  <summary dir="rtl" style="text-align: right;"> 2 | Install ProxyChains</summary>

  <p dir="rtl" style="text-align: right;">
   
🧰 **این گزینه برای 'نصب ProxyChains-Ng' استفاده میشود.**

 <br> 🔹 **در صورت شکست عملیات یا لغو توسط کاربر > موارد نصب شده حذف خواهند شد**
 <br> 🔹 **در صورت عدم اتصال به دلیل اشکال در DNS > ابتدا خود اسکریپت برای رفع مشکل و تنظیم موقت DNS اقدام میکند**


  <br><br> برای شروع پس از انتخاب گزینه 2:
  <br><br> 1_ پرسش مربوطه را تایید کنید > در صورت تایید "ProxyChains" برای نصب تمیز حذف خواهند شد .
  <p align="center">
    <img src="https://github.com/kalilovers/sonchain/blob/main/assets/images/menu/chainssetup2.png">
  </p>




  <br> 2_ پس از پایان نصب پرسشی برای همگام سازی تنظیمات ProxyChains با تنظیمات Tor انجام میشود , در صورتی که تایید کنید در صورت وجود Torو تنظیمات معتبر , همگام سازی انجام خواهد شد , در غیر اینصورت باید مقادیر آیپی و پورت خروجی ProxyChains را به صورت دستی وارد کنید.
  <br> در نمونه زیر من همگام سازی را تایید کردم :
  <p align="center">
    <img src="https://github.com/kalilovers/sonchain/blob/main/assets/images/menu/chainssetup2-2.png">
  </p>



</details>








&nbsp;

<details>
  <summary dir="rtl" style="text-align: right;"> 3 | Edit Configuration</summary>

  <p dir="rtl" style="text-align: right;">
   
🧰 **این گزینه برای 'ویرایش دستی کانفیگ ProxyChains' در مسیر "etc/proxychains.conf" استفاده میشود.**

 <br> 🔹 **در صورت عدم وجود فایل کانفیگ یا خود ProxyChains پیام مناسب نمایش داده میشود**
 <br> 🔹 **از تغییرات غیر استاندارد و اشتباه خودداری کنید**


  <br><br> برای شروع پس از انتخاب گزینه 3:
  <br><br> پس از اتمام ویرایش با دکمه ctrl+c و تایید با y تنظیمات بدون بررسی صحت محتوا ذخیره میشود **بنابراین در ویرایش تنظیمات احتیاط کنید**.
  <p align="center">
    <img src="https://github.com/kalilovers/sonchain/blob/main/assets/images/menu/chainssetup3.png">
  </p>

</details>









&nbsp;

<details>
  <summary dir="rtl" style="text-align: right;"> 4 | Change Chain Type (Strict/Dynamic)</summary>

  <p dir="rtl" style="text-align: right;">
   
🧰 **این گزینه برای 'تغییر حالت Chain Type' کانفیگ ProxyChains در مسیر "etc/proxychains.conf" استفاده میشود.**

 <br> 🔹 **در صورت عدم وجود فایل کانفیگ یا خود ProxyChains پیام مناسب نمایش داده میشود**
 <br> 🔹 **برای اطلاعات بیشتر به داکیومنت مراجعه کنید**
 <br> 🔹 **از اعمال تغییراتی که اطلاعات کافی ندارید خودداری کنید**



  <br><br> برای شروع پس از انتخاب گزینه 4:
  <br><br> حالت مورد نظر خود را انتخاب کنید , در نمونه زیر من حالت Dynamic Chain را انتخاب کردم.
  <p align="center">
    <img src="https://github.com/kalilovers/sonchain/blob/main/assets/images/menu/chainssetup4.png">
  </p>

</details>











&nbsp;

<details>
  <summary dir="rtl" style="text-align: right;"> 5 | Change Quiet Mode (Active/InActive)</summary>

  <p dir="rtl" style="text-align: right;">
   
🧰 **این گزینه برای 'فعال و غیر فعال کردن حالت Quiet Mode' کانفیگ ProxyChains در مسیر "etc/proxychains.conf" استفاده میشود.**

 <br> 🔹 **در صورت عدم وجود فایل کانفیگ یا خود ProxyChains پیام مناسب نمایش داده میشود**
 <br> 🔹 **برای اطلاعات بیشتر به داکیومنت مراجعه کنید**
 <br> 🔹 **از اعمال تغییراتی که اطلاعات کافی ندارید خودداری کنید**



  <br><br> برای شروع پس از انتخاب گزینه 5:
  <br><br> پس از هربار اجرا حالت تغییر میکند , بدون نیاز به ورودی.
  <p align="center">
    <img src="https://github.com/kalilovers/sonchain/blob/main/assets/images/menu/chainssetup5.png">
  </p>

</details>







&nbsp;

<details>
  <summary dir="rtl" style="text-align: right;"> 6 | Change DNS_Proxy Mode</summary>

  <p dir="rtl" style="text-align: right;">
   
🧰 **این گزینه برای 'تغییر حالت DNS_Proxy' کانفیگ ProxyChains در مسیر "etc/proxychains.conf" استفاده میشود.**

 <br> 🔹 **در صورت عدم وجود فایل کانفیگ یا خود ProxyChains پیام مناسب نمایش داده میشود**
 <br> 🔹 **برای اطلاعات بیشتر به داکیومنت مراجعه کنید**
 <br> 🔹 **از اعمال تغییراتی که اطلاعات کافی ندارید خودداری کنید**



  <br><br> برای شروع پس از انتخاب گزینه 6:
  <br><br> حالت مورد نظر خود را انتخاب کنید , در نمونه زیر من حالت proxy_dns را انتخاب کردم.
  <p align="center">
    <img src="https://github.com/kalilovers/sonchain/blob/main/assets/images/menu/chainssetup6.png">
  </p>

</details>









&nbsp;

<details>
  <summary dir="rtl" style="text-align: right;"> 7 | Add Custom Proxy</summary>

  <p dir="rtl" style="text-align: right;">
   
🧰 **این گزینه برای 'افزودن Proxy از نوع Socks یا http و با یا بدون مقادیر احراز هویت' , به کانفیگ ProxyChains در مسیر "etc/proxychains.conf" استفاده میشود.**

 <br> 🔹 **در صورت عدم وجود فایل کانفیگ یا خود ProxyChains پیام مناسب نمایش داده میشود**
 <br> 🔹 **برای اطلاعات بیشتر به داکیومنت مراجعه کنید**
 <br> 🔹 **از اعمال تغییراتی که اطلاعات کافی ندارید خودداری کنید**



  <br><br> برای شروع پس از انتخاب گزینه 7:
  <br><br> حالت مورد نظر خود را انتخاب کنید , در نمونه زیر من مقادیر ip و Port پروکسی خودم را وارد کرده و سپس پرسش افزودن یوزرنیم و پسوورد را تایید کردم (در صورت عدم استفاده از احراز هویت میتوانید رد کنید) , پس از وارد کردن یوزرنیم و پسوورد پروتکل پروکسی را انتخاب کردم , و درنهایت افزوده شد , **از افزودن پروکسی و مقادیر اشتباه خودداری کنید**.
  <p align="center">
    <img src="https://github.com/kalilovers/sonchain/blob/main/assets/images/menu/chainssetup7.png">
  </p>

</details>









&nbsp;

<details>
  <summary dir="rtl" style="text-align: right;"> 8 | Sync with Tor</summary>

  <p dir="rtl" style="text-align: right;">
   
🧰 **این گزینه برای 'همگام سازی مقادیر Socks و Port کانفیگ ProxyChains در مسیر "etc/proxychains.conf" با تنظیمات Tor' استفاده میشود.**

 <br> 🔹 **در صورت عدم وجود فایل کانفیگ یا خود Tor یا proxychains پیام مناسب نمایش داده میشود**
 <br> 🔹 **برای اطلاعات بیشتر به داکیومنت مراجعه کنید**





  <br><br> برای شروع پس از انتخاب گزینه 8:
  <br><br> در نمونه زیر همگام سازی انجام نشده ( به این دلیل که در حال حاظر همگام هست و نیازی به همگام سازی مجدد نداشته).
  <p align="center">
    <img src="https://github.com/kalilovers/sonchain/blob/main/assets/images/menu/chainssetup8.png">
  </p>

</details>









&nbsp;

<details>
  <summary dir="rtl" style="text-align: right;"> 9 | Remove ProxyChains</summary>

  <p dir="rtl" style="text-align: right;">
   
🧰 **این گزینه برای 'حذف ProxyChains-Ng' استفاده میشود .**

&nbsp;

پرسش مربوطه را تایید کنید > در صورت تایید "ProxyChains" حذف خواهند شد .


  <p align="center">
    <img src="https://github.com/kalilovers/sonchain/blob/main/assets/images/menu/chainssetup9.png">
  </p>

</details>






</details>

&nbsp;









<details>
<summary>6️⃣ DnsSon Setup</summary>

  <p dir="rtl" style="text-align: right;">
   
 🧰 **این منو برای 'مدیریت DnsSon' طراحی شده.**
 <br> 🔹**این ابزار به تنهایی قابل استفاده نیست و نیاز به "Tor" (یا یک dns پروکسی دیگر) برای نصب و همگام سازی با آن دارد.**

![image](https://github.com/kalilovers/sonchain/blob/main/assets/images/menu/dnssonmenu.png)








 &nbsp;
 
<details>
  <summary dir="rtl" style="text-align: right;">1 | DNSSON Status </summary>

  <p dir="rtl" style="text-align: right;">
   
  🧰 **این گزینه برای 'بررسی وضعیت DnsSon' استفاده می‌شود.**  
  <br><br> برای مثال طبق تصویر زیر:
  </p>

  <p align="center">
    <img src="https://github.com/kalilovers/sonchain/blob/main/assets/images/menu/dnssonstatus.png">
  </p>

  <ul dir="rtl" style="text-align: right;">
    <li><b>بخش  Destination:</b> مقصد مربوط به DNS تنظیم شده , که برای تنظیم موقت در فایل <code>resolv.conf</code> و همچنین در <code>iptables</code> هنگام استفاده از این ابزار به صورت موقت به عنوان DNS تنظیم خواهد شد .</li>
    <li><b>بخش IPTables Rules:</b> وضعیت فعلی رول های <code>iptables</code> را نمایش میدهد - طبق تصویر فعلی <code>Not Active</code> به این معنی است که در حال حاظر رول ها در حال استفاده نیستند که عادیست و زمان اجرای این ابزار به صورت موقت مورد استفاده قرار میگیرند .</li>
    <li><b>در صورت عدم وجود:</b> اگر فایل <code>DnsSon</code> وجود نداشته باشد یا مشکلات دیگری پیش بیاید، پیغام مناسب نمایش داده می‌شود.</li>
  </ul>

</details>









&nbsp;

<details>
  <summary dir="rtl" style="text-align: right;"> 2 | Install DnsSon</summary>

  <p dir="rtl" style="text-align: right;">
   
🧰 **این گزینه برای 'نصب DnsSon' استفاده میشود.**


  <br><br> برای شروع پس از انتخاب گزینه 2:
  <br><br> 1_ پرسش مربوطه را تایید کنید (درصورتی که درحال حاظر DnsSon نصب شده باشه این پرسش انجام میشود) > در صورت تایید "DnsSon" برای نصب تمیز حذف خواهند شد .
  <p align="center">
    <img src="https://github.com/kalilovers/sonchain/blob/main/assets/images/menu/dnssonsetup2.png">
  </p>





  <br> 2_ پس از پایان نصب پرسشی برای همگام سازی تنظیمات DnsSon با تنظیمات Dnsport-Tor انجام میشود , در صورتی که تایید کنید در صورت وجود Torو تنظیمات معتبر , همگام سازی انجام خواهد شد , در غیر اینصورت باید مقادیر آیپی و پورت Dns را به صورت دستی وارد کنید.
  <br> در نمونه زیر من همگام سازی را تایید کردم :
  <p align="center">
    <img src="https://github.com/kalilovers/sonchain/blob/main/assets/images/menu/dnssonsetup2-2.png">
  </p>
  
  <br> و مشخصات DNS به عنوان Nameserver در DnsSon تنظیم شد .



</details>







&nbsp;

<details>
  <summary dir="rtl" style="text-align: right;"> 3 | Change Destination</summary>

  <p dir="rtl" style="text-align: right;">
   
🧰 **این گزینه برای تغییر 'مقصد یا همان DNS' مورد استفاده در DnsSon استفاده میشود.**

 <br> 🔹 **در صورت عدم وجود کانفیگ DnsSon پیام مناسب نمایش داده میشود**
 <br> 🔹 **از تغییرات غیر استاندارد و اشتباه خودداری کنید**


  <br><br> برای شروع پس از انتخاب گزینه 3:
  <br><br> پس از وارد کردن مقادیر IP و PORT , بدون بررسی صحت محتوا ذخیره میشود **بنابراین در ویرایش تنظیمات احتیاط کنید**.
  <p align="center">
    <img src="https://github.com/kalilovers/sonchain/blob/main/assets/images/menu/dnssonsetup3.png">
  </p>

</details>







&nbsp;

<details>
  <summary dir="rtl" style="text-align: right;"> 4 | Synchronize With Tor</summary>

  <p dir="rtl" style="text-align: right;">
   
🧰 **این گزینه برای 'همگام سازی مقادیر DNS کانفیگ DnsSon با تنظیمات Dnsport مربوط به Tor' استفاده میشود.**

 <br> 🔹 **در صورت عدم وجود فایل کانفیگ یا خود Tor یا DnsSon پیام مناسب نمایش داده میشود**
 <br> 🔹 **برای اطلاعات بیشتر به داکیومنت مراجعه کنید**





  <br><br> برای شروع پس از انتخاب گزینه 4:
  <br><br> در نمونه زیر همگام سازی انجام شده و خروجی جدید نمایش داده شده.
  <p align="center">
    <img src="https://github.com/kalilovers/sonchain/blob/main/assets/images/menu/dnssonsetup4.png">
  </p>

</details>







&nbsp;

<details>
  <summary dir="rtl" style="text-align: right;"> 5 | Remove DnsSon</summary>

  <p dir="rtl" style="text-align: right;">
   
🧰 **این گزینه برای 'حذف DnsSon' استفاده میشود .**

&nbsp;

پرسش مربوطه را تایید کنید > در صورت تایید "DnsSon" حذف خواهند شد .

  <p align="center">
    <img src="https://github.com/kalilovers/sonchain/blob/main/assets/images/menu/dnssonsetup5.png">
  </p>

</details>

</details>










&nbsp;

<details>
<summary>7️⃣ ProxySon Setup</summary>

  <p dir="rtl" style="text-align: right;">
   
 🧰 **این منو برای 'مدیریت ProxySon' طراحی شده.**
 <br> 🔹**این ابزار به تنهایی قابل استفاده نیست و نیاز به "Tor" (یا یک پروکسی دیگر) + Proxychains یا Socksify برای نصب و همگام سازی با آنها دارد.**

![image](https://github.com/kalilovers/sonchain/blob/main/assets/images/menu/proxysonmenu.png)








 &nbsp;
 
<details>
  <summary dir="rtl" style="text-align: right;">1 | ProxySon Status</summary>

  <p dir="rtl" style="text-align: right;">
   
  🧰 **این گزینه برای 'بررسی وضعیت ProxySon' استفاده می‌شود.**  
  <br><br> برای مثال طبق تصویر زیر:
  </p>

  <p align="center">
    <img src="https://github.com/kalilovers/sonchain/blob/main/assets/images/menu/proxysonstatus.png">
  </p>

  <ul dir="rtl" style="text-align: right;">
    <li><b>بخش  Destination:</b> مقصد مربوط به DNS تنظیم شده , که برای تنظیم موقت در فایل <code>resolv.conf</code> و همچنین در <code>iptables</code> هنگام استفاده از این ابزار به صورت موقت به عنوان dns تنظیم خواهد شد .</li>
    <li><b>بخش Command:</b> نمایش 'دستور' تنظیم شده که توسط دستور <code>proxyson</code> اجرا خواهد شد.</li>
    <li><b>بخش Connection Status:</b> وضعیت اتصال را نشان می دهد - نتیجه حداکثر تا 10 ثانیه نمایش داده می شود.</li>
    <li><b>بخش IPTables Rules:</b> وضعیت فعلی رول های <code>iptables</code> را نمایش میدهد - طبق تصویر فعلی <code>Not Active</code> به این معنی است که در حال حاظر رول ها در حال استفاده نیستند که عادیست و زمان اجرای این ابزار به صورت موقت مورد استفاده قرار میگیرند .</li>
    <li><b>در صورت عدم وجود:</b> اگر فایل <code>proxyson</code> وجود نداشته باشد یا مشکلات دیگری پیش بیاید، پیغام مناسب نمایش داده می‌شود.</li>
  </ul>

</details>











&nbsp;

<details>
  <summary dir="rtl" style="text-align: right;"> 2 | Install ProxySon</summary>

  <p dir="rtl" style="text-align: right;">
   
🧰 **این گزینه برای 'نصب ProxySon' استفاده میشود.**


  <br><br> برای شروع پس از انتخاب گزینه 2:
  <br><br> 1_ پرسش مربوطه را تایید کنید (درصورتی که درحال حاظر ProxySon نصب شده باشه این پرسش انجام میشود)  > در صورت تایید "ProxySon" برای نصب تمیز حذف خواهند شد .
  <p align="center">
    <img src="https://github.com/kalilovers/sonchain/blob/main/assets/images/menu/proxysonsetup2.png">
  </p>






  <br> 2_ پس از پایان نصب پرسشی برای همگام سازی تنظیمات ProxySon با تنظیمات Dnsport-Tor انجام میشود , در صورتی که تایید کنید در صورت وجود Torو تنظیمات معتبر , همگام سازی انجام خواهد شد , در غیر اینصورت باید مقادیر آیپی و پورت Dns را به صورت دستی وارد کنید.
  <br> 3_ سپس پرسش بعدی انجام میشود > دستوری که تمایل دارید توسط proxyson مورد استفاده قرار گیرد را وارد کنید (درحالت پیشفرض socksify استفاده میشود) , مثل proxychains4 , یا با فشردن 'Enter' از مقدار پیشفرض استفاده خواهد شد.
  <br> در نمونه زیر من همگام سازی را تایید کردم و برای پرسش دوم هم 'Enter' را وارد کردم:
  <p align="center">
    <img src="https://github.com/kalilovers/sonchain/blob/main/assets/images/menu/proxysonsetup2-2.png">
  </p>
  
  <br> و مشخصات DNS به عنوان Nameserver در ProxySon تنظیم شد .
  <br> همچنین دستور پیشفرض 'socksify' به عنوان دستور مورد اجرا تنظیم شد .


</details>







&nbsp;

<details>
  <summary dir="rtl" style="text-align: right;"> 3 | Change Destination</summary>

  <p dir="rtl" style="text-align: right;">
   
🧰 **این گزینه برای تغییر 'مقصد یا همان DNS' مورد استفاده در ProxySon استفاده میشود.**

 <br> 🔹 **در صورت عدم وجود کانفیگ ProxySon پیام مناسب نمایش داده میشود**
 <br> 🔹 **از تغییرات غیر استاندارد و اشتباه خودداری کنید**


  <br><br> برای شروع پس از انتخاب گزینه 3:
  <br><br> پس از وارد کردن مقادیر IP و PORT , بدون بررسی صحت محتوا ذخیره میشود **بنابراین در ویرایش تنظیمات احتیاط کنید**.
  <p align="center">
    <img src="https://github.com/kalilovers/sonchain/blob/main/assets/images/menu/proxysonsetup3.png">
  </p>

</details>











&nbsp;

<details>
  <summary dir="rtl" style="text-align: right;"> 4 | Change Command</summary>

  <p dir="rtl" style="text-align: right;">
   
🧰 **این گزینه برای تغییر 'فرمان اجرایی تنظیم شده' توسط ProxySon استفاده میشود.**

 <br> 🔹 **در صورت عدم وجود فایل کانفیگ یا خود Tor یا ProxySon پیام مناسب نمایش داده میشود**
 <br> 🔹 **برای اطلاعات بیشتر به داکیومنت مراجعه کنید**





  <br><br> برای شروع پس از انتخاب گزینه 4:
  <br><br> در نمونه زیر تغییرات انجام شده و خروجی جدید نمایش داده شده.
  <br> دستور proxychains4 را وارد کردم.
  <p align="center">
    <img src="https://github.com/kalilovers/sonchain/blob/main/assets/images/menu/proxysonsetup4.png">
  </p>

</details>






&nbsp;

<details>
  <summary dir="rtl" style="text-align: right;"> 5 | Sync with Tor</summary>

  <p dir="rtl" style="text-align: right;">
   
🧰 **این گزینه برای 'همگام سازی مقادیر DNS کانفیگ ProxySon با تنظیمات Dnsport مربوط به Tor' استفاده میشود.**

 <br> 🔹 **در صورت عدم وجود فایل کانفیگ یا خود Tor یا ProxySon پیام مناسب نمایش داده میشود**
 <br> 🔹 **برای اطلاعات بیشتر به داکیومنت مراجعه کنید**





  <br><br> برای شروع پس از انتخاب گزینه 5:
  <br><br> در نمونه زیر همگام سازی انجام شده و خروجی جدید نمایش داده شده.
  <p align="center">
    <img src="https://github.com/kalilovers/sonchain/blob/main/assets/images/menu/proxysonsetup5.png">
  </p>

</details>








&nbsp;

<details>
  <summary dir="rtl" style="text-align: right;"> 6 | Remove ProxySon</summary>

  <p dir="rtl" style="text-align: right;">
   
🧰 **این گزینه برای حذف ProxySon استفاده میشود .**

&nbsp;

پرسش مربوطه را تایید کنید > در صورت تایید "ProxySon" حذف خواهند شد .

  <p align="center">
    <img src="https://github.com/kalilovers/sonchain/blob/main/assets/images/menu/proxysonsetup6.png">
  </p>

</details>










</details>

&nbsp;


<details>
<summary>8️⃣ Update Script</summary>

  <p dir="rtl" style="text-align: right;">
   
 🧰 **این گزینه برای بروزرسانی اسکریپت Sonchain طراحی شده است.**

  <br> ♻️ **پس از انتخاب این گزینه , جهت بررسی آخرین نسخه موجود و نصب , پرسش مربوط به بروزرسانی را تایید کنید**.
  <br> ♻️ **این گزینه فقط خود اسکریپت Sonchain را بروزرسانی میکند و ارتباطی با ابزار های نصب شده توسط اسکریپت ندارد**.


</details>

&nbsp;



<details>
<summary>9️⃣ Uninstall</summary>

  <p dir="rtl" style="text-align: right;">
   
 🧰 **این منو برای 'حذف اسکریپت یا ابزار های نصب شده' طراحی شده.**

![image](https://github.com/kalilovers/sonchain/blob/main/assets/images/menu/uninstallmenu.png)


  <br><br> 🗑 **گزینه مورد نظر را برای حذف انتخاب کرده و تایید کنید تا عملیات حذف آغاز شود**.






</details>

&nbsp;



- [↪️ بازگشت به فهرست مطالب](#list)












<br><br><br>

&nbsp;
<a id="thanks"></a>
## 🙏 تشکر و قدردانی

سپاس ویژه از:
- **کانال و گروه https://t.me/OPIran_official :** که با اشتراک ابزار های کاربردی و پروژه ها و مطالب فنی به افزایش دانش عمومی کمک میکند.
- **کانال و سایت [Digitalvps](https://t.me/digital_vps) :** که با ارایه تجهیزات مورد نیاز برای تست و بررسی در سهولت بیشتر نقش قابل توجهی ایفا کرد.







<br><br><br>
<a id="contact"></a>
<h2>📞 تماس با من</h2>
<p>
<ul>
  <li>ایمیل : kaliloverscontact@gmail.com
  <li>یا از بخش Issues گیت هاب استفاده کنید .
</ul>
</p>






 

<br><br><br>
<a id="Financialsupport"></a>
## 💰 Donation
🤝 ****حمایت از سازنده پروژه و توسعه بیشتر:****
 
- **Bitcoin :**
```bash
bc1q83yf8k5klulj5n2nh7zmergjsjcwj72x4h8a6c
```
- **Tron TRX Or USDT** :
```bash
TAodRbeJmtj7Lj48TZeds84BKmYVtXpdaJ
```
- [↪️ بازگشت به فهرست مطالب](#list)

