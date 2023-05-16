# Guest Management System v1.0 has reflected cross-site scripting

BUG_Author: DRXYJ

Website source code address:  https://www.sourcecodester.com/php/14664/guest-management-system-php-full-source-code.html

Vulnerability File: /guestmanagement/dateTest.php

GET parameter "name" exists reflected cross-site scripting vulnerability

Payload: /guestmanagement/dateTest.php?name="><script>alert(document.cookie)</script>&name1=Submit

The js code is successfully executed and the cookie value is returned, which proves that there is a reflected cross-site scripting vulnerability.

![image](https://github.com/xryj920/CVE/blob/main/xss.png)
