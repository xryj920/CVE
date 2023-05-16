BUG_Author: DRXYJ

Vulnerability File: /guestmanagement/dateTest.php

GET parameter "name" exists reflected cross-site scripting vulnerability

Payload: /guestmanagement/dateTest.php?name="><script>alert(document.cookie)</script>&name1=Submit

The js code is successfully executed and the cookie value is returned, which proves that there is a reflected cross-site scripting vulnerability.

![image](https://github.com/xryj920/CVE/blob/main/xss.png)
