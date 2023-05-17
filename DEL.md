# Seacms v11.6 has Delete any file in the foreground

Website source address: https://github.com/seacms-net/CMS

Register and log in at the foreground, and then capture the package where the picture is uploaded.

![image](https://github.com/xryj920/CVE/blob/main/pic1.png)

Capture the package and then there is oldpic at the bottom of the package, which indicates the path under the root directory of the project, the default is uploads/user/a.png, modify it to the file path under the root directory and then delete any file

![image](https://github.com/xryj920/CVE/blob/main/pic2.png)

Source code audit: Oldpic will be deleted when uploading .

![image](https://github.com/xryj920/CVE/blob/main/pic3.png)
