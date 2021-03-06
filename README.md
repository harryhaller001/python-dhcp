python-dhcp
===========
DHCP implementation in python (based on http://code.activestate.com/recipes/577649-dhcp-query/).


Usage
-----
Request DHCP information from router.
```python
from dhcp import full_request

print(full_request())
```

Output as python dictionary:

```
{"op": 2, "htype": 1, "hlen": 6, ...  }
```

Request subnet-mask of local network:

```python
from dhcp import get_subnet_mask

print(get_subnet_mask())
```

Output as string:

```
"255.255.255.0"
```

License
-------

MIT License

Copyright (c) 2019 harryhaller001

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
