python-dhcp
===========
DHCP implementation in python.


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
print(get_subnet_mask())
```

Output as string:

```
"255.255.255.0"
```

License
-------

