# CNT4713_Project2_Group21

## Members and IDs
### Emre Akilli - 6537421
Contributions:
* Display IPs for queried domain name

### Sabrina Vasquez - 6443277
Contributions: 
* Send query to root DNS server
* Receive reply from root DNS server

### Carlos Velazquez - 6566016
Contributions:
* Display server reply content
* Extract intermediate DNS server IP
* Send query to intermediate servers

### Gabriel Somek - 6150276
Contributions:
* Receive reply from intermediate servers

## Programming Language
Python 3

## Run Instructions
python mydns.py \<domain-name> \<root-dns-ip>

## Example
python mydns.py cs.fiu.edu 202.12.27.33