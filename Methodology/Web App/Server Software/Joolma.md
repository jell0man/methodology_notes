## Scanning
We can determine the version of Joomla! running using [Joomscan](https://github.com/OWASP/joomscan)

Usage
```bash
git clone https://github.com/OWASP/joomscan.git # already ~/tools/joomscan
cd joomscan
perl joomscan.pl -u http://target.com/joomla
```