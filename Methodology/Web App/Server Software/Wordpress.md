Admin login page
	/wp-admin

Automated Enumeration
```
# basic usage
wpscan --url "target" --verbose

# enumerate vulnerable plugins, users, vulrenable themes, timthumbs

wpscan --url "target" --enumerate vp,u,vt,tt --follow-redirection --verbose --log target.log

wpscan --url "target" --enumerate p,t --follow-redirection --verbose --log target.log

	p # plguins
	vp # vulnerable plugins
	u # users
	vt # vulnerable themes
	tt # timthumbs
	t # themes
	
	# may need to seperate p and t from the rest (seperate scan)

# Add Wpscan API to get the details of vulnerabilties.
wpscan --url http://alvida-eatery.org/ --api-token NjnoSGZkuWDve0fDjmmnUNb1ZnkRw6J2J1FvBsVLPkA 

#Accessing Wordpress shell
http://10.10.67.245/retro/wp-admin/theme-editor.php?file=404.php&theme=90s-retro

http://10.10.67.245/retro/wp-content/themes/90s-retro/404.php

```