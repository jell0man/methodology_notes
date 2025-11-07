`steghide`
	how to extract?
		`man steghide` for tutorial
	`steghide extract -sf image.jpg`

`exiftool <file>`

#### Crack steghide files

Old way `stegcracker`
	`stegcracker <file> <wordlist> -t <threads>` default is 16
	retired
	replaced by stegseek

New Way `stegseek`
https://github.com/RickdeJager/stegseek/blob/master/BUILD.md
i have installed already
	Bruteforce
		`stegseek <file> <wordlist>
	Passwordless extraction
		`steegseek --seed <file>`