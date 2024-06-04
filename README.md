# XSSRecon - Reflected XSS Scanner
![python](https://img.shields.io/pypi/pyversions/Django.svg)
![size](https://img.shields.io/github/size/ak-wa/XSSRecon/xssrecon.py.svg)
![lastcommit](https://img.shields.io/github/last-commit/ak-wa/XSSRecon.svg)
![follow](https://img.shields.io/github/followers/ak-wa.svg?label=Follow&style=social)


* Scans a website for reflected Cross-Site-Scripting
* Zero false positives, its using a real browser checking for the popups
* Automatic out-of-scope checking (experimental, but works very well yet)
* Uses Python 3.7 with selenium / geckodriver (chrome has anti-xss protections)
* Crawler or single URL scanner
* Configurable:   
--target | Target to scan   
--crawl | Activate crawler   
--wordlist | Wordlist to use   
--delay | Delay between requests   
--visible | Visible browser for debugging (geckodriver/firefox)   
--silent | Only print when vulns have been found   

## Usage & examples

1. Single URL Scan

`
python3 xssrecon.py --target https://example.com/index.php?id=
`
![](docs/xssrecon_singleurl.gif)   

2. Crawler   

`
python3 xssrecon.py --target https://example.com --crawl
`
![](docs/xssrecon3.gif)   

## FAQ   
* It doesnt recognize geckodriver on my system!   
Solution:
1. Run these commands:   
```   
wget https://github.com/mozilla/geckodriver/releases/download/v0.23.0/geckodriver-v0.23.0-linux64.tar.gz   
sh -c 'tar -x geckodriver -zf geckodriver-v0.23.0-linux64.tar.gz -O > /usr/bin/geckodriver' 
chmod +x /usr/bin/geckodriver   
rm geckodriver-v0.23.0-linux64.tar.gz   
```

2. Then append 
`export PATH=$PATH:[/usr/bin/geckodriver]`
to ~/.bashrc

3. type "bash" into terminal

    Sources:   
   https://askubuntu.com/questions/870530/how-to-install-geckodriver-in-ubuntu
   https://softwaretestingboard.com/q2a/2326/how-do-i-set-geckodriver-on-kali-linux#axzz66Zfm8sCa

* Its too fast! I think its not working correctly!   
Because of that there is the --delay argument :)

* My terminal doesnt seem to work correctly with this tool, instead of showing "live" results it spams my terminal!   
I am working on this, the tool works perfectly on Kali 2019.3, but on 2019.4 ive noticed it spams the terminal (though it does still run like a charm when you use the xterm terminal (for that, simply enter `xterm` into the default terminal)).
If that happens to you, live with the spam or use the `--silent` argument, which only prints when it found a vulnerability

* The crawler scans each href on the website, without checking for duplicates!   
Im working on that, the crawler is experimental yet

* Why cant it do DOM based XSS & generate its own payloads!!   
Im not a cross-site-scripting expert, and i plan to do both of those!

* I want to help!   
Thats great! Feel free to message me! :)
