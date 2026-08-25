# Records demo.gif from a REAL Tblue scan (no simulation).
#
#   pip install tblue
#   vhs demo.tape
#
# A curated --only set keeps the recording short; drop it to run all 582.
# The hidden setup clears prior history so the demo shows a clean first run.

Output demo.gif

Set FontSize 13
Set Width 920
Set Height 620
Set Theme "Dracula"
Set TypingSpeed 45ms
Set CursorBlink false
Set Padding 20

Hide
Type "cd $(mktemp -d) && rm -rf ~/.tblue/history/example.com && clear"
Enter
Show

Sleep 400ms
Type "tblue -u https://example.com -d 1 --only headers,csp,cookies,clickjacking,mixed_content,dns_caa,js_secrets,hsts_preload"
Sleep 600ms
Enter
Sleep 14s
