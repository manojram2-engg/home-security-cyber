# Home Lab Attack Surface Snapshot

A working web app: a Node backend runs Nmap on your lab, maps every service version to public exploits
with searchsploit, streams live progress, stores scan history and feeds the dashboard. Zero dependencies.

## Run it (Kali / Linux / macOS)
    sudo apt install nmap exploitdb      # Kali already has both
    node server.js                       # Node 18+
    open http://127.0.0.1:3000

Click "Run demo" first to see the whole flow with dummy data and nothing scanned.

## Safety built in
- Only private IPv4 targets (10.x, 172.16-31.x, 192.168.x, 127.x), CIDR no larger than /22
- Authorization checkbox required, enforced by the server
- Nmap/searchsploit launched with fixed argument lists, never through a shell
- One scan at a time, 15 minute timeout, binds to 127.0.0.1 by default
- Requests need a custom header and same-origin, blocking cross-site triggers
Set HOST=0.0.0.0 only if you understand the exposure; the server has no login.

## Static hosting (Netlify)
Deploy the `public/` folder. With no server behind it the page switches to static mode: scanning is
disabled, but you can still drop an Nmap `-oX` file onto "Analyse your own scan".

## Files
- server.js: API, scan runner, SSE progress, history in ./data
- public/index.html: dashboard
- map_vulns.py: standalone Nmap XML to searchsploit script
- sample-scan.xml: dummy scan
