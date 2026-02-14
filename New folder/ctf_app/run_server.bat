@echo off
echo Setting environment variables...
set SECRET_KEY=lan_secret_key_change_me_if_public
set ADMIN_PASSWORD=admin_password_change_me

echo Starting CTF Platform...
python app.py
pause
