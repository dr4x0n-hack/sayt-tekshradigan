# 1. Dasturni yuklab olish
git clone https://github.com/sizning-repo/kali-pentest-gui.git
cd kali-pentest-gui

# 2. Zarur kutubxonalarni o'rnatish
sudo apt update
sudo apt install -y python3-pip python3-tk
sudo pip3 install requests python-nmap python-whois dnspython pillow

# 3. Dasturni ishga tushirish
sudo python3 kali_pentest_gui.py
# Yoki ruxsatlar bilan:
chmod +x kali_pentest_gui.py
./kali_pentest_gui.py
