def integrate_kali_tools(self):
    """Kali Linux vositalari bilan integratsiya"""
    tools = {
        "nmap": "sudo nmap -sS -sV -O -T4",
        "nikto": "nikto -h",
        "sqlmap": "sqlmap -u",
        "metasploit": "msfconsole",
        "john": "john --wordlist",
        "hydra": "hydra -l admin -P passlist.txt"
    }
    
    # Har bir tool uchun GUI tugma
    for tool, command in tools.items():
        btn = tk.Button(self.tool_frame, text=f"🛠️ {tool}", 
                       command=lambda cmd=command: self.run_kali_tool(cmd))
        btn.pack(side=tk.LEFT, padx=2)
