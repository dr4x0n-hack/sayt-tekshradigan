def network_monitor(self):
    """Real-time tarmoq monitori"""
    import psutil
    
    while self.monitoring:
        # Network statistikasi
        net_io = psutil.net_io_counters()
        
        self.log_message(f"📡 Network: Sent={net_io.bytes_sent:,} | "
                        f"Recv={net_io.bytes_recv:,} | "
                        f"Packets={net_io.packets_sent:,}")
        
        # CPU va Memory
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        
        self.update_stats(cpu_percent, memory.percent)
        time.sleep(2)
