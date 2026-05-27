from main import check_virustotal, check_abuseipdb, check_alienvault

def test_ips():
    # สุ่ม IP สาธารณะมาทดสอบ 3 IP
    test_ips_list = [
        "8.8.8.8",        # Google Public DNS (น่าจะ Clean)
        "1.1.1.1",        # Cloudflare DNS (น่าจะ Clean)
        "209.74.65.20"    # IP ที่มีประวัติ
    ]
    
    print("=" * 60)
    print("🚀 เริ่มการทดสอบตรวจสอบ IP (Full SOC Context Local Test)")
    print("=" * 60)
    
    for ip in test_ips_list:
        print(f"\n[*] กำลังตรวจสอบ IP: {ip}")
        print("-" * 60)
        
        # เรียกใช้ฟังก์ชันจาก main.py โดยตรง
        vt_result = check_virustotal(ip)
        ab_result = check_abuseipdb(ip)
        otx_result = check_alienvault(ip) 

        
        # ปริ้นท์ผลลัพธ์ออกมาตรงๆ แบบไม่เติมตัวอักษรนำหน้า 
        # เพื่อให้เส้นสาขา (├, └) และการเว้นวรรค (Indent) ทำงานได้สมบูรณ์
        print(vt_result)
        print(ab_result)
        print(otx_result)
        
        
    print("\n" + "=" * 60)
    print("🏁 สิ้นสุดการทดสอบ")
    print("=" * 60)

if __name__ == "__main__":
    test_ips()