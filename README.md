# 🚀 Automate-Check-3rd-Party

โปรเจกต์นี้คือระบบอัตโนมัติ (Automation) สำหรับทีม Security Operations Center (SOC) เพื่อลดระยะเวลาในการวิเคราะห์เบื้องต้น (Triage) และแก้ปัญหา Alert Fatigue ระบบจะคอยดักจับ Ticket ใหม่ที่เข้ามาใน Jira ดึง IP Address สาธารณะออกมา และตรวจสอบประวัติภัยคุกคามจาก 3rd Party Threat Intelligence ชั้นนำ ก่อนจะสรุปผลและคอมเมนต์กลับเข้าไปใน Ticket ทันที

## 🛠️ แพลตฟอร์มวิเคราะห์ภัยคุกคามที่ใช้ (Threat Intelligence)
* **VirusTotal:** ตรวจสอบ IP ว่าถูกสแกนพบเป็นภัยคุกคามจาก Antivirus Engines กี่แห่ง พร้อมดึงข้อมูลเจ้าของโครงข่าย (ASN) และคะแนน Reputation
* **AbuseIPDB:** ตรวจสอบประวัติพฤติกรรมไม่พึงประสงค์ (เช่น สแกนพอร์ต, โจมตี) ระบุระดับความเสี่ยง (%) และดึงสถานะ Whitelist เพื่อป้องกัน False Positive
* **AlienVault OTX:** ตรวจสอบความเชื่อมโยงของ IP กับแคมเปญการโจมตี (Pulse) พร้อมระบุชื่อแคมเปญล่าสุดและข้อมูล Geolocation

## 💻 เครื่องมือที่ใช้พัฒนา (Development Stack)
* **Python 3.x:** ภาษาหลักที่ใช้เขียน Logic และเชื่อมต่อ API
* **FastAPI & Uvicorn:** สร้าง Web Server และ API Endpoint เพื่อรอรับ Webhook จาก Jira
* **ngrok:** เครื่องมือสร้าง Tunnel เพื่อเปิด Localhost ออกสู่อินเทอร์เน็ตสำหรับการทำ Webhook
* **Jira Python Library:** ใช้จัดการและพ่นคอมเมนต์กลับเข้าไปใน Ticket

---

## ⚙️ ขั้นตอนการติดตั้ง (Installation)

**1. Clone โค้ดลงเครื่อง**
เปิด Terminal แล้วรันคำสั่ง:
`git clone <ลิงก์_repository_ของคุณ>`
`cd <ชื่อโฟลเดอร์_โปรเจกต์>`

**2. ติดตั้งไลบรารีที่จำเป็น (Dependencies)**
รันคำสั่งด้านล่างนี้เพื่อติดตั้งแพ็กเกจทั้งหมดที่โค้ดต้องใช้:
`pip install fastapi uvicorn requests pycountry jira`

**3. การตั้งค่า API Keys (Configuration)**
เปิดไฟล์ `main.py` และอัปเดตตัวแปรเหล่านี้ให้เป็นข้อมูลของคุณ:
* `JIRA_URL`, `JIRA_EMAIL`, `JIRA_TOKEN`: ข้อมูลบัญชี Jira และ API Token
* `VT_API_KEY`: กุญแจจาก VirusTotal
* `AB_API_KEY`: กุญแจจาก AbuseIPDB
* `ALIENVAULT_API_KEY`: กุญแจจาก AlienVault OTX

---

## 🚀 วิธีการรันโปรเจกต์ (How to Run)

โปรเจกต์นี้รองรับการทำงาน 2 โหมด ได้แก่ โหมดทดสอบ (Local Test) และโหมดรับงานจริง (Production Webhook)

### โหมดที่ 1: รันเพื่อทดสอบ (Local Test)
ใช้สำหรับทดสอบการทำงานของ Threat Intel APIs ว่าสามารถดึงข้อมูลได้ถูกต้องหรือไม่ โดยไม่ต้องเชื่อมต่อกับ Jira
`python test_ip_check.py`
*(ระบบจะทำการทดสอบกับ IP ตัวอย่าง 3 ชุด และแสดงผลลัพธ์เป็นแผนผังต้นไม้บน Terminal)*

### โหมดที่ 2: เปิดระบบรอรับ Webhook จาก Jira (Live Mode)
**Terminal ที่ 1 (เปิดเซิร์ฟเวอร์บอท):**
`uvicorn main:app --reload`
*(ระบบจะรัน FastAPI ขึ้นมาที่พอร์ต 8000)*

**Terminal ที่ 2 (เปิด ngrok เพื่อสร้าง Public URL):**
`ngrok http 8000`
*(ก๊อปปี้ URL ที่ขึ้นต้นด้วย `https://...ngrok-free.app` ไปใช้ในขั้นตอนถัดไป)*

---

## 🔗 การตั้งค่า Jira Webhook
1. เข้าไปที่ **Project Settings** ใน Jira
2. ไปที่ **Automation** และสร้าง Rule ใหม่
3. **Trigger:** เลือก `Issue created` (หรือเงื่อนไขตามที่ SOC ต้องการ)
4. **Action:** เลือก `Send web request`
5. **Web request URL:** นำลิงก์จาก ngrok มาวาง แล้วต่อท้ายด้วย `/jira-webhook` (เช่น `https://1234.ngrok-free.app/jira-webhook`)
6. **HTTP method:** เลือก `POST`
7. **Webhook body:** เลือก `Issue data (JSON)`
8. กด Save และ Turn on rule

---

## 📌 ข้อจำกัดที่ควรทราบ (Known Limitations)
* **Jira Free Plan:** หากใช้ Jira แพ็กเกจฟรี จะมีโควต้าการทำงานของ Automation อยู่ที่ 100 ครั้ง/เดือน หากโควต้าหมด Webhook จะไม่ถูกส่ง (แนะนำให้นำไป Implement บน Jira ระดับ Production ขององค์กร)
* **การแสดงผลรูปธงชาติ (OS Emojis):** ระบบปฏิบัติการ Windows ไม่รองรับการแสดงผล Color Emoji รูปธงชาติ หากเปิดผ่านเบราว์เซอร์บน Windows อาจเห็นเป็นรูปหมุด (📍) หรือตัวอักษรย่อประเทศแทน แต่จะแสดงผลเป็นรูปธงชาติปกติเมื่อเปิดผ่าน macOS, iOS หรือ Androidomation อยู่ที่ 100 ครั้ง/เดือน หากโควต้าหมด Webhook จะไม่ถูกส่ง (แนะนำให้นำไป Implement บน Jira ระดับ Production ขององค์กร)
* **การแสดงผลรูปธงชาติ (OS Emojis):** ระบบปฏิบัติการ Windows ไม่รองรับการแสดงผล Color Emoji รูปธงชาติ หากเปิดผ่านเบราว์เซอร์บน Windows อาจเห็นเป็นรูปตัวอักษรย่อประเทศแทน แต่จะแสดงผลเป็นรูปธงชาติปกติเมื่อเปิดผ่าน macOS, iOS หรือ Android
