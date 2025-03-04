# SSL Certificate Expiry Checker  

This Python script monitors SSL certificate expiration dates for **both local PEM files** and **remote domains**. It sends an email alert when certificates are close to expiring, with all configuration options set via a `.env` file.  

## **Features**  
✅ Checks SSL certificates from local `.pem` files.  
✅ Checks SSL certificates of remote domains over HTTPS.  
✅ Sends email alerts if a certificate is nearing expiry.  
✅ Configurable expiration threshold (e.g., alert if ≤15 days left).  
✅ Supports logging and email notifications.  
✅ Environment variables for secure and flexible configuration.  

---

## **Installation**  

### **1. Clone the Repository**  
```sh
git clone https://github.com/yourusername/ssl-cert-checker.git
cd ssl-cert-checker
```

### **2. Install Dependencies**  
```sh
pip install -r requirements.txt
```

### **3. Configure the `.env` File**  
Rename `.env.example` to `.env` and update the values:  
```sh
mv .env.example .env
```
Then, edit `.env` to set your configurations.

---

## **Configuration**  

### **Environment Variables (in `.env`)**  

| Variable                 | Description |
|-------------------------|-------------|
| `CERT_FILE_PATHS`       | Comma-separated paths to local PEM certificate files. |
| `DOMAINS_TO_CHECK`      | Comma-separated list of domains to check. |
| `ALERT_THRESHOLD_DAYS`  | Number of days before expiration to trigger an alert. |
| `ALWAYS_SEND_EMAIL`     | If `True`, sends a report even if no certificates are expiring. |
| `EMAIL_HOST`            | SMTP server (e.g., `smtp.gmail.com`). |
| `EMAIL_PORT`            | SMTP port (default: `465` for SSL). |
| `EMAIL_HOST_USER`       | Sender email address. |
| `EMAIL_HOST_PASSWORD`   | App password for email authentication. |
| `EMAIL_RECIPIENTS`      | Comma-separated list of recipient emails. |
| `MACHINE_NAME`          | Name of the machine running the script. |
| `SERVER_LOCATION`       | Custom label for server location (included in emails). |

---

## **Usage**  

### **Run the Script**  
```sh
python ssl_cert_checker.py
```

### **Run on a Schedule (Linux)**  
To check certificates daily, add this to `crontab -e`:  
```sh
0 8 * * * /usr/bin/python3 /path/to/ssl_cert_checker.py
```
This will run the script every day at **8:00 AM**.

---

## **Logging**  
- Logs are saved in the `logs/` folder.  
- To enable **debug mode**, set `LOG=1` in `.env`.  

---

## **Email Alerts**  
✅ If any certificate is **expiring soon**, an **alert email** is sent.  
✅ If `ALWAYS_SEND_EMAIL=True`, a **summary email** is sent even if no alerts exist.  

---

### **🔹 Automating the Script on Windows using Task Scheduler**  

To run the **SSL Certificate Expiry Checker** automatically on Windows, use **Task Scheduler** to execute it at a fixed interval (e.g., daily at 8:00 AM).  

---

### **🛠 Step 1: Ensure Python is Installed**  
1. Open **Command Prompt (cmd)** and type:  
   ```sh
   python --version
   ```
   If Python is installed, it will show the version number.  
   
2. If Python is not installed, [download and install it](https://www.python.org/).  
   - During installation, check the box **“Add Python to PATH”**.  

---

### **📍 Step 2: Find the Python and Script Paths**  
You'll need two important file paths:  

1. **Python Executable Path**  
   - Run the following command in **Command Prompt**:  
     ```sh
     where python
     ```
   - Example output:  
     ```
     C:\Users\YourUser\AppData\Local\Programs\Python\Python39\python.exe
     ```
   - Copy this **Python path**.

2. **Script File Path**  
   - Locate the `ssl_cert_checker.py` script.  
   - Right-click the file → **Properties** → Copy the **full path** (e.g., `C:\Users\YourUser\ssl_cert_checker.py`).  

---

### **📅 Step 3: Create a Scheduled Task**  

1. Press `Win + R`, type **`taskschd.msc`**, and press `Enter`.  
2. Click **“Create Basic Task”**.  
3. **Name the task**:  
   - Example: `SSL Certificate Expiry Checker`.  
4. **Set the Trigger**:  
   - Choose **“Daily”** and set the time (e.g., `08:00 AM`).  

---

### **⚡ Step 4: Configure the Action**  

1. Choose **"Start a Program"** → Click **Next**.  
2. **Program/script**:  
   - Paste the **Python executable path** (e.g., `C:\Users\YourUser\AppData\Local\Programs\Python\Python39\python.exe`).  
3. **Add arguments (optional)**:  
   - Add the script path in quotes. Example:  
     ```
     "C:\Users\YourUser\ssl_cert_checker.py"
     ```
4. Click **Next** → **Finish**.

---

### **✅ Step 5: Test the Task**  

1. Open **Task Scheduler**.  
2. Find the task under **Task Scheduler Library**.  
3. Right-click → **Run**.  
4. Check the `logs/` folder for a new log file (e.g., `2025_03_04__08_00.log`).  

---

### **🔧 Troubleshooting**  
| Issue | Solution |
|--------|----------|
| **Script doesn’t run** | Ensure Python is installed and the `.env` file is correctly configured. |
| **Email not sent** | Check SMTP settings and enable App Passwords for Gmail. |
| **Permissions error** | Run Task Scheduler as **Administrator**. |

---

### **🗑 How to Edit or Delete the Task**  
- To **edit**: Open Task Scheduler → Right-click task → **Properties** → Modify settings.  
- To **delete**: Right-click the task → **Delete**.  

---

The script will now **run automatically at the scheduled time** to monitor SSL certificate expirations and send alerts. 🚀

---

## **Contributing**  
1. Fork the repository.  
2. Create a new branch: `git checkout -b feature-name`.  
3. Commit your changes: `git commit -m "Added feature XYZ"`.  
4. Push to the branch: `git push origin feature-name`.  
5. Submit a pull request!  

---

## **License**  
This project is licensed under the MIT License.  

---

## **Author**  
Developed by **Rafael Oliveira** – [contact@rafaelaugustodev.com](mailto:contact@rafaelaugustodev.com)  
