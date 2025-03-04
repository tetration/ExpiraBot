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
