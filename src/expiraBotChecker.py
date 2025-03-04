import os
import ssl
import socket
import smtplib
import logging
import time
from dotenv import load_dotenv
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# If you want to automatically load the .env, install python-dotenv:
#   pip install python-dotenv
# and then uncomment the following lines:
#
# from dotenv import load_dotenv
# load_dotenv()  # Loads .env into os.environ

from cryptography import x509
from cryptography.hazmat.backends import default_backend
# Create the directory to store logs if it doesn't exist already
if not os.path.exists('logs'):
    os.mkdir('logs')
# Configure logging
logging.basicConfig(
    level=logging.DEBUG if os.getenv('LOG') == '1' else logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(f"logs/{time.strftime('%Y_%m_%d__%H_%M', time.localtime(time.time()))}.log"),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger() # Starts logging everything

# Function to check and create .env.example file without sensitive information
def check_and_create_env_file(file_path='.env'):
    if not os.path.exists(file_path):
        logger.warning("No .env.example file found! Generating one...")
        with open(file_path, "w") as env_file:
            env_file.write("# --- Always send email ---\n")
            env_file.write("# If set to true, the script will always send an email, even if no certificates are about to expire\n")
            env_file.write("ALWAYS_SEND_EMAIL=True\n\n")

            env_file.write("# --- LOCAL CERTIFICATES ---\n")
            env_file.write("# Comma-separated list of full paths to PEM certificate files\n")
            env_file.write("CERT_FILE_PATHS=/path/to/cert1.pem,/path/to/cert2.pem\n\n")

            env_file.write("# --- REMOTE DOMAINS ---\n")
            env_file.write("# Comma-separated list of domains to check\n")
            env_file.write("DOMAINS_TO_CHECK=example.com,another-example.com\n\n")

            env_file.write("# --- ALERT THRESHOLD ---\n")
            env_file.write("# If a certificate has fewer days left than this threshold, we send a warning\n")
            env_file.write("ALERT_THRESHOLD_DAYS=15\n\n")

            env_file.write("# --- EMAIL SETTINGS ---\n")
            env_file.write("EMAIL_HOST=smtp.example.com\n")
            env_file.write("EMAIL_PORT=465\n")
            env_file.write("EMAIL_HOST_USER=bot@example.com\n")
            env_file.write("EMAIL_HOST_PASSWORD=EMAIL_APP_PASSWORD\n")
            env_file.write("EMAIL_RECIPIENTS=recipient1@example.com,recipient2@example.com\n\n")

            env_file.write("# --- SYSTEM INFO ---\n")
            env_file.write("MACHINE_NAME=server_name\n")
            env_file.write("SERVER_LOCATION=office_location\n")

        logger.warning(f"{file_path} created with example values.")
    else:
        logger.warning(f"{file_path} already exists. Skipping creation.")

# Load the .env file
def load_environment_variables(file_path='.env'):
    check_and_create_env_file(file_path)
    load_dotenv(file_path)
    logger.info(f"Environment variables succesfully loaded from {file_path}.")


def load_cert_from_file(cert_file_path: str):
    """
    Loads a local PEM certificate file using cryptography.
    Returns an x509 object or None if there's an error.
    """
    try:
        with open(cert_file_path, 'rb') as cert_file:
            cert_data = cert_file.read()
        cert = x509.load_pem_x509_certificate(cert_data, default_backend())
        return cert
    except Exception as e:
        print(f"[ERROR] Could not load certificate {cert_file_path}: {e}")
        logger.error(f"[ERROR] Could not load certificate {cert_file_path}: {e}")
        return None


def check_local_certificate_expiration(cert):
    """
    Given an x509 certificate object, returns:
    (expiration_datetime, days_left).
    """
    expiration_datetime = cert.not_valid_after
    days_left = (expiration_datetime - datetime.utcnow()).days
    return expiration_datetime, days_left


def get_ssl_expiration_date(domain):
    """
    Connects via SSL to a domain on port 443 and retrieves
    the certificate's expiration date as a datetime object.
    Returns None if there's an error.
    """
    context = ssl.create_default_context()
    try:
        with socket.create_connection((domain, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                ssl_info = ssock.getpeercert()
                # 'notAfter' example: 'Mar 13 23:59:59 2025 GMT'
                expiry_str = ssl_info['notAfter']
                expiry_date = datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y GMT")
                return expiry_date
    except Exception as e:
        print(f"[ERROR] Could not get SSL certificate for {domain}: {e}")
        logger.error(f"[ERROR] Could not get SSL certificate for {domain}: {e}")
        return None


def send_email(subject, body, to_emails, from_email, smtp_server, smtp_port, smtp_user, smtp_password):
    """
    Sends an email using SMTP (SSL).
    `to_emails` should be a list of recipients.
    """
    msg = MIMEMultipart()
    msg['From'] = from_email
    msg['To'] = ", ".join(to_emails)  # for the header only
    msg['Subject'] = subject

    msg.attach(MIMEText(body, 'plain'))

    try:
        with smtplib.SMTP_SSL(smtp_server, smtp_port) as server:
            server.login(smtp_user, smtp_password)
            server.sendmail(from_email, to_emails, msg.as_string())
            print("[INFO] Email sent successfully!")
            logger.info("[INFO] Email sent successfully!")
            server.quit()
    except Exception as e:
        print(f"[ERROR] Failed to send email: {e}")
        logger.error(f"[ERROR] Failed to send email: {e}")


def main():
    """
    1. Reads config from environment variables.
    2. Checks both local PEM certs and remote domain certs.
    3. Builds a single email body with all warnings.
    4. Sends an email if any certificate is near expiry.
    """
    load_environment_variables()
    # --- 1. Environment Config ---
    cert_file_paths = os.getenv("CERT_FILE_PATHS", "")  # Comma separated
    domains_to_check = os.getenv("DOMAINS_TO_CHECK", "")  # Comma separated
    machine_name = os.getenv("MACHINE_NAME", "Unknown")
    server_location = os.getenv("SERVER_LOCATION", "Unknown")

    email_host = os.getenv("EMAIL_HOST", "smtp.gmail.com")
    email_port = int(os.getenv("EMAIL_PORT", "465"))
    email_user = os.getenv("EMAIL_HOST_USER", "bot@example.com")
    email_password = os.getenv("EMAIL_HOST_PASSWORD", "")
    email_recipients_str = os.getenv("EMAIL_RECIPIENTS", "")
    email_recipients = [r.strip() for r in email_recipients_str.split(",") if r.strip()]

    alert_threshold_days = int(os.getenv("ALERT_THRESHOLD_DAYS", "30"))
    always_send_email = bool(os.getenv("ALWAYS_SEND_EMAIL", "False").lower() in ("true", "yes", "1"))

    # --- 2. Prepare a single alert body ---
    alert_body = []
    send_alert = False  # We only send the email if there's at least one cert near expiry

    alert_body.append("Relatório de Expiração dos Certificados SSL:\n")

    # --- 2a. Check local certificate files ---
    if cert_file_paths.strip():
        alert_body.append("== Arquivos Locais PEM na máquina " + machine_name + " ==\n")
        
        for path in cert_file_paths.split(","):
            path = path.strip()
            if not path:
                continue

            cert = load_cert_from_file(path)
            if cert:
                expiration_datetime, days_left = check_local_certificate_expiration(cert)
                cert_name = os.path.basename(path)

                info_line = (
                    f"Certificado: {cert_name}\n"
                    f"Expira em: {expiration_datetime.strftime('%d/%m/%Y %H:%M:%S')}\n"
                    f"Dias restantes: {days_left}\n"
                )

                # Check if near expiry
                if days_left <= alert_threshold_days:
                    send_alert = True
                    info_line += ">> [ALERTA] Vence em breve!\n"

                alert_body.append(info_line + "-"*40 + "\n")
            else:
                alert_body.append(f"[ERROR] Falha ao carregar {path}\n" + "-"*40 + "\n")
                logger.error(f"[ERROR] Failed to load {path}")
    else:
        alert_body.append("Nenhum certificado local configurado.\n\n")
        logger.info("No local certificates configured.")

    # --- 2b. Check remote domain certificates ---
    if domains_to_check.strip():
        alert_body.append("== Domínios Remotos ==\n")
        for domain in domains_to_check.split(","):
            domain = domain.strip()
            if not domain:
                continue

            expiry_date = get_ssl_expiration_date(domain)
            if expiry_date:
                days_left = (expiry_date - datetime.utcnow()).days
                info_line = (
                    f"Domínio: {domain}\n"
                    f"Expira em: {expiry_date.strftime('%d/%m/%Y %H:%M:%S')}\n"
                    f"Dias restantes: {days_left}\n"
                )

                if days_left <= alert_threshold_days:
                    send_alert = True
                    info_line += ">> [ALERTA] Vence em breve!\n"
                    logger.warning(f"[ALERT] Certificate for {domain} is near expiry!")

                alert_body.append(info_line + "-"*40 + "\n")
            else:
                alert_body.append(f"[ERROR] Falha ao obter certificado de {domain}\n" + "-"*40 + "\n")
                logger.error(f"[ERROR] Falha ao obter certificado de {domain}")
    else:
        alert_body.append("Nenhum domínio configurado para verificação.\n\n")

    # --- 3. Send email if needed ---
    if send_alert:
        subject = "ALERTA: Certificados SSL prestes a expirar" + f" - {server_location}"
    else:
        subject = "Relatório de Expiração dos Certificados SSL - Sem alertas urgentes" + f" - {server_location}"

    # If you only want to send the email when there's an alert, you could wrap
    # send_email in an if-statement. If you always want to send the summary,
    # then remove the condition below.
    #
    # For example, to ALWAYS send:
    # send_email(subject, "\n".join(alert_body), email_recipients, email_user,
    #            email_host, email_port, email_user, email_password)

    if send_alert:
        send_email(subject, "\n".join(alert_body), email_recipients, email_user,
                   email_host, email_port, email_user, email_password)
    else:
        print("[INFO] No certificates are near expiry; skipping alert email.")
        logger.info("[INFO] No certificates are near expiry; skipping alert email.")
        # If you want to send the "no alerts" email, uncomment below:
        if always_send_email:
            print("[INFO] No certificates are near expiry, but always_send_email parameter is on.")
            logger.info("[INFO] No certificates are near expiry, but always_send_email parameter is on.")
            print("[INFO] Sending email with summary.")
            logger.info("[INFO] Sending email with summary.")
            send_email(subject, "\n".join(alert_body), email_recipients, email_user,
                       email_host, email_port, email_user, email_password)


if __name__ == "__main__":
    main()
