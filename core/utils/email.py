# utils/email.py
import os
from resend import Resend
from threading import Thread

resend = Resend(api_key=os.getenv("RESEND_API_KEY"))  # put your Resend API key in Railway variables

def send_otp_email(to_email, otp_code):
    subject = "Your OTP Code"
    body = f"Your OTP is {otp_code}. It expires in 10 minutes."

    # Use a thread so sending email does not block your Django request
    def send_email():
        try:
            resend.emails.send(
                from_="onboarding@resend.dev",  # or your verified Resend sender
                to=[to_email],
                subject=subject,
                html=f"<p>{body}</p>"
            )
            print(f"📨 OTP email sent to {to_email}")
        except Exception as e:
            print(f"❌ Failed to send OTP email to {to_email}: {e}")

    Thread(target=send_email).start()
