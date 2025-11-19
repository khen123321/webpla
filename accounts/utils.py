from django.core.mail import send_mail
from django.utils import timezone
from datetime import timedelta
import random
from .models import EmailOTP
from django.conf import settings

def generate_and_send_otp(user):
    # Generate a random 6-digit OTP
    otp_code = str(random.randint(100000, 999999))

    # Set expiry time
    expires_at = timezone.now() + timedelta(seconds=getattr(settings, 'OTP_VALIDITY', 600))

    # Save OTP to database
    EmailOTP.objects.create(user=user, otp_code=otp_code, expires_at=expires_at)

    # Send OTP email
    subject = getattr(settings, 'OTP_EMAIL_SUBJECT', 'Your OTP Code')
    message_template = getattr(settings, 'OTP_EMAIL_BODY_TEMPLATE', 'Your OTP code is: {otp_code}')
    message = message_template.format(otp_code=otp_code)

    send_mail(
        subject,
        message,
        settings.EMAIL_HOST_USER,
        [user.email],
        fail_silently=False,
    )

    return otp_code
