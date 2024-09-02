from django.urls import reverse
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.core.mail import send_mail
from django.conf import settings

from .tokens import (
    account_activation_token,
    account_verification_token,
    account_reset_password_token,
)


def send_activation_mail(user, request):
    uid = urlsafe_base64_encode(force_bytes(user.pk))
    token = account_activation_token.make_token(user)
    activation_link = reverse("activate_user", kwargs={"uidb64": uid, "token": token})
    activation_url = f"{request.scheme}://{request.get_host()}{activation_link}"

    subject = "Confirm your Account"
    message = (
        f"Hi {user.username},\n\n"
        f"Please click the link below to confirm your account:\n{activation_url}"
    )
    email_from = settings.EMAIL_HOST_USER
    recipient_list = [user.email]

    send_mail(subject, message, email_from, recipient_list)


def send_change_email_mail(user, request):
    uid = urlsafe_base64_encode(force_bytes(user.pk))
    token = account_verification_token.make_token(user)
    verification_link = reverse("verify_email", kwargs={"uidb64": uid, "token": token})
    verification_url = f"{request.scheme}://{request.get_host()}{verification_link}"

    subject = "Confirm Your Email Change"
    message = (
        f"Hi {user.username},\n\n"
        f"We received a request to change the email address associated with your account.\n\n"
        f"To confirm this change, please click the link below:\n{verification_url}"
    )
    email_from = settings.EMAIL_HOST_USER
    recipient_list = [user.email]

    send_mail(subject, message, email_from, recipient_list)


def send_reset_password_mail(user, request):
    uid = urlsafe_base64_encode(force_bytes(user.pk))
    token = account_reset_password_token.make_token(user)
    reset_link = reverse("reset_password", kwargs={"uidb64": uid, "token": token})
    reset_url = f"{request.scheme}://{request.get_host()}{reset_link}"

    subject = "Reset Your Password"
    message = (
        f"Hi {user.username},\n\n"
        f"We received a request to reset the password for your account.\n\n"
        f"To reset your password, please click the link below:\n{reset_url}\n\n"
        f"If you did not request this password reset, please ignore this email.\n\n"
        f"Thank you,\nThe Team"
    )
    email_from = settings.EMAIL_HOST_USER
    recipient_list = [user.email]

    send_mail(subject, message, email_from, recipient_list)
