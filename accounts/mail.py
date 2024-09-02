from django.urls import reverse
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.core.mail import send_mail
from django.conf import settings

from .tokens import account_activation_token


def send_activation_mail(user, request):
    uid = urlsafe_base64_encode(force_bytes(user.pk))
    token = account_activation_token.make_token(user)
    activation_link = reverse("activate", kwargs={"uidb64": uid, "token": token})
    activation_url = f"{request.scheme}://{request.get_host()}{activation_link}"

    subject = "Confirm your Account"
    message = (
        f"Hi {user.username},\n\n"
        f"Please click the link below to confirm your account:\n{activation_url}"
    )
    email_from = settings.EMAIL_HOST_USER
    recipient_list = [user.email]

    send_mail(subject, message, email_from, recipient_list)
