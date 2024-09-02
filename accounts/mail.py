from django.urls import reverse
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.core.mail import send_mail
from django.conf import settings


class EmailService:
    def __init__(self, user, request):
        self.user = user
        self.request = request
        self.email_from = settings.EMAIL_HOST_USER
        self.uid = urlsafe_base64_encode(force_bytes(user.pk))
        self.recipient_list = [user.email]

    def get_activation_token(self, token_generator):
        return token_generator.make_token(self.user)

    def get_url(self, view_name, token):
        link = reverse(view_name, kwargs={"uidb64": self.uid, "token": token})
        return f"{self.request.scheme}://{self.request.get_host()}{link}"

    def send_email(self, subject, message):
        send_mail(subject, message, self.email_from, self.recipient_list)

    def send_activation_mail(self, token_generator):
        token = self.get_activation_token(token_generator)
        activation_url = self.get_url("activate_user", token)

        subject = "Confirm your Account"
        message = (
            f"Hi {self.user.username},\n\n"
            f"Please click the link below to confirm your account:\n{activation_url}"
        )

        self.send_email(subject, message)

    def send_change_email_mail(self, token_generator):
        token = self.get_activation_token(token_generator)
        verification_url = self.get_url("verify_email", token)

        subject = "Confirm Your Email Change"
        message = (
            f"Hi {self.user.username},\n\n"
            f"We received a request to change the email address associated with your account.\n\n"
            f"To confirm this change, please click the link below:\n{verification_url}"
        )

        self.send_email(subject, message)
