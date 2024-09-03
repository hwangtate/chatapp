from django.core.mail import send_mail
from django.conf import settings
from django.core import signing
from django.core.signing import TimestampSigner


class EmailService:
    def __init__(self, user, request):
        self.user = user
        self.request = request
        self.email_from = settings.EMAIL_HOST_USER
        self.recipient_list = [user.email]

    def signer(self):
        signer = TimestampSigner()
        signed_user_email = signer.sign(self.user.email)
        signer_dump = signing.dumps(signed_user_email)
        return signer_dump

    def get_url(self, uri):
        link = f"/{uri}/?code={self.signer()}"
        return f"{self.request.scheme}://{self.request.get_host()}{link}"

    def send_email(self, subject, message):
        send_mail(subject, message, self.email_from, self.recipient_list)

    def send_activation_mail(self):
        uri = "active"
        activation_url = self.get_url(uri)

        subject = "Confirm your Account"
        message = (
            f"Hi {self.user.username},\n\n"
            f"Please click the link below to confirm your account:\n{activation_url}"
        )

        self.send_email(subject, message)

    def send_change_email_mail(self):
        uri = "verify"
        verification_url = self.get_url(uri)

        subject = "Confirm Your Email Change"
        message = (
            f"Hi {self.user.username},\n\n"
            f"We received a request to change the email address associated with your account.\n\n"
            f"To confirm this change, please click the link below:\n{verification_url}"
        )

        self.send_email(subject, message)
