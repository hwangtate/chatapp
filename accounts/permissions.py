from rest_framework.permissions import BasePermission


# class IsAdminUser(BasePermission):
#     def has_permission(self, request, view):
#         return request.user and request.user.is_superuser


class IsEmailVerified(BasePermission):
    message = (
        "Your email is not verified. Please verify your email to access this resource."
    )

    def has_permission(self, request, view):
        return request.user and request.user.email_is_verified
