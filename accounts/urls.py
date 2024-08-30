from django.urls import path
from . import views

urlpatterns = [
    path("users/", views.user_list, name="user_list"),
    path("users/<int:pk>/", views.user_detail, name="user_detail"),
    path("user/profile/", views.user_profile, name="user_profile"),
    path("user/register/", views.user_register, name="user_register"),
    path("activate/<uidb64>/<token>/", views.activate, name="activate"),
    path("user/login/", views.user_login, name="user_login"),
    path("user/logout/", views.user_logout, name="user_logout"),
    path(
        "user/profile/change-email/", views.user_change_email, name="user_change_email"
    ),
    # path("change-password/", views.change_password, name="change_password"),
    # path("find-password/", views.find_password, name="find_password"),
]
