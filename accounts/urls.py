from django.urls import path
from . import views

urlpatterns = [
    path("users/", views.user_list, name="user_list"),
    path("users/<int:pk>", views.user_detail, name="user_detail"),
    path("register/", views.user_register, name="user_register"),
    # path("login/", views.user_login, name="user_login"),
]
