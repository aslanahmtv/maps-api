from django.urls import path

from map import views
from map.views import index

urlpatterns = [
    path("", views.index, name="index"),
    path("newUser", views.UserRegistrationAPIView.as_view()),
    path("login", views.UserLoginAPIView.as_view()),
    path("logout", views.UserLogoutAPIView.as_view()),
    path("get_routes", views.GetRoutesAPIVIew.as_view()),
    path("set_routes", views.SetRoutesAPIView.as_view())
]
