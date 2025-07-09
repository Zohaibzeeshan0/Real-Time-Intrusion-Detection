from django.contrib import admin
from django.urls import path
from . import views

urlpatterns = [
    path('', views.home, name='home'),
    path('login/', views.Login, name='login'),
    path('signup/', views.SignUp, name='sign-up'),
    path('user-dashboard/', views.user_dashboard, name='user_dashboard'),
    # Main dashboard and traffic processing
    path('dashboard/', views.dashboard, name='dashboard'),
    #path('generate_and_classify/', views.generate_and_classify, name='generate_and_classify'),
    path('start_capture/', views.capture_live_traffic, name='start_capture'),
    path('latest_traffic/', views.get_latest_traffic, name='get_latest_traffic'),
    # Static pages
    path('about-us/', views.AboutUs, name='about-us'),
    path('contact-us/', views.ContactUs, name='contact-us'),
    path('privacy-policy/', views.PrivacyPolicy, name='privacy-policy'),
    path('terms-of-service/', views.TermsOfService, name='terms-of-service'),
]