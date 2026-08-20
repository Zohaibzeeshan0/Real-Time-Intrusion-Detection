from django.contrib import admin
from django.urls import path
from . import views

urlpatterns = [
    path('', views.home, name='home'),
    path('login/', views.Login, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('signup/', views.SignUp, name='sign-up'),
    path('user-dashboard/', views.user_dashboard, name='user_dashboard'),
    # Main dashboard and traffic processing
    path('dashboard/', views.dashboard, name='dashboard'),
    #path('generate_and_classify/', views.generate_and_classify, name='generate_and_classify'),
    path('start_capture/', views.capture_live_traffic, name='start_capture'),
    path('start_monitoring/', views.start_traffic_monitoring, name='start_monitoring'),
    path('stop_monitoring/', views.stop_traffic_monitoring, name='stop_monitoring'),
    path('latest_traffic/', views.get_latest_traffic, name='get_latest_traffic'),
    path('anomaly_stats/', views.get_anomaly_stats, name='get_anomaly_stats'),
    path('test_email/', views.test_email_notification, name='test_email'),
    # Static pages
    path('about-us/', views.AboutUs, name='about-us'),
    path('contact-us/', views.ContactUs, name='contact-us'),
    path('privacy-policy/', views.PrivacyPolicy, name='privacy-policy'),
    path('terms-of-service/', views.TermsOfService, name='terms-of-service'),
]