from django.urls import path
from . import views

app_name = 'crypto_demo'

urlpatterns = [
    path('', views.index, name='index'),
    path('encrypt/', views.encrypt_document, name='encrypt_document'),
    path('decrypt/', views.decrypt_document, name='decrypt_document'),
    path('logout/', views.logout_crypto, name='logout_crypto'),
    path('under-development/', views.under_development, name='under_development'),
    
    # Game paths (redirected to under development)
    path('login/', views.under_development, name='login'),
    path('lobby/', views.under_development, name='lobby'),
    path('game/', views.under_development, name='game_interface'),
]