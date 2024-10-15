from django.urls import path
from eapp import views


urlpatterns = [
    path('', views.index, name='index')
]
