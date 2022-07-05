"""dsktool URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, re_path
from dsktool import views
from dsktool import rfc
from dsktool.views import exportcsv

# from django.conf.urls import url



urlpatterns = [
    path('admin/', admin.site.urls),
    path('', views.index, name='index'),
    path('courses', views.courses, name='courses'),
    path('enrollments', views.enrollments, name='enrollments'),
    path('get_3LO_token', views.get_3LO_token, name='get_3LO_token'),
    path('get_API_token', views.get_API_token, name='get_API_token'),
    path('guestusernotallowed', views.guestusernotallowed, name='guestusernotallowed'),
    path('isup', views.isup, name='isup'),
    path('learnlogout', views.learnlogout, name='learnlogout'),
    path('notauthorized', views.notauthorized, name='notauthorized'),
    path('users', views.users, name='users'),
    path('whoami', views.whoami, name='whoami'),
    path('rfcreport', views.rfcreport, name='rfcreport'),
    path('exportcsvzip/', views.exportcsvzip, name="exportcsvzip"),

    path('exportcsv/', views.exportcsv, name='exportcsv'),
    path('exportmessagescsv/', views.exportmessagescsv, name='exportmessagescsv'),
    path('exportlogscsv/', views.exportlogscsv, name='exportlogscsv'),
    re_path(r'^ajax/purgereportdata/$', views.purgeData, name='purgereportdata'),
    
    re_path(r'^ajax/getDataSourceKeys/$', views.getDataSourceKeys, name='getDataSourceKeys'),
    re_path(r'^ajax/validate_userIdentifier/$', views.validate_userIdentifier, name='validate_userIdentifier'),
    re_path(r'^ajax/validate_courseIdentifier/$', views.validate_courseIdentifier, name='validate_courseIdentifier'),
    re_path(r'^ajax/getCourseMembership/$', views.getCourseMembership, name='getCourseMembership'),
    re_path(r'^ajax/updateCourseMembership/$', views.updateCourseMembership, name='updateCourseMembership'),
    re_path(r'^ajax/getCourseMemberships/$', views.getCourseMemberships, name='getCourseMemberships'),
    re_path(r'^ajax/updateCourseMemberships/$', views.updateCourseMemberships, name='updateCourseMemberships'),
    re_path(r'^ajax/getUserMemberships/$', views.getUserMemberships, name='getUserMemberships'),
    re_path(r'^ajax/updateUserMemberships/$', views.updateUserMemberships, name='updateUserMemberships'),
    re_path(r'^ajax/getUsers/$', views.getUsers, name='getUsers'),
    re_path(r'^ajax/updateUsers/$', views.updateUsers, name='updateUsers'),
    re_path(r'^ajax/getUser/$', views.getUser, name='getUser'),
    re_path(r'^ajax/updateUser/$', views.updateUser, name='updateUser'),
    re_path(r'^ajax/getCourse/$', views.getCourse, name='getCourse'),
    re_path(r'^ajax/updateCourse/$', views.updateCourse, name='updateCourse'),
    re_path(r'^ajax/getCourses/$', views.getCourses, name='getCourses'),
    re_path(r'^ajax/updateCourses/$', views.updateCourses, name='updateCourses'),
    re_path(r'^ajax/getMembershipsByDSK/$', views.getMembershipsByDSK, name='getMembershipsByDSK'),
]

handler500 = views.error_500

from django.conf import settings
from django.conf.urls.static import static

urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)