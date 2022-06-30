from django.db import models

class Messages(models.Model):
    id = models.AutoField(primary_key=True)
    user_id = models.CharField(max_length=255)
    change_type = models.CharField(max_length=255)
    change_comment = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True, blank=True)

class Logs(models.Model):
    id = models.AutoField(primary_key=True)
    message = models.ForeignKey('Messages', on_delete=models.CASCADE, related_name='logs')
    user_id = models.CharField(max_length=255, null=True)
    external_id = models.CharField(max_length=255)
    course_id = models.CharField(max_length=255, null=True)
    course_role = models.CharField(max_length=255, null=True)
    availability_status = models.CharField(max_length=255, null=True)
    datasource_id = models.CharField(max_length=255, null=True)
    state = models.CharField(max_length=255, null=True)
    created_at = models.DateTimeField(auto_now_add=True, blank=True)