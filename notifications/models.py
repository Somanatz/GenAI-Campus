from django.db import models # type: ignore
from django.conf import settings # type: ignore
from accounts.models import School
from content.models import Class

class Event(models.Model):
    EVENT_TYPES = [
        ('Holiday', 'Holiday'),
        ('Exam', 'Exam'),
        ('Meeting', 'Meeting'),
        ('Activity', 'Activity'),
        ('Deadline', 'Deadline'),
        ('General', 'General'),
    ]

    title = models.CharField(max_length=255)
    description = models.TextField(blank=True, null=True)
    date = models.DateField()
    end_date = models.DateField(null=True, blank=True, help_text="Optional: For multi-day events")
    type = models.CharField(max_length=10, choices=EVENT_TYPES, default='General')
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, related_name='created_events')
    school = models.ForeignKey(School, on_delete=models.CASCADE, null=True, blank=True, related_name='school_events', help_text="If specific to a school")
    target_class = models.ForeignKey(Class, on_delete=models.SET_NULL, null=True, blank=True, related_name='class_events', help_text="If specific to a class within the selected school")

    class Meta:
        ordering = ['date']

    def __str__(self):
        return f"{self.title} ({self.type}) on {self.date}"

    def clean(self):
        from django.core.exceptions import ValidationError # type: ignore
        if self.target_class and self.school and self.target_class.school != self.school:
            raise ValidationError({'target_class': 'Target class must belong to the selected school.'})

class Message(models.Model):
    sender = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, related_name='sent_messages', help_text="User sending the message")
    receiver = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name='received_messages', help_text="User receiving the message, null for broadcast messages")
    school = models.ForeignKey(School, on_delete=models.CASCADE, null=True, blank=True, related_name='school_messages', help_text="School context for the message, if applicable")
    content = models.TextField()
    sent_at = models.DateTimeField(auto_now_add=True)
    read = models.BooleanField(default=False, help_text="Indicates if the receiver has read the message")
    parent_message = models.ForeignKey('self', on_delete=models.SET_NULL, null=True, blank=True, related_name='replies', help_text="Reference to parent message for threaded conversations")

    class Meta:
        ordering = ['-sent_at']

    def __str__(self):
        receiver_str = self.receiver.username if self.receiver else 'Broadcast'
        return f"Message from {self.sender.username} to {receiver_str} ({self.sent_at.strftime('%Y-%m-%d %H:%M')})"