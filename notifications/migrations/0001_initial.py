# Generated by Django 5.1 on 2025-06-28 04:03

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ("accounts", "0002_initial"),
        ("content", "0001_initial"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="Event",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("title", models.CharField(max_length=255)),
                ("description", models.TextField(blank=True, null=True)),
                ("date", models.DateField()),
                (
                    "end_date",
                    models.DateField(
                        blank=True,
                        help_text="Optional: For multi-day events",
                        null=True,
                    ),
                ),
                (
                    "type",
                    models.CharField(
                        choices=[
                            ("Holiday", "Holiday"),
                            ("Exam", "Exam"),
                            ("Meeting", "Meeting"),
                            ("Activity", "Activity"),
                            ("Deadline", "Deadline"),
                            ("General", "General"),
                        ],
                        default="General",
                        max_length=10,
                    ),
                ),
                (
                    "created_by",
                    models.ForeignKey(
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="created_events",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
                (
                    "school",
                    models.ForeignKey(
                        blank=True,
                        help_text="If specific to a school",
                        null=True,
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="school_events",
                        to="accounts.school",
                    ),
                ),
                (
                    "target_class",
                    models.ForeignKey(
                        blank=True,
                        help_text="If specific to a class within the selected school",
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="class_events",
                        to="content.class",
                    ),
                ),
            ],
            options={
                "ordering": ["date"],
            },
        ),
        migrations.CreateModel(
            name="Message",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("content", models.TextField()),
                ("sent_at", models.DateTimeField(auto_now_add=True)),
                (
                    "read",
                    models.BooleanField(
                        default=False,
                        help_text="Indicates if the receiver has read the message",
                    ),
                ),
                (
                    "parent_message",
                    models.ForeignKey(
                        blank=True,
                        help_text="Reference to parent message for threaded conversations",
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="replies",
                        to="notifications.message",
                    ),
                ),
                (
                    "receiver",
                    models.ForeignKey(
                        blank=True,
                        help_text="User receiving the message, null for broadcast messages",
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="received_messages",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
                (
                    "school",
                    models.ForeignKey(
                        blank=True,
                        help_text="School context for the message, if applicable",
                        null=True,
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="school_messages",
                        to="accounts.school",
                    ),
                ),
                (
                    "sender",
                    models.ForeignKey(
                        help_text="User sending the message",
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="sent_messages",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                "ordering": ["-sent_at"],
            },
        ),
    ]
