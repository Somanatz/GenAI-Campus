from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.utils import timezone

class CustomUserManager(BaseUserManager):
    def create_user(self, username, email, password=None, **extra_fields):
        if not email:
            raise ValueError('The Email field must be set')
        email = self.normalize_email(email)
        user = self.model(username=username, email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, username, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('role', 'Admin')
        extra_fields.setdefault('is_school_admin', True)
        return self.create_user(username, email, password, **extra_fields)

class CustomUser(AbstractBaseUser, PermissionsMixin):
    ROLE_CHOICES = (
        ('Student', 'Student'),
        ('Teacher', 'Teacher'),
        ('Parent', 'Parent'),
        ('Admin', 'Admin'),
    )

    username = models.CharField(max_length=150, unique=True)
    email = models.EmailField(unique=True)
    role = models.CharField(max_length=20, choices=ROLE_CHOICES)
    is_school_admin = models.BooleanField(default=False)
    school = models.ForeignKey('School', on_delete=models.SET_NULL, null=True, blank=True)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    date_joined = models.DateTimeField(default=timezone.now)
    face_encoding = models.TextField(blank=True, null=True)  # Stores face encoding as JSON

    objects = CustomUserManager()

    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = ['email', 'role']

    class Meta:
        verbose_name = 'User'
        verbose_name_plural = 'Users'

    def __str__(self):
        return self.username

class School(models.Model):
    name = models.CharField(max_length=255)
    school_id_code = models.CharField(max_length=50, unique=True)
    license_number = models.CharField(max_length=100, unique=True)
    official_email = models.EmailField(unique=True)
    phone_number = models.CharField(max_length=20, blank=True)
    address = models.TextField(blank=True)
    principal_full_name = models.CharField(max_length=255, blank=True)
    principal_contact_number = models.CharField(max_length=20, blank=True)
    principal_email = models.EmailField(blank=True)
    admin_user = models.OneToOneField(CustomUser, on_delete=models.CASCADE, related_name='administered_school')

    def __str__(self):
        return self.name

class StudentProfile(models.Model):
    user = models.OneToOneField(CustomUser, on_delete=models.CASCADE, related_name='student_profile')
    school = models.ForeignKey('School', on_delete=models.SET_NULL, null=True, blank=True)
    enrolled_class = models.ForeignKey('content.Class', on_delete=models.SET_NULL, null=True, blank=True)
    full_name = models.CharField(max_length=255, blank=True)
    preferred_language = models.CharField(max_length=50, blank=True)
    father_name = models.CharField(max_length=255, blank=True)
    mother_name = models.CharField(max_length=255, blank=True)
    place_of_birth = models.CharField(max_length=255, blank=True)
    date_of_birth = models.DateField(null=True, blank=True)
    blood_group = models.CharField(max_length=10, blank=True)
    needs_assistant_teacher = models.BooleanField(default=False)
    admission_number = models.CharField(max_length=50, unique=True, blank=True, null=True)
    parent_email_for_linking = models.EmailField(blank=True)
    parent_mobile_for_linking = models.CharField(max_length=20, blank=True)
    parent_occupation = models.CharField(max_length=255, blank=True)
    hobbies = models.TextField(blank=True)
    favorite_sports = models.CharField(max_length=255, blank=True)
    interested_in_gardening_farming = models.BooleanField(default=False)
    nickname = models.CharField(max_length=50, blank=True)
    profile_picture = models.ImageField(upload_to='profile_pics/students/', null=True, blank=True)
    profile_completed = models.BooleanField(default=False)

    def __str__(self):
        return f"{self.user.username}'s Student Profile"

class TeacherProfile(models.Model):
    user = models.OneToOneField(CustomUser, on_delete=models.CASCADE, related_name='teacher_profile')
    school = models.ForeignKey('School', on_delete=models.SET_NULL, null=True, blank=True)
    assigned_classes = models.ManyToManyField('content.Class', blank=True)
    subject_expertise = models.ManyToManyField('content.Subject', blank=True)
    full_name = models.CharField(max_length=255, blank=True)
    interested_in_tuition = models.BooleanField(default=False)
    mobile_number = models.CharField(max_length=20, blank=True)
    address = models.TextField(blank=True)
    profile_picture = models.ImageField(upload_to='profile_pics/teachers/', null=True, blank=True)
    profile_completed = models.BooleanField(default=False)

    def __str__(self):
        return f"{self.user.username}'s Teacher Profile"

class ParentProfile(models.Model):
    user = models.OneToOneField(CustomUser, on_delete=models.CASCADE, related_name='parent_profile')
    full_name = models.CharField(max_length=255, blank=True)
    mobile_number = models.CharField(max_length=20, blank=True)
    address = models.TextField(blank=True)
    profile_picture = models.ImageField(upload_to='profile_pics/parents/', null=True, blank=True)
    profile_completed = models.BooleanField(default=False)

    def __str__(self):
        return f"{self.user.username}'s Parent Profile"

class ParentStudentLink(models.Model):
    parent = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='parent_links')
    student = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='student_links')

    class Meta:
        unique_together = ('parent', 'student')

    def __str__(self):
        return f"{self.parent.username} -> {self.student.username}"