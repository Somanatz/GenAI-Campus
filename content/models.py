from django.db import models # type: ignore
from django.db.models import JSONField # type: ignore
from django.conf import settings # type: ignore
from accounts.models import School

class Class(models.Model):
    school = models.ForeignKey(School, related_name='classes', on_delete=models.CASCADE, null=True, blank=True)
    name = models.CharField(max_length=100)
    description = models.TextField(blank=True, null=True)

    class Meta:
        ordering = ['name']

    def __str__(self):
        return f"{self.name} ({self.school.name if self.school else 'No School'})"

class Subject(models.Model):
    class_obj = models.ForeignKey(Class, related_name='subjects', on_delete=models.CASCADE)
    name = models.CharField(max_length=100)
    description = models.TextField(blank=True, null=True)

    class Meta:
        ordering = ['name']

    def __str__(self):
        school_name_part = ""
        if self.class_obj and self.class_obj.school:
            school_name_part = f" - {self.class_obj.school.name}"
        return f"{self.name} ({self.class_obj.name}{school_name_part})"

class Chapter(models.Model):
    subject = models.ForeignKey(Subject, related_name='chapters', on_delete=models.CASCADE)
    title = models.CharField(max_length=200)
    description = models.TextField(blank=True, null=True)
    chapter_order = models.PositiveIntegerField(default=0)

    class Meta:
        ordering = ['chapter_order']

    def __str__(self):
        return f"{self.title} ({self.subject.name})"

class Section(models.Model):
    chapter = models.ForeignKey(Chapter, related_name='sections', on_delete=models.CASCADE)
    title = models.CharField(max_length=200)
    content = models.TextField()
    video_url = models.URLField(blank=True, null=True)
    audio_url = models.URLField(blank=True, null=True)
    image_url = models.URLField(blank=True, null=True)
    simplified_content = models.TextField(blank=True, null=True)
    section_order = models.PositiveIntegerField(default=0)
    requires_previous_quiz = models.BooleanField(default=False, help_text="If true, student must pass the quiz of the previous section to access this one.")

    class Meta:
        ordering = ['section_order']

    def __str__(self):
        return f"{self.title} ({self.chapter.title})"

class Quiz(models.Model):
    section = models.OneToOneField(Section, related_name='quiz', on_delete=models.CASCADE)
    title = models.CharField(max_length=200)
    description = models.TextField(blank=True, null=True)
    pass_mark_percentage = models.FloatField(default=70.0, help_text="Percentage required to pass this quiz.")

    class Meta:
        ordering = ['title']

    def __str__(self):
        return f"Quiz for {self.section.title}"

class Question(models.Model):
    quiz = models.ForeignKey(Quiz, related_name='questions', on_delete=models.CASCADE)
    text = models.TextField()

    class Meta:
        ordering = ['id']

    def __str__(self):
        return self.text[:50] + '...'

class Choice(models.Model):
    question = models.ForeignKey(Question, related_name='choices', on_delete=models.CASCADE)
    text = models.CharField(max_length=200)
    is_correct = models.BooleanField(default=False)

    class Meta:
        ordering = ['id']

    def __str__(self):
        return self.text

class UserQuizAttempt(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='quiz_attempts')
    quiz = models.ForeignKey(Quiz, on_delete=models.CASCADE, related_name='user_attempts')
    score = models.FloatField(default=0.0, help_text="Score as a percentage (0-100).")
    answers = JSONField(blank=True, null=True, help_text="Stores the user's answers for each question.")
    completed_at = models.DateTimeField(auto_now_add=True)
    passed = models.BooleanField(default=False)

    class Meta:
        ordering = ['-completed_at']

    def __str__(self):
        return f"{self.user.username}'s attempt on {self.quiz.title}"

class UserSectionProgress(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='section_progress')
    section = models.ForeignKey(Section, on_delete=models.CASCADE, related_name='user_progress')
    completed = models.BooleanField(default=False)
    progress_data = JSONField(blank=True, null=True, help_text="Stores specific progress within a section.")
    last_updated = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ('user', 'section')
        ordering = ['user', 'section']

    def __str__(self):
        return f"{self.user.username}'s progress in {self.section.title}"

class ProcessedNote(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='processed_notes')
    section = models.ForeignKey(Section, on_delete=models.SET_NULL, related_name='processed_notes', null=True, blank=True)
    original_notes = models.TextField()
    processed_output = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"Note from {self.user.username} ({self.created_at.strftime('%Y-%m-%d %H:%M')})"

class Book(models.Model):
    class_obj = models.ForeignKey(Class, related_name='books', on_delete=models.CASCADE, null=True, blank=True)
    subject = models.ForeignKey(Subject, related_name='books', on_delete=models.CASCADE, null=True, blank=True)
    title = models.CharField(max_length=255)
    author = models.CharField(max_length=255, blank=True, null=True)
    file = models.FileField(upload_to='books/')

    class Meta:
        ordering = ['title']

    def __str__(self):
        return self.title

class Reward(models.Model):
    title = models.CharField(max_length=255)
    description = models.TextField()
    icon_name = models.CharField(max_length=50, help_text="Lucide icon name (e.g., Award, Star, Trophy)")

    class Meta:
        ordering = ['title']

    def __str__(self):
        return self.title

class UserReward(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='achieved_rewards')
    reward = models.ForeignKey(Reward, on_delete=models.CASCADE, related_name='user_achievements')
    achieved_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('user', 'reward')
        ordering = ['-achieved_at']

    def __str__(self):
        return f"{self.user.username} achieved {self.reward.title}"