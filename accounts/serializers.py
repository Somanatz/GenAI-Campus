from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from .models import CustomUser, ParentStudentLink, School, StudentProfile, TeacherProfile, ParentProfile
from content.models import Class as ContentClass, Subject as ContentSubject
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError as DjangoValidationError
from django.db import transaction
import face_recognition
import json
import numpy as np
import logging

logger = logging.getLogger(__name__)

class SchoolSerializer(serializers.ModelSerializer):
    admin_username = serializers.CharField(write_only=True, required=True)
    admin_email = serializers.EmailField(write_only=True, required=True)
    admin_password = serializers.CharField(write_only=True, required=True, style={'input_type': 'password'})

    class Meta:
        model = School
        fields = [
            'id', 'name', 'school_id_code', 'license_number', 'official_email',
            'phone_number', 'address', 'principal_full_name', 'principal_contact_number',
            'principal_email', 'admin_user',
            'admin_username', 'admin_email', 'admin_password'
        ]
        read_only_fields = ['admin_user']
        extra_kwargs = {
            'school_id_code': {'validators': []},
            'official_email': {'validators': []},
        }

    def validate_admin_password(self, value):
        try:
            validate_password(value)
        except DjangoValidationError as e:
            raise serializers.ValidationError(list(e.messages))
        return value

    def create(self, validated_data):
        admin_username = validated_data.pop('admin_username')
        admin_email = validated_data.pop('admin_email')
        admin_password = validated_data.pop('admin_password')

        if CustomUser.objects.filter(username=admin_username).exists():
            raise serializers.ValidationError({"admin_username": "An admin user with this username already exists."})
        if CustomUser.objects.filter(email=admin_email).exists():
            raise serializers.ValidationError({"admin_email": "An admin user with this email already exists."})

        try:
            admin_user = CustomUser.objects.create_user(
                username=admin_username,
                email=admin_email,
                password=admin_password,
                role='Admin',
                is_school_admin=True,
                is_staff=False,
                is_active=True
            )
        except Exception as e:
            logger.error(f"Failed to create admin user: {str(e)}")
            raise serializers.ValidationError({"admin_user_creation": str(e)})

        school = School.objects.create(admin_user=admin_user, **validated_data)
        admin_user.school = school
        admin_user.save()
        return school

class StudentProfileSerializer(serializers.ModelSerializer):
    enrolled_class_name = serializers.CharField(source='enrolled_class.name', read_only=True, allow_null=True)
    school_name = serializers.CharField(source='school.name', read_only=True, allow_null=True)
    profile_picture_url = serializers.SerializerMethodField()

    class Meta:
        model = StudentProfile
        fields = '__all__'
        read_only_fields = ['user', 'profile_picture_url', 'school_name', 'enrolled_class_name']
        extra_kwargs = {
            'school': {'required': False, 'allow_null': True},
            'enrolled_class': {'required': False, 'allow_null': True},
            'profile_picture': {'write_only': True, 'required': False, 'allow_null': True},
        }

    def get_profile_picture_url(self, obj):
        request = self.context.get('request')
        if obj.profile_picture and hasattr(obj.profile_picture, 'url'):
            if request is not None:
                return request.build_absolute_uri(obj.profile_picture.url)
            return obj.profile_picture.url
        return None

class TeacherProfileSerializer(serializers.ModelSerializer):
    school_name = serializers.CharField(source='school.name', read_only=True, allow_null=True)
    assigned_classes_details = serializers.SerializerMethodField()
    subject_expertise_details = serializers.SerializerMethodField()
    profile_picture_url = serializers.SerializerMethodField()

    class Meta:
        model = TeacherProfile
        fields = '__all__'
        read_only_fields = ['user', 'profile_picture_url', 'school_name', 'assigned_classes_details', 'subject_expertise_details']
        extra_kwargs = {
            'school': {'required': False, 'allow_null': True},
            'assigned_classes': {'required': False},
            'subject_expertise': {'required': False},
            'profile_picture': {'write_only': True, 'required': False, 'allow_null': True},
        }

    def get_assigned_classes_details(self, obj):
        return [{'id': cls.id, 'name': cls.name} for cls in obj.assigned_classes.all()]

    def get_subject_expertise_details(self, obj):
        return [{'id': sub.id, 'name': sub.name} for sub in obj.subject_expertise.all()]

    def get_profile_picture_url(self, obj):
        request = self.context.get('request')
        if obj.profile_picture and hasattr(obj.profile_picture, 'url'):
            if request is not None:
                return request.build_absolute_uri(obj.profile_picture.url)
            return obj.profile_picture.url
        return None

class ParentProfileSerializer(serializers.ModelSerializer):
    profile_picture_url = serializers.SerializerMethodField()

    class Meta:
        model = ParentProfile
        fields = '__all__'
        read_only_fields = ['user', 'profile_picture_url']
        extra_kwargs = {
            'profile_picture': {'write_only': True, 'required': False, 'allow_null': True},
        }

    def get_profile_picture_url(self, obj):
        request = self.context.get('request')
        if obj.profile_picture and hasattr(obj.profile_picture, 'url'):
            if request is not None:
                return request.build_absolute_uri(obj.profile_picture.url)
            return obj.profile_picture.url
        return None

class CustomUserSerializer(serializers.ModelSerializer):
    student_profile = StudentProfileSerializer(read_only=True)
    teacher_profile = TeacherProfileSerializer(read_only=True)
    parent_profile = ParentProfileSerializer(read_only=True)
    school_name = serializers.CharField(source='school.name', read_only=True, allow_null=True)
    school_id = serializers.PrimaryKeyRelatedField(queryset=School.objects.all(), source='school', write_only=True, allow_null=True, required=False)
    profile_completed = serializers.SerializerMethodField()
    administered_school = SchoolSerializer(read_only=True, allow_null=True)

    class Meta:
        model = CustomUser
        fields = [
            'id', 'username', 'email', 'role', 'password', 'is_school_admin',
            'school_id', 'school_name', 'administered_school',
            'student_profile', 'teacher_profile', 'parent_profile',
            'profile_completed',
        ]
        extra_kwargs = {
            'password': {'write_only': True, 'required': False},
        }

    def get_profile_completed(self, obj):
        if obj.role == 'Student' and hasattr(obj, 'student_profile') and obj.student_profile:
            return obj.student_profile.profile_completed
        elif obj.role == 'Teacher' and hasattr(obj, 'teacher_profile') and obj.teacher_profile:
            return obj.teacher_profile.profile_completed
        elif obj.role == 'Parent' and hasattr(obj, 'parent_profile') and obj.parent_profile:
            return obj.parent_profile.profile_completed
        return False

    def create(self, validated_data):
        user = CustomUser.objects.create_user(**validated_data)
        return user

    def update(self, instance, validated_data):
        password = validated_data.pop('password', None)
        if password:
            instance.set_password(password)
        school = validated_data.pop('school', None)
        if school:
            instance.school = school
        return super().update(instance, validated_data)

class UserSignupSerializer(serializers.ModelSerializer):
    face_image = serializers.ImageField(write_only=True, required=False)

    class Meta:
        model = CustomUser
        fields = ['id', 'username', 'email', 'role', 'password', 'face_image']
        extra_kwargs = {
            'password': {'write_only': True, 'required': True},
            'role': {'required': True}
        }

    def validate_role(self, value):
        valid_roles = [choice[0] for choice in CustomUser.ROLE_CHOICES if choice[0] != 'Admin']
        if value not in valid_roles:
            raise serializers.ValidationError(f"Invalid role. Choose from {', '.join(valid_roles)}.")
        return value

    def validate_face_image(self, value):
        if not value:
            return value
        try:
            if not value.content_type.startswith('image/'):
                raise serializers.ValidationError("Invalid image format.")
            if value.size > 5 * 1024 * 1024:  # 5MB limit
                raise serializers.ValidationError("Image size exceeds 5MB.")
        except Exception as e:
            logger.error(f"Face image validation failed: {str(e)}")
            raise serializers.ValidationError(f"Invalid image: {str(e)}")
        return value

    @transaction.atomic
    def create(self, validated_data):
        face_image = validated_data.pop('face_image', None)
        user = CustomUser.objects.create_user(
            username=validated_data['username'],
            email=validated_data['email'],
            password=validated_data['password'],
            role=validated_data['role'],
            is_active=True
        )
        try:
            if face_image:
                image = face_recognition.load_image_file(face_image)
                encodings = face_recognition.face_encodings(image)
                if encodings:
                    user.face_encoding = json.dumps(encodings[0].tolist())
                    user.save()
                else:
                    logger.warning(f"No face detected for user {user.username}")
                    # Allow registration to proceed without face encoding
            if user.role == 'Student':
                StudentProfile.objects.create(user=user, profile_completed=False)
            elif user.role == 'Teacher':
                TeacherProfile.objects.create(user=user, profile_completed=False)
            elif user.role == 'Parent':
                ParentProfile.objects.create(user=user, profile_completed=False)
            return user
        except Exception as e:
            logger.error(f"Failed to create user {user.username}: {str(e)}")
            user.delete()
            raise serializers.ValidationError(f"User creation failed: {str(e)}")

class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)
        token['role'] = user.role
        token['is_school_admin'] = user.is_school_admin
        return token

    def validate(self, attrs):
        try:
            data = super().validate(attrs)
            data.update({
                'user_id': self.user.id,
                'username': self.user.username,
                'email': self.user.email,
                'role': self.user.role,
            })
            return data
        except Exception as e:
            logger.error(f"Token validation failed: {str(e)}")
            raise serializers.ValidationError(f"Login failed: {str(e)}")

class FaceLoginSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
    face_image = serializers.ImageField(required=True)

    def validate(self, data):
        email = data.get('email')
        face_image = data.get('face_image')
        try:
            user = CustomUser.objects.get(email=email)
            if not user.face_encoding:
                logger.warning(f"No face encoding for user {email}")
                raise serializers.ValidationError({"face_image": "No face encoding stored for this user."})
            image = face_recognition.load_image_file(face_image)
            login_encoding = face_recognition.face_encodings(image)
            if not login_encoding:
                logger.warning(f"No face detected in login image for {email}")
                raise serializers.ValidationError({"face_image": "No face detected in the provided image."})
            stored_encoding = np.array(json.loads(user.face_encoding))
            match = face_recognition.compare_faces([stored_encoding], login_encoding[0], tolerance=0.6)
            if not match[0]:
                logger.warning(f"Face mismatch for user {email}")
                raise serializers.ValidationError({"face_image": "Face does not match stored encoding."})
            data['user'] = user
            return data
        except CustomUser.DoesNotExist:
            logger.error(f"User with email {email} not found")
            raise serializers.ValidationError({"email": "User with this email does not exist."})
        except Exception as e:
            logger.error(f"Face recognition failed for {email}: {str(e)}")
            raise serializers.ValidationError({"face_image": f"Face recognition failed: {str(e)}"})

class ParentStudentLinkSerializer(serializers.ModelSerializer):
    parent_username = serializers.CharField(source='parent.username', read_only=True)
    student_username = serializers.CharField(source='student.username', read_only=True)
    student_details = StudentProfileSerializer(source='student.student_profile', read_only=True)

    class Meta:
        model = ParentStudentLink
        fields = ['id', 'parent', 'student', 'parent_username', 'student_username', 'student_details']
        extra_kwargs = {
            'parent': {'queryset': CustomUser.objects.filter(role='Parent')},
            'student': {'queryset': CustomUser.objects.filter(role='Student')},
        }

    def validate(self, data):
        parent = data.get('parent')
        student = data.get('student')
        if parent and parent.role != 'Parent':
            raise serializers.ValidationError({"parent": "Selected user is not a Parent."})
        if student and student.role != 'Student':
            raise serializers.ValidationError({"student": "Selected user is not a Student."})
        return data

class StudentProfileCompletionSerializer(serializers.ModelSerializer):
    school_id = serializers.PrimaryKeyRelatedField(queryset=School.objects.all(), source='school', write_only=True, allow_null=True, required=False)
    enrolled_class_id = serializers.PrimaryKeyRelatedField(queryset=ContentClass.objects.all(), source='enrolled_class', write_only=True, allow_null=True, required=False)
    profile_picture = serializers.ImageField(required=False, allow_null=True)

    class Meta:
        model = StudentProfile
        fields = [
            'full_name', 'school', 'school_id', 'enrolled_class', 'enrolled_class_id',
            'preferred_language', 'father_name', 'mother_name', 'place_of_birth',
            'date_of_birth', 'blood_group', 'needs_assistant_teacher', 'admission_number',
            'parent_email_for_linking', 'parent_mobile_for_linking', 'parent_occupation',
            'hobbies', 'favorite_sports', 'interested_in_gardening_farming', 'nickname',
            'profile_picture', 'profile_completed'
        ]
        read_only_fields = ['user', 'school', 'enrolled_class']

class TeacherProfileCompletionSerializer(serializers.ModelSerializer):
    school_id = serializers.PrimaryKeyRelatedField(queryset=School.objects.all(), source='school', write_only=True, allow_null=True, required=False)
    assigned_classes_ids = serializers.PrimaryKeyRelatedField(
        queryset=ContentClass.objects.all(), source='assigned_classes', many=True, required=False, write_only=True
    )
    subject_expertise_ids = serializers.PrimaryKeyRelatedField(
        queryset=ContentSubject.objects.all(), source='subject_expertise', many=True, required=False, write_only=True
    )
    profile_picture = serializers.ImageField(required=False, allow_null=True)

    class Meta:
        model = TeacherProfile
        fields = [
            'full_name', 'school', 'school_id', 'assigned_classes', 'assigned_classes_ids',
            'subject_expertise', 'subject_expertise_ids', 'interested_in_tuition',
            'mobile_number', 'address', 'profile_picture', 'profile_completed'
        ]
        read_only_fields = ['user', 'school', 'assigned_classes', 'subject_expertise']

class ParentProfileCompletionSerializer(serializers.ModelSerializer):
    profile_picture = serializers.ImageField(required=False, allow_null=True)

    class Meta:
        model = ParentProfile
        fields = ['full_name', 'mobile_number', 'address', 'profile_picture', 'profile_completed']
        read_only_fields = ['user']